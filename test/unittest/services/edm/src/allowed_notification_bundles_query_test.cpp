/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <message_parcel.h>

#include "allowed_notification_bundles_query.h"
#include "allowed_notification_bundles_serializer.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "iplugin.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
namespace {
const std::string BROKEN_POLICY_DATA = "not-a-json-array";

std::string BuildPolicyData(int32_t userId, const std::string &bundleName)
{
    AllowedNotificationBundlesType item;
    item.userId = userId;
    item.trustList.insert(bundleName);
    std::vector<AllowedNotificationBundlesType> data = { item };
    std::string policyData;
    AllowedNotificationBundlesSerializer::GetInstance()->Serialize(data, policyData);
    return policyData;
}
}

class AllowedNotificationBundlesQueryTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void AllowedNotificationBundlesQueryTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void AllowedNotificationBundlesQueryTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
}

/**
 * @tc.name: GetPolicyName_Success
 * @tc.desc: Test AllowedNotificationBundlesQuery::GetPolicyName.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedNotificationBundlesQueryTest, GetPolicyName_Success, TestSize.Level1)
{
    AllowedNotificationBundlesQuery query;
    EXPECT_EQ(query.GetPolicyName(), PolicyName::POLICY_ALLOWED_NOTIFICATION_BUNDLES);
}

/**
 * @tc.name: GetPermission_Success
 * @tc.desc: Test AllowedNotificationBundlesQuery::GetPermission.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedNotificationBundlesQueryTest, GetPermission_Success, TestSize.Level1)
{
    AllowedNotificationBundlesQuery query;
    EXPECT_EQ(query.GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, ""),
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION);
}

/**
 * @tc.name: QueryPolicy_InvalidPolicyData_Failed
 * @tc.desc: Test AllowedNotificationBundlesQuery::QueryPolicy rejects an unparsable policy.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedNotificationBundlesQueryTest, QueryPolicy_InvalidPolicyData_Failed, TestSize.Level1)
{
    AllowedNotificationBundlesQuery query;
    std::string policyData = BROKEN_POLICY_DATA;
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(DEFAULT_USER_ID);
    ErrCode ret = query.QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: QueryPolicy_IllegalAccountId_Failed
 * @tc.desc: Test AllowedNotificationBundlesQuery::QueryPolicy rejects a negative accountId.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedNotificationBundlesQueryTest, QueryPolicy_IllegalAccountId_Failed, TestSize.Level1)
{
    AllowedNotificationBundlesQuery query;
    std::string policyData = BuildPolicyData(DEFAULT_USER_ID, "com.test.a");
    ASSERT_FALSE(policyData.empty());
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(-1);
    ErrCode ret = query.QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: QueryPolicy_MatchedAccount
 * @tc.desc: Test AllowedNotificationBundlesQuery::QueryPolicy writes the trust list of the account.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedNotificationBundlesQueryTest, QueryPolicy_MatchedAccount, TestSize.Level1)
{
    AllowedNotificationBundlesQuery query;
    std::string policyData = BuildPolicyData(DEFAULT_USER_ID, "com.test.a");
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(DEFAULT_USER_ID);
    ErrCode ret = query.QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    reply.RewindRead(0);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    std::vector<std::string> bundleNames;
    reply.ReadStringVector(&bundleNames);
    ASSERT_EQ(bundleNames.size(), 1u);
    EXPECT_EQ(bundleNames[0], "com.test.a");
}

/**
 * @tc.name: QueryPolicy_OtherAccount
 * @tc.desc: Test AllowedNotificationBundlesQuery::QueryPolicy writes an empty list for others.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedNotificationBundlesQueryTest, QueryPolicy_OtherAccount, TestSize.Level1)
{
    AllowedNotificationBundlesQuery query;
    std::string policyData = BuildPolicyData(DEFAULT_USER_ID, "com.test.a");
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(DEFAULT_USER_ID + 1);
    ErrCode ret = query.QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    reply.RewindRead(0);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    std::vector<std::string> bundleNames;
    reply.ReadStringVector(&bundleNames);
    EXPECT_TRUE(bundleNames.empty());
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
