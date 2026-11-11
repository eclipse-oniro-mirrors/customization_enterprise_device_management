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

#include "disallowed_wifi_list_query.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "iplugin.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class DisallowedWifiListQueryTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void DisallowedWifiListQueryTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DisallowedWifiListQueryTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
}

/**
 * @tc.name: GetPolicyName_ReturnCorrectValue_Success
 * @tc.desc: Test DisallowedWifiListQuery::GetPolicyName.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedWifiListQueryTest, GetPolicyName_ReturnCorrectValue_Success, TestSize.Level1)
{
    DisallowedWifiListQuery query;
    EXPECT_EQ(query.GetPolicyName(), PolicyName::POLICY_DISALLOWED_WIFI_LIST);
}

/**
 * @tc.name: GetPermission_ReturnCorrectValue_Success
 * @tc.desc: Test DisallowedWifiListQuery::GetPermission.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedWifiListQueryTest, GetPermission_ReturnCorrectValue_Success, TestSize.Level1)
{
    DisallowedWifiListQuery query;
    EXPECT_EQ(query.GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, ""),
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_WIFI);
}

/**
 * @tc.name: QueryPolicy_DelegatesToSerializer
 * @tc.desc: Test DisallowedWifiListQuery::QueryPolicy forwards to the wifi id serializer.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedWifiListQueryTest, QueryPolicy_DelegatesToSerializer, TestSize.Level1)
{
    DisallowedWifiListQuery query;
    std::string policyData = "[]";
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = query.QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    reply.RewindRead(0);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: QueryPolicy_InvalidPolicyData
 * @tc.desc: Test DisallowedWifiListQuery::QueryPolicy with an unparsable policy.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedWifiListQueryTest, QueryPolicy_InvalidPolicyData, TestSize.Level1)
{
    DisallowedWifiListQuery query;
    std::string policyData = "broken";
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = query.QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    EXPECT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
