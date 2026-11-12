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

#include "allowed_app_distribution_types_query.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "iplugin.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class AllowedAppDistributionTypesQueryTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void AllowedAppDistributionTypesQueryTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void AllowedAppDistributionTypesQueryTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
}

/**
 * @tc.name: GetPolicyName_Success
 * @tc.desc: Test AllowedAppDistributionTypesQuery::GetPolicyName.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedAppDistributionTypesQueryTest, GetPolicyName_Success, TestSize.Level1)
{
    AllowedAppDistributionTypesQuery query;
    EXPECT_EQ(query.GetPolicyName(), PolicyName::POLICY_ALLOWED_INSTALL_APP_TYPE);
}

/**
 * @tc.name: GetPermission_Success
 * @tc.desc: Test AllowedAppDistributionTypesQuery::GetPermission.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedAppDistributionTypesQueryTest, GetPermission_Success, TestSize.Level1)
{
    AllowedAppDistributionTypesQuery query;
    EXPECT_EQ(query.GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, ""),
        EdmPermission::PERMISSION_ENTERPRISE_SET_BUNDLE_INSTALL_POLICY);
}

/**
 * @tc.name: QueryPolicy_EmptyList_Success
 * @tc.desc: Test AllowedAppDistributionTypesQuery::QueryPolicy writes an empty type list.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedAppDistributionTypesQueryTest, QueryPolicy_EmptyList_Success, TestSize.Level1)
{
    AllowedAppDistributionTypesQuery query;
    std::string policyData = "[]";
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = query.QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    reply.RewindRead(0);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    std::vector<int32_t> policy;
    EXPECT_TRUE(reply.ReadInt32Vector(&policy));
    EXPECT_TRUE(policy.empty());
}

/**
 * @tc.name: QueryPolicy_TwoTypes_Success
 * @tc.desc: Test AllowedAppDistributionTypesQuery::QueryPolicy writes every configured type.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedAppDistributionTypesQueryTest, QueryPolicy_TwoTypes_Success, TestSize.Level1)
{
    AllowedAppDistributionTypesQuery query;
    std::string policyData = "[1,2]";
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = query.QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    reply.RewindRead(0);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    std::vector<int32_t> policy;
    EXPECT_TRUE(reply.ReadInt32Vector(&policy));
    EXPECT_EQ(policy.size(), 2u);
}

/**
 * @tc.name: QueryPolicy_InvalidPolicyData
 * @tc.desc: Test AllowedAppDistributionTypesQuery::QueryPolicy ignores an unparsable policy.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedAppDistributionTypesQueryTest, QueryPolicy_InvalidPolicyData, TestSize.Level1)
{
    AllowedAppDistributionTypesQuery query;
    std::string policyData = "broken";
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = query.QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    reply.RewindRead(0);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
