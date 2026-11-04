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

#include "edm_constants.h"
#include "edm_errors.h"
#include "enterprise_reset_policy_query.h"
#include "managed_policy.h"
#include "parameters.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
namespace {
std::string g_originalPolicyValue;
} // namespace

class EnterpriseResetPolicyQueryTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void EnterpriseResetPolicyQueryTest::SetUpTestSuite(void)
{
    g_originalPolicyValue = system::GetParameter(
        EdmConstants::SecurityManager::PARAM_EDM_ENTERPRISE_RESET_POLICY, "0");
}

void EnterpriseResetPolicyQueryTest::TearDownTestSuite(void)
{
    system::SetParameter(
        EdmConstants::SecurityManager::PARAM_EDM_ENTERPRISE_RESET_POLICY, g_originalPolicyValue);
}

/**
 * @tc.name: TestGetPolicyName_SUC
 * @tc.desc: Test GetPolicyName function returns correct policy name.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseResetPolicyQueryTest, TestGetPolicyName_SUC, TestSize.Level1)
{
    EnterpriseResetPolicyQuery query;
    std::string policyName = query.GetPolicyName();
    EXPECT_EQ(policyName, PolicyName::POLICY_ENTERPRISE_RESET_POLICY);
}

/**
 * @tc.name: TestGetPermission_SUC
 * @tc.desc: Test GetPermission function returns correct permission.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseResetPolicyQueryTest, TestGetPermission_SUC, TestSize.Level1)
{
    EnterpriseResetPolicyQuery query;
    std::string permission = query.GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "");
    EXPECT_EQ(permission, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY);
}

/**
 * @tc.name: TestQueryPolicyDefault_SUC
 * @tc.desc: Test QueryPolicy returns DEFAULT when policy is unset.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseResetPolicyQueryTest, TestQueryPolicyDefault_SUC, TestSize.Level1)
{
    system::SetParameter(EdmConstants::SecurityManager::PARAM_EDM_ENTERPRISE_RESET_POLICY, "0");
    EnterpriseResetPolicyQuery query;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = query.QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), static_cast<int32_t>(EnterpriseResetPolicy::DEFAULT));
}

/**
 * @tc.name: TestQueryPolicyAuthOn_SUC
 * @tc.desc: Test QueryPolicy returns ENTERPRISE_ACCOUNT_AUTH_ON.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseResetPolicyQueryTest, TestQueryPolicyAuthOn_SUC, TestSize.Level1)
{
    system::SetParameter(EdmConstants::SecurityManager::PARAM_EDM_ENTERPRISE_RESET_POLICY, "1");
    EnterpriseResetPolicyQuery query;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = query.QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), static_cast<int32_t>(EnterpriseResetPolicy::ENTERPRISE_ACCOUNT_AUTH_ON));
}

/**
 * @tc.name: TestQueryPolicyAuthOff_SUC
 * @tc.desc: Test QueryPolicy returns ENTERPRISE_ACCOUNT_AUTH_OFF.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseResetPolicyQueryTest, TestQueryPolicyAuthOff_SUC, TestSize.Level1)
{
    system::SetParameter(EdmConstants::SecurityManager::PARAM_EDM_ENTERPRISE_RESET_POLICY, "2");
    EnterpriseResetPolicyQuery query;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = query.QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), static_cast<int32_t>(EnterpriseResetPolicy::ENTERPRISE_ACCOUNT_AUTH_OFF));
}

/**
 * @tc.name: TestQueryPolicyInvalidValue_SUC
 * @tc.desc: Test QueryPolicy clamps out-of-range policy value to DEFAULT.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseResetPolicyQueryTest, TestQueryPolicyInvalidValue_SUC, TestSize.Level1)
{
    system::SetParameter(EdmConstants::SecurityManager::PARAM_EDM_ENTERPRISE_RESET_POLICY, "100");
    EnterpriseResetPolicyQuery query;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = query.QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), static_cast<int32_t>(EnterpriseResetPolicy::DEFAULT));
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
