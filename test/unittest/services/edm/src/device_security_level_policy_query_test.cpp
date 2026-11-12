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

#include "device_security_level_policy_query.h"
#include "managed_policy.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "iplugin.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class DeviceSecurityLevelPolicyQueryTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void DeviceSecurityLevelPolicyQueryTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DeviceSecurityLevelPolicyQueryTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
}

/**
 * @tc.name: GetPolicyName_Success
 * @tc.desc: Test DeviceSecurityLevelPolicyQuery::GetPolicyName.
 * @tc.type: FUNC
 */
HWTEST_F(DeviceSecurityLevelPolicyQueryTest, GetPolicyName_Success, TestSize.Level1)
{
    DeviceSecurityLevelPolicyQuery query;
    EXPECT_EQ(query.GetPolicyName(), PolicyName::POLICY_DEVICE_SECURITY_LEVEL_POLICY);
}

/**
 * @tc.name: GetPermission_Success
 * @tc.desc: Test DeviceSecurityLevelPolicyQuery::GetPermission ignores the permission tag.
 * @tc.type: FUNC
 */
HWTEST_F(DeviceSecurityLevelPolicyQueryTest, GetPermission_Success, TestSize.Level1)
{
    DeviceSecurityLevelPolicyQuery query;
    EXPECT_EQ(query.GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, ""),
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY);
    EXPECT_EQ(query.GetPermission(IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, "version_23"),
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY);
}

/**
 * @tc.name: QueryPolicy_ReadParameter
 * @tc.desc: Test DeviceSecurityLevelPolicyQuery::QueryPolicy replies with the current level.
 * @tc.type: FUNC
 */
HWTEST_F(DeviceSecurityLevelPolicyQueryTest, QueryPolicy_ReadParameter, TestSize.Level1)
{
    DeviceSecurityLevelPolicyQuery query;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = query.QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    reply.RewindRead(0);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    int32_t policy = reply.ReadInt32();
    EXPECT_GE(policy, static_cast<int32_t>(DeviceSecurityLevelPolicy::DEFAULT_ENFORCED));
    EXPECT_LE(policy, static_cast<int32_t>(DeviceSecurityLevelPolicy::ALLOW_FLEXIBLE));
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
