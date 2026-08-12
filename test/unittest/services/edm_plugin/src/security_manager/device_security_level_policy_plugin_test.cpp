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
#include "device_security_level_policy_plugin.h"
#include "edm_ipc_interface_code.h"
#include "func_code.h"
#include "handle_policy_data.h"
#include "iplugin_manager.h"
#include "utils.h"
#include "managed_policy.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class DeviceSecurityLevelPolicyPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void DeviceSecurityLevelPolicyPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DeviceSecurityLevelPolicyPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnHandlePolicyDefaultEnforced
 * @tc.desc: Test OnHandlePolicy with DEFAULT_ENFORCED value.
 * @tc.type: FUNC
 */
HWTEST_F(DeviceSecurityLevelPolicyPluginTest, TestOnHandlePolicyDefaultEnforced, TestSize.Level1)
{
    DeviceSecurityLevelPolicyPlugin plugin;
    std::uint32_t funcCode = POLICY_FUNC_CODE(
        (std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DEVICE_SECURITY_LEVEL_POLICY);
    MessageParcel data;
    data.WriteInt32(static_cast<int32_t>(DeviceSecurityLevelPolicy::DEFAULT_ENFORCED));
    MessageParcel reply;
    HandlePolicyData handlePolicyData;
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestOnHandlePolicyAllowBalanced
 * @tc.desc: Test OnHandlePolicy with ALLOW_BALANCED value.
 * @tc.type: FUNC
 */
HWTEST_F(DeviceSecurityLevelPolicyPluginTest, TestOnHandlePolicyAllowBalanced, TestSize.Level1)
{
    DeviceSecurityLevelPolicyPlugin plugin;
    std::uint32_t funcCode = POLICY_FUNC_CODE(
        (std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DEVICE_SECURITY_LEVEL_POLICY);
    MessageParcel data;
    data.WriteInt32(static_cast<int32_t>(DeviceSecurityLevelPolicy::ALLOW_BALANCED));
    MessageParcel reply;
    HandlePolicyData handlePolicyData;
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestOnHandlePolicyAllowFlexible
 * @tc.desc: Test OnHandlePolicy with ALLOW_FLEXIBLE value.
 * @tc.type: FUNC
 */
HWTEST_F(DeviceSecurityLevelPolicyPluginTest, TestOnHandlePolicyAllowFlexible, TestSize.Level1)
{
    DeviceSecurityLevelPolicyPlugin plugin;
    std::uint32_t funcCode = POLICY_FUNC_CODE(
        (std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DEVICE_SECURITY_LEVEL_POLICY);
    MessageParcel data;
    data.WriteInt32(static_cast<int32_t>(DeviceSecurityLevelPolicy::ALLOW_FLEXIBLE));
    MessageParcel reply;
    HandlePolicyData handlePolicyData;
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestOnHandlePolicyIllegalValue
 * @tc.desc: Test OnHandlePolicy with value exceeding valid range.
 * @tc.type: FUNC
 */
HWTEST_F(DeviceSecurityLevelPolicyPluginTest, TestOnHandlePolicyIllegalValue, TestSize.Level1)
{
    DeviceSecurityLevelPolicyPlugin plugin;
    std::uint32_t funcCode = POLICY_FUNC_CODE(
        (std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DEVICE_SECURITY_LEVEL_POLICY);
    MessageParcel data;
    data.WriteInt32(100);
    MessageParcel reply;
    HandlePolicyData handlePolicyData;
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnHandlePolicyNegativeValue
 * @tc.desc: Test OnHandlePolicy with negative value.
 * @tc.type: FUNC
 */
HWTEST_F(DeviceSecurityLevelPolicyPluginTest, TestOnHandlePolicyNegativeValue, TestSize.Level1)
{
    DeviceSecurityLevelPolicyPlugin plugin;
    std::uint32_t funcCode = POLICY_FUNC_CODE(
        (std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DEVICE_SECURITY_LEVEL_POLICY);
    MessageParcel data;
    data.WriteInt32(-1);
    MessageParcel reply;
    HandlePolicyData handlePolicyData;
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnHandlePolicyBoundaryValue
 * @tc.desc: Test OnHandlePolicy with boundary value just above valid range.
 * @tc.type: FUNC
 */
HWTEST_F(DeviceSecurityLevelPolicyPluginTest, TestOnHandlePolicyBoundaryValue, TestSize.Level1)
{
    DeviceSecurityLevelPolicyPlugin plugin;
    std::uint32_t funcCode = POLICY_FUNC_CODE(
        (std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DEVICE_SECURITY_LEVEL_POLICY);
    MessageParcel data;
    data.WriteInt32(static_cast<int32_t>(DeviceSecurityLevelPolicy::ALLOW_FLEXIBLE) + 1);
    MessageParcel reply;
    HandlePolicyData handlePolicyData;
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
