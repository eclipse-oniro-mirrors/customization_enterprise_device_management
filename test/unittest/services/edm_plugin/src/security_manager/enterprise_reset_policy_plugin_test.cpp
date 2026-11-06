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
#include "edm_ipc_interface_code.h"
#include "enterprise_reset_policy_plugin.h"
#include "func_code.h"
#include "handle_policy_data.h"
#include "iplugin_manager.h"
#include "managed_policy.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {

class EnterpriseResetPolicyPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void EnterpriseResetPolicyPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void EnterpriseResetPolicyPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnHandlePolicyDefault
 * @tc.desc: Test OnHandlePolicy with DEFAULT value.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseResetPolicyPluginTest, TestOnHandlePolicyDefault, TestSize.Level1)
{
    EnterpriseResetPolicyPlugin plugin;
    std::uint32_t funcCode = POLICY_FUNC_CODE(
        (std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::ENTERPRISE_RESET_POLICY);
    MessageParcel data;
    data.WriteInt32(static_cast<int32_t>(EnterpriseResetPolicy::DEFAULT));
    MessageParcel reply;
    HandlePolicyData handlePolicyData;
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestOnHandlePolicyEnterpriseAccountAuthOn
 * @tc.desc: Test OnHandlePolicy with ENTERPRISE_ACCOUNT_AUTH_ON value.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseResetPolicyPluginTest, TestOnHandlePolicyEnterpriseAccountAuthOn, TestSize.Level1)
{
    EnterpriseResetPolicyPlugin plugin;
    std::uint32_t funcCode = POLICY_FUNC_CODE(
        (std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::ENTERPRISE_RESET_POLICY);
    MessageParcel data;
    data.WriteInt32(static_cast<int32_t>(EnterpriseResetPolicy::ENTERPRISE_ACCOUNT_AUTH_ON));
    MessageParcel reply;
    HandlePolicyData handlePolicyData;
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestOnHandlePolicyEnterpriseAccountAuthOff
 * @tc.desc: Test OnHandlePolicy with ENTERPRISE_ACCOUNT_AUTH_OFF value.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseResetPolicyPluginTest, TestOnHandlePolicyEnterpriseAccountAuthOff, TestSize.Level1)
{
    EnterpriseResetPolicyPlugin plugin;
    std::uint32_t funcCode = POLICY_FUNC_CODE(
        (std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::ENTERPRISE_RESET_POLICY);
    MessageParcel data;
    data.WriteInt32(static_cast<int32_t>(EnterpriseResetPolicy::ENTERPRISE_ACCOUNT_AUTH_OFF));
    MessageParcel reply;
    HandlePolicyData handlePolicyData;
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestOnHandlePolicyGetOperateType
 * @tc.desc: Test OnHandlePolicy with GET operate type.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseResetPolicyPluginTest, TestOnHandlePolicyGetOperateType, TestSize.Level1)
{
    EnterpriseResetPolicyPlugin plugin;
    std::uint32_t funcCode = POLICY_FUNC_CODE(
        (std::uint32_t)FuncOperateType::GET, EdmInterfaceCode::ENTERPRISE_RESET_POLICY);
    MessageParcel data;
    data.WriteInt32(static_cast<int32_t>(EnterpriseResetPolicy::DEFAULT));
    MessageParcel reply;
    HandlePolicyData handlePolicyData;
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnHandlePolicyReadDataFailed
 * @tc.desc: Test OnHandlePolicy when reading policy data from parcel fails.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseResetPolicyPluginTest, TestOnHandlePolicyReadDataFailed, TestSize.Level1)
{
    EnterpriseResetPolicyPlugin plugin;
    std::uint32_t funcCode = POLICY_FUNC_CODE(
        (std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::ENTERPRISE_RESET_POLICY);
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData handlePolicyData;
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnHandlePolicyIllegalValue
 * @tc.desc: Test OnHandlePolicy with value exceeding valid range.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseResetPolicyPluginTest, TestOnHandlePolicyIllegalValue, TestSize.Level1)
{
    EnterpriseResetPolicyPlugin plugin;
    std::uint32_t funcCode = POLICY_FUNC_CODE(
        (std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::ENTERPRISE_RESET_POLICY);
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
HWTEST_F(EnterpriseResetPolicyPluginTest, TestOnHandlePolicyNegativeValue, TestSize.Level1)
{
    EnterpriseResetPolicyPlugin plugin;
    std::uint32_t funcCode = POLICY_FUNC_CODE(
        (std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::ENTERPRISE_RESET_POLICY);
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
HWTEST_F(EnterpriseResetPolicyPluginTest, TestOnHandlePolicyBoundaryValue, TestSize.Level1)
{
    EnterpriseResetPolicyPlugin plugin;
    std::uint32_t funcCode = POLICY_FUNC_CODE(
        (std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::ENTERPRISE_RESET_POLICY);
    MessageParcel data;
    data.WriteInt32(static_cast<int32_t>(EnterpriseResetPolicy::ENTERPRISE_ACCOUNT_AUTH_OFF) + 1);
    MessageParcel reply;
    HandlePolicyData handlePolicyData;
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS