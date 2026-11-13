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

#define private public
#include "power_mode_settings_plugin.h"
#undef private

#include <gtest/gtest.h>

#include "edm_constants.h"
#include "edm_data_ability_utils_mock.h"
#include "edm_ipc_interface_code.h"
#include "edm_os_account_manager_impl_mock.h"
#include "external_manager_factory_mock.h"
#include "iplugin_manager.h"
#include "setting_item_policy.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class PowerModeSettingsPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void PowerModeSettingsPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmServiceEnable();
    Utils::SetEdmInitialEnv();
}

void PowerModeSettingsPluginTest::TearDownTestSuite(void)
{
    Utils::SetEdmServiceDisable();
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
}

static std::shared_ptr<PowerModeSettingsPlugin> CreatePlugin()
{
    return std::make_shared<PowerModeSettingsPlugin>(EdmInterfaceCode::POWER_MODE_SETTINGS,
        PolicyName::POLICY_POWER_MODE_SETTINGS);
}

static std::uint32_t GetFuncCode(FuncOperateType operateType)
{
    return POLICY_FUNC_CODE(static_cast<std::uint32_t>(operateType),
        static_cast<std::uint32_t>(EdmInterfaceCode::POWER_MODE_SETTINGS));
}

static std::uint32_t GetFuncCodeNew(FuncOperateType operateType)
{
    return POLICY_FUNC_CODE_NEW(static_cast<std::uint32_t>(operateType),
        static_cast<std::uint32_t>(EdmInterfaceCode::POWER_MODE_SETTINGS));
}

static ErrCode HandlePolicy(std::shared_ptr<PowerModeSettingsPlugin> plugin, SettingsItem item,
    const std::string &valueStr, FuncOperateType operateType = FuncOperateType::SET)
{
    MessageParcel data;
    data.WriteInt32(static_cast<int32_t>(item));
    data.WriteString(valueStr);
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"TestString", "", false};
    return plugin->OnHandlePolicy(GetFuncCode(operateType), data, reply, handlePolicyData, DEFAULT_USER_ID);
}

static ErrCode GetPolicy(std::shared_ptr<PowerModeSettingsPlugin> plugin, SettingsItem item,
    MessageParcel &reply)
{
    MessageParcel data;
    data.WriteInt32(static_cast<int32_t>(item));
    std::string policyData{"TestString"};
    return plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
}

static const std::string VALID_POWER_POLICY =
    "{\"powerScene\":0,\"powerPolicy\":{\"powerPolicyAction\":1,\"delayTime\":1000}}";

/**
 * @tc.name: OnHandlePolicy_RemoveOperate_SysAbnormally
 * @tc.desc: Test OnHandlePolicy function when operate type is REMOVE.
 * @tc.type: FUNC
 */
HWTEST_F(PowerModeSettingsPluginTest, OnHandlePolicy_RemoveOperate_ExecuteTimeOut, TestSize.Level1)
{
    std::shared_ptr<PowerModeSettingsPlugin> plugin = CreatePlugin();
    ErrCode ret = HandlePolicy(plugin, SettingsItem::SCREEN_OFF_DC, "30000", FuncOperateType::REMOVE);
    EXPECT_EQ(ret, static_cast<int32_t>(EdmReturnErrCode::EXECUTE_TIME_OUT));
}

/**
 * @tc.name: OnHandlePolicy_UnsupportedItem_ExecuteTimeOut
 * @tc.desc: Test OnHandlePolicy function when item is not a power mode item.
 * @tc.type: FUNC
 */
HWTEST_F(PowerModeSettingsPluginTest, OnHandlePolicy_UnsupportedItem_ExecuteTimeOut, TestSize.Level1)
{
    std::shared_ptr<PowerModeSettingsPlugin> plugin = CreatePlugin();
    ErrCode ret = HandlePolicy(plugin, SettingsItem::DEVICE_NAME, "30000");
    EXPECT_EQ(ret, static_cast<int32_t>(EdmReturnErrCode::EXECUTE_TIME_OUT));
}

/**
 * @tc.name: OnHandlePolicy_EmptyValue_ParamError
 * @tc.desc: Test OnHandlePolicy function when screen off time is empty string.
 * @tc.type: FUNC
 */
HWTEST_F(PowerModeSettingsPluginTest, OnHandlePolicy_EmptyValue_ParameterVerificationFailed, TestSize.Level1)
{
    std::shared_ptr<PowerModeSettingsPlugin> plugin = CreatePlugin();
    ErrCode ret = HandlePolicy(plugin, SettingsItem::SCREEN_OFF_AC, "");
    EXPECT_EQ(ret, static_cast<int32_t>(EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED));
}

/**
 * @tc.name: OnHandlePolicy_ValueNotNumber_ParameterVerificationFailed
 * @tc.desc: Test OnHandlePolicy function when screen off time contains non-numeric characters.
 * @tc.type: FUNC
 */
HWTEST_F(PowerModeSettingsPluginTest, OnHandlePolicy_ValueNotNumber_ParameterVerificationFailed, TestSize.Level1)
{
    std::shared_ptr<PowerModeSettingsPlugin> plugin = CreatePlugin();
    ErrCode ret = HandlePolicy(plugin, SettingsItem::SCREEN_OFF_DC, "abc");
    EXPECT_EQ(ret, static_cast<int32_t>(EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED));
}

/**
 * @tc.name: OnHandlePolicy_ValueOverflow_ParameterVerificationFailed
 * @tc.desc: Test OnHandlePolicy function when screen off time exceeds int32 range.
 * @tc.type: FUNC
 */
HWTEST_F(PowerModeSettingsPluginTest, OnHandlePolicy_ValueOverflow_ParameterVerificationFailed, TestSize.Level1)
{
    std::shared_ptr<PowerModeSettingsPlugin> plugin = CreatePlugin();
    ErrCode ret = HandlePolicy(plugin, SettingsItem::SCREEN_OFF_AC, "2147483648");
    EXPECT_EQ(ret, static_cast<int32_t>(EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED));
}

/**
 * @tc.name: OnHandlePolicy_ValueBelowMin_ParamError
 * @tc.desc: Test OnHandlePolicy function when screen off time is 14999.
 * @tc.type: FUNC
 */
HWTEST_F(PowerModeSettingsPluginTest, OnHandlePolicy_ValueBelowMin_ParameterVerificationFailed, TestSize.Level1)
{
    std::shared_ptr<PowerModeSettingsPlugin> plugin = CreatePlugin();
    ErrCode ret = HandlePolicy(plugin, SettingsItem::SCREEN_OFF_AC, "14999");
    EXPECT_EQ(ret, static_cast<int32_t>(EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED));
}

/**
 * @tc.name: OnHandlePolicy_MinBoundaryValue_Success
 * @tc.desc: Test OnHandlePolicy function when screen off time is exactly 15000.
 * @tc.type: FUNC
 */
HWTEST_F(PowerModeSettingsPluginTest, OnHandlePolicy_MinBoundaryValue_Success, TestSize.Level1)
{
    std::shared_ptr<PowerModeSettingsPlugin> plugin = CreatePlugin();
    EdmDataAbilityUtils::SetResult("test success");
    ErrCode ret = HandlePolicy(plugin, SettingsItem::SCREEN_OFF_DC, "15000");
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: OnHandlePolicy_NeverTimeOutValue_ParameterVerificationFailed
 * @tc.desc: Test OnHandlePolicy function when screen off time is -1 (never timeout).
 * @tc.type: FUNC
 */
HWTEST_F(PowerModeSettingsPluginTest, OnHandlePolicy_NeverTimeOutValue_ParameterVerificationFailed, TestSize.Level1)
{
    std::shared_ptr<PowerModeSettingsPlugin> plugin = CreatePlugin();
    EdmDataAbilityUtils::SetResult("test success");
    ErrCode ret = HandlePolicy(plugin, SettingsItem::SCREEN_OFF_AC, "-1");
    EXPECT_EQ(ret, static_cast<int32_t>(EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED));
}

/**
 * @tc.name: OnHandlePolicy_UpdateSettingsDataFailed_SysAbnormally
 * @tc.desc: Test OnHandlePolicy function when writing settings data failed.
 * @tc.type: FUNC
 */
HWTEST_F(PowerModeSettingsPluginTest, OnHandlePolicy_UpdateSettingsDataFailed_ExecuteTimeOut, TestSize.Level1)
{
    std::shared_ptr<PowerModeSettingsPlugin> plugin = CreatePlugin();
    EdmDataAbilityUtils::SetResult("SYSTEM_ABNORMALLY");
    ErrCode ret = HandlePolicy(plugin, SettingsItem::SCREEN_OFF_DC, "30000");
    EXPECT_EQ(ret, static_cast<int32_t>(EdmReturnErrCode::EXECUTE_TIME_OUT));
}

/**
 * @tc.name: OnGetPolicy_ReadSettingsDataFailed_ExecuteTimeOut
 * @tc.desc: Test OnGetPolicy function when reading screen off time failed.
 * @tc.type: FUNC
 */
HWTEST_F(PowerModeSettingsPluginTest, OnGetPolicy_ReadSettingsDataFailed_ExecuteTimeOut, TestSize.Level1)
{
    std::shared_ptr<PowerModeSettingsPlugin> plugin = CreatePlugin();
    MessageParcel reply;
    EdmDataAbilityUtils::SetResult("SYSTEM_ABNORMALLY");
    ErrCode ret = GetPolicy(plugin, SettingsItem::SCREEN_OFF_AC, reply);
    EXPECT_EQ(ret, static_cast<int32_t>(EdmReturnErrCode::EXECUTE_TIME_OUT));
    EXPECT_EQ(reply.ReadInt32(), static_cast<int32_t>(EdmReturnErrCode::EXECUTE_TIME_OUT));
}

/**
 * @tc.name: OnGetPolicy_DcMode_Success
 * @tc.desc: Test OnGetPolicy function in DC mode and reply contains string value.
 * @tc.type: FUNC
 */
HWTEST_F(PowerModeSettingsPluginTest, OnGetPolicy_DcMode_Success, TestSize.Level1)
{
    std::shared_ptr<PowerModeSettingsPlugin> plugin = CreatePlugin();
    MessageParcel reply;
    EdmDataAbilityUtils::SetResult("test success");
    ErrCode ret = GetPolicy(plugin, SettingsItem::SCREEN_OFF_DC, reply);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), static_cast<int32_t>(ERR_OK));
    EXPECT_EQ(reply.ReadString(), "0");
}

/**
 * @tc.name: OnGetPolicy_AcMode_Success
 * @tc.desc: Test OnGetPolicy function in AC mode and reply contains string value.
 * @tc.type: FUNC
 */
HWTEST_F(PowerModeSettingsPluginTest, OnGetPolicy_AcMode_Success, TestSize.Level1)
{
    std::shared_ptr<PowerModeSettingsPlugin> plugin = CreatePlugin();
    MessageParcel reply;
    EdmDataAbilityUtils::SetResult("test success");
    ErrCode ret = GetPolicy(plugin, SettingsItem::SCREEN_OFF_AC, reply);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), static_cast<int32_t>(ERR_OK));
    EXPECT_EQ(reply.ReadString(), "0");
}

/**
 * @tc.name: OnGetPolicy_UnsupportedItem_ExecuteTimeOut
 * @tc.desc: Test OnGetPolicy function when item is not a power mode item.
 * @tc.type: FUNC
 */
HWTEST_F(PowerModeSettingsPluginTest, OnGetPolicy_UnsupportedItem_ExecuteTimeOut, TestSize.Level1)
{
    std::shared_ptr<PowerModeSettingsPlugin> plugin = CreatePlugin();
    MessageParcel reply;
    ErrCode ret = GetPolicy(plugin, SettingsItem::DEVICE_NAME, reply);
    EXPECT_EQ(ret, static_cast<int32_t>(EdmReturnErrCode::EXECUTE_TIME_OUT));
    EXPECT_EQ(reply.ReadInt32(), static_cast<int32_t>(EdmReturnErrCode::EXECUTE_TIME_OUT));
}

/**
 * @tc.name: OnHandlePolicy_InvalidJson_ParamError
 * @tc.desc: Test OnHandlePolicy function when power policy value is invalid json.
 * @tc.type: FUNC
 */
HWTEST_F(PowerModeSettingsPluginTest, OnHandlePolicy_InvalidJson_ParameterVerificationFailed, TestSize.Level1)
{
    std::shared_ptr<PowerModeSettingsPlugin> plugin = CreatePlugin();
    ErrCode ret = HandlePolicy(plugin, SettingsItem::POWER_POLICY_AC, "json error");
    EXPECT_EQ(ret, static_cast<int32_t>(EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED));
}

/**
 * @tc.name: OnHandlePolicy_MissingPowerScene_ParameterVerificationFailed
 * @tc.desc: Test OnHandlePolicy function when powerScene key is missing.
 * @tc.type: FUNC
 */
HWTEST_F(PowerModeSettingsPluginTest, OnHandlePolicy_MissingPowerScene_ParameterVerificationFailed, TestSize.Level1)
{
    std::shared_ptr<PowerModeSettingsPlugin> plugin = CreatePlugin();
    ErrCode ret = HandlePolicy(plugin, SettingsItem::POWER_POLICY_DC,
        "{\"powerPolicy\":{\"powerPolicyAction\":1,\"delayTime\":1000}}");
    EXPECT_EQ(ret, static_cast<int32_t>(EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED));
}

/**
 * @tc.name: OnHandlePolicy_MissingPowerPolicy_ParameterVerificationFailed
 * @tc.desc: Test OnHandlePolicy function when powerPolicy key is missing.
 * @tc.type: FUNC
 */
HWTEST_F(PowerModeSettingsPluginTest, OnHandlePolicy_MissingPowerPolicy_ParameterVerificationFailed, TestSize.Level1)
{
    std::shared_ptr<PowerModeSettingsPlugin> plugin = CreatePlugin();
    ErrCode ret = HandlePolicy(plugin, SettingsItem::POWER_POLICY_AC, "{\"powerScene\":0}");
    EXPECT_EQ(ret, static_cast<int32_t>(EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED));
}

/**
 * @tc.name: OnHandlePolicy_UnsupportedPowerScene_ParameterVerificationFailed
 * @tc.desc: Test OnHandlePolicy function when power scene is unsupported.
 * @tc.type: FUNC
 */
HWTEST_F(PowerModeSettingsPluginTest, OnHandlePolicy_UnsupportedPowerScene_ParameterVerificationFailed, TestSize.Level1)
{
    std::shared_ptr<PowerModeSettingsPlugin> plugin = CreatePlugin();
    ErrCode ret = HandlePolicy(plugin, SettingsItem::POWER_POLICY_DC,
        "{\"powerScene\":1000,\"powerPolicy\":{\"powerPolicyAction\":1,\"delayTime\":1000}}");
    EXPECT_EQ(ret, static_cast<int32_t>(EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED));
}

/**
 * @tc.name: OnHandlePolicy_ActionOutOfRange_ParameterVerificationFailed
 * @tc.desc: Test OnHandlePolicy function when powerPolicyAction is out of range.
 * @tc.type: FUNC
 */
HWTEST_F(PowerModeSettingsPluginTest, OnHandlePolicy_ActionOutOfRange_ParameterVerificationFailed, TestSize.Level1)
{
    std::shared_ptr<PowerModeSettingsPlugin> plugin = CreatePlugin();
    ErrCode ret = HandlePolicy(plugin, SettingsItem::POWER_POLICY_AC,
        "{\"powerScene\":0,\"powerPolicy\":{\"powerPolicyAction\":5,\"delayTime\":1000}}");
    EXPECT_EQ(ret, static_cast<int32_t>(EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED));
}

/**
 * @tc.name: OnHandlePolicy_DelayTimeInvalid_ParameterVerificationFailed
 * @tc.desc: Test OnHandlePolicy function when delayTime equals 30000.
 * @tc.type: FUNC
 */
HWTEST_F(PowerModeSettingsPluginTest, OnHandlePolicy_DelayTimeInvalid_ParameterVerificationFailed, TestSize.Level1)
{
    std::shared_ptr<PowerModeSettingsPlugin> plugin = CreatePlugin();
    ErrCode ret = HandlePolicy(plugin, SettingsItem::POWER_POLICY_DC,
        "{\"powerScene\":0,\"powerPolicy\":{\"powerPolicyAction\":1,\"delayTime\":30000}}");
    EXPECT_EQ(ret, static_cast<int32_t>(EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED));
}

/**
 * @tc.name: OnHandlePolicy_DelayTimeNegative_ParameterVerificationFailed
 * @tc.desc: Test OnHandlePolicy function when delayTime is negative (should be rejected, not wrapped to uint32).
 * @tc.type: FUNC
 */
HWTEST_F(PowerModeSettingsPluginTest, OnHandlePolicy_DelayTimeNegative_ParameterVerificationFailed, TestSize.Level1)
{
    std::shared_ptr<PowerModeSettingsPlugin> plugin = CreatePlugin();
    ErrCode ret = HandlePolicy(plugin, SettingsItem::POWER_POLICY_AC,
        "{\"powerScene\":0,\"powerPolicy\":{\"powerPolicyAction\":1,\"delayTime\":-1}}");
    EXPECT_EQ(ret, static_cast<int32_t>(EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED));
}

/**
 * @tc.name: OnHandlePolicy_DelayTimeNotNumber_ParameterVerificationFailed
 * @tc.desc: Test OnHandlePolicy function when delayTime is a string (non-number type).
 * @tc.type: FUNC
 */
HWTEST_F(PowerModeSettingsPluginTest, OnHandlePolicy_DelayTimeNotNumber_ParameterVerificationFailed, TestSize.Level1)
{
    std::shared_ptr<PowerModeSettingsPlugin> plugin = CreatePlugin();
    ErrCode ret = HandlePolicy(plugin, SettingsItem::POWER_POLICY_DC,
        "{\"powerScene\":0,\"powerPolicy\":{\"powerPolicyAction\":1,\"delayTime\":\"1000\"}}");
    EXPECT_EQ(ret, static_cast<int32_t>(EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED));
}

/**
 * @tc.name: OnHandlePolicy_SetPowerPolicySuccess
 * @tc.desc: Test OnHandlePolicy function when setting power policy successfully.
 * @tc.type: FUNC
 */
HWTEST_F(PowerModeSettingsPluginTest, OnHandlePolicy_SetPowerPolicySuccess, TestSize.Level1)
{
    std::shared_ptr<PowerModeSettingsPlugin> plugin = CreatePlugin();
    EdmDataAbilityUtils::SetResult("power_suspend_normal");
    ErrCode ret = HandlePolicy(plugin, SettingsItem::POWER_POLICY_DC, VALID_POWER_POLICY);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: OnHandlePolicy_PowerPolicyReadSettingsDataFailed_ExecuteTimeOut
 * @tc.desc: Test OnHandlePolicy function when reading suspend settings data failed.
 * @tc.type: FUNC
 */
HWTEST_F(PowerModeSettingsPluginTest, OnHandlePolicy_PowerPolicyReadSettingsDataFailed_ExecuteTimeOut,
    TestSize.Level1)
{
    std::shared_ptr<PowerModeSettingsPlugin> plugin = CreatePlugin();
    EdmDataAbilityUtils::SetResult("SYSTEM_ABNORMALLY");
    ErrCode ret = HandlePolicy(plugin, SettingsItem::POWER_POLICY_AC, VALID_POWER_POLICY);
    EXPECT_EQ(ret, static_cast<int32_t>(EdmReturnErrCode::EXECUTE_TIME_OUT));
}

/**
 * @tc.name: OnHandlePolicy_InvalidSuspendJson_ExecuteTimeOut
 * @tc.desc: Test OnHandlePolicy function when suspend settings data is invalid json.
 * @tc.type: FUNC
 */
HWTEST_F(PowerModeSettingsPluginTest, OnHandlePolicy_InvalidSuspendJson_ExecuteTimeOut, TestSize.Level1)
{
    std::shared_ptr<PowerModeSettingsPlugin> plugin = CreatePlugin();
    EdmDataAbilityUtils::SetResult("power_suspend_json_error");
    ErrCode ret = HandlePolicy(plugin, SettingsItem::POWER_POLICY_DC, VALID_POWER_POLICY);
    EXPECT_EQ(ret, static_cast<int32_t>(EdmReturnErrCode::EXECUTE_TIME_OUT));
}

/**
 * @tc.name: OnHandlePolicy_TimeoutKeyMissing_ExecuteTimeOut
 * @tc.desc: Test OnHandlePolicy function when suspend settings json has no timeout node.
 * @tc.type: FUNC
 */
HWTEST_F(PowerModeSettingsPluginTest, OnHandlePolicy_TimeoutKeyMissing_ExecuteTimeOut, TestSize.Level1)
{
    std::shared_ptr<PowerModeSettingsPlugin> plugin = CreatePlugin();
    EdmDataAbilityUtils::SetResult("power_suspend_json_no_time_out");
    ErrCode ret = HandlePolicy(plugin, SettingsItem::POWER_POLICY_AC, VALID_POWER_POLICY);
    EXPECT_EQ(ret, static_cast<int32_t>(EdmReturnErrCode::EXECUTE_TIME_OUT));
}

/**
 * @tc.name: OnHandlePolicy_TimeoutNotObject_ExecuteTimeOut
 * @tc.desc: Test OnHandlePolicy function when timeout node of suspend settings json is not object.
 * @tc.type: FUNC
 */
HWTEST_F(PowerModeSettingsPluginTest, OnHandlePolicy_TimeoutNotObject_ExecuteTimeOut, TestSize.Level1)
{
    std::shared_ptr<PowerModeSettingsPlugin> plugin = CreatePlugin();
    EdmDataAbilityUtils::SetResult("power_suspend_json_key_not_object");
    ErrCode ret = HandlePolicy(plugin, SettingsItem::POWER_POLICY_DC, VALID_POWER_POLICY);
    EXPECT_EQ(ret, static_cast<int32_t>(EdmReturnErrCode::EXECUTE_TIME_OUT));
}

/**
 * @tc.name: OnGetPolicy_PowerPolicyReadSettingsDataFailed_ExecuteTimeOut
 * @tc.desc: Test OnGetPolicy function when reading power policy data failed.
 * @tc.type: FUNC
 */
HWTEST_F(PowerModeSettingsPluginTest, OnGetPolicy_PowerPolicyReadSettingsDataFailed_ExecuteTimeOut,
    TestSize.Level1)
{
    std::shared_ptr<PowerModeSettingsPlugin> plugin = CreatePlugin();
    MessageParcel reply;
    EdmDataAbilityUtils::SetResult("SYSTEM_ABNORMALLY");
    ErrCode ret = GetPolicy(plugin, SettingsItem::POWER_POLICY_DC, reply);
    EXPECT_EQ(ret, static_cast<int32_t>(EdmReturnErrCode::EXECUTE_TIME_OUT));
    EXPECT_EQ(reply.ReadInt32(), static_cast<int32_t>(EdmReturnErrCode::EXECUTE_TIME_OUT));
}

/**
 * @tc.name: OnGetPolicy_PowerPolicySuccess
 * @tc.desc: Test OnGetPolicy function and reply contains power policy json string.
 * @tc.type: FUNC
 */
HWTEST_F(PowerModeSettingsPluginTest, OnGetPolicy_PowerPolicySuccess, TestSize.Level1)
{
    std::shared_ptr<PowerModeSettingsPlugin> plugin = CreatePlugin();
    MessageParcel reply;
    EdmDataAbilityUtils::SetResult("power_suspend_normal");
    ErrCode ret = GetPolicy(plugin, SettingsItem::POWER_POLICY_AC, reply);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), static_cast<int32_t>(ERR_OK));
    std::string policy = reply.ReadString();
    EXPECT_NE(policy.find("\"powerScene\""), std::string::npos);
    EXPECT_NE(policy.find("\"powerPolicyAction\""), std::string::npos);
    EXPECT_NE(policy.find("\"delayTime\""), std::string::npos);
}

/**
 * @tc.name: OnGetPolicy_PowerPolicyTimeoutNotObject_ExecuteTimeOut
 * @tc.desc: Test OnGetPolicy function when timeout node of suspend settings json is not object.
 * @tc.type: FUNC
 */
HWTEST_F(PowerModeSettingsPluginTest, OnGetPolicy_PowerPolicyTimeoutNotObject_ExecuteTimeOut, TestSize.Level1)
{
    std::shared_ptr<PowerModeSettingsPlugin> plugin = CreatePlugin();
    MessageParcel reply;
    EdmDataAbilityUtils::SetResult("power_suspend_json_key_not_object");
    ErrCode ret = GetPolicy(plugin, SettingsItem::POWER_POLICY_DC, reply);
    EXPECT_EQ(ret, static_cast<int32_t>(EdmReturnErrCode::EXECUTE_TIME_OUT));
    EXPECT_EQ(reply.ReadInt32(), static_cast<int32_t>(EdmReturnErrCode::EXECUTE_TIME_OUT));
}

/**
 * @tc.name: OnHandlePolicy_CrossUserNotAllowed
 * @tc.desc: Test OnHandlePolicy function when userId differs from current user on new interface.
 * @tc.type: FUNC
 */
HWTEST_F(PowerModeSettingsPluginTest, OnHandlePolicy_CrossUserNotAllowed, TestSize.Level1)
{
    std::shared_ptr<PowerModeSettingsPlugin> plugin = CreatePlugin();
    auto factory = std::make_shared<ExternalManagerFactoryMock>();
    auto osAccountMgrMock = std::make_shared<EdmOsAccountManagerImplMock>();
    plugin->externalManagerFactory_ = factory;
    EXPECT_CALL(*factory, CreateOsAccountManager).Times(1).WillOnce(Return(osAccountMgrMock));
    EXPECT_CALL(*osAccountMgrMock, GetCurrentUserId).Times(1).WillOnce(Return(100));

    MessageParcel data;
    data.WriteInt32(static_cast<int32_t>(SettingsItem::SCREEN_OFF_DC));
    data.WriteString("30000");
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"TestString", "", false};
    ErrCode ret = plugin->OnHandlePolicy(GetFuncCodeNew(FuncOperateType::SET), data, reply, handlePolicyData, 101);
    EXPECT_EQ(ret, static_cast<int32_t>(EdmReturnErrCode::CROSS_USER_NOT_ALLOWED));
}

/**
 * @tc.name: OnHandlePolicy_SameUserNewInterface_Success
 * @tc.desc: Test OnHandlePolicy function when userId equals current user on new interface passes cross-user check.
 * @tc.type: FUNC
 */
HWTEST_F(PowerModeSettingsPluginTest, OnHandlePolicy_SameUserNewInterface_Success, TestSize.Level1)
{
    std::shared_ptr<PowerModeSettingsPlugin> plugin = CreatePlugin();
    auto factory = std::make_shared<ExternalManagerFactoryMock>();
    auto osAccountMgrMock = std::make_shared<EdmOsAccountManagerImplMock>();
    plugin->externalManagerFactory_ = factory;
    EXPECT_CALL(*factory, CreateOsAccountManager).Times(1).WillOnce(Return(osAccountMgrMock));
    EXPECT_CALL(*osAccountMgrMock, GetCurrentUserId).Times(1).WillOnce(Return(100));
    EdmDataAbilityUtils::SetResult("test success");

    MessageParcel data;
    data.WriteInt32(static_cast<int32_t>(SettingsItem::SCREEN_OFF_DC));
    data.WriteString("30000");
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"TestString", "", false};
    ErrCode ret = plugin->OnHandlePolicy(GetFuncCodeNew(FuncOperateType::SET), data, reply, handlePolicyData, 100);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: OnHandlePolicy_OldInterfaceCrossUser_NoCrossUserCheck
 * @tc.desc: Test OnHandlePolicy function on old interface (without admin) skips cross-user check.
 * @tc.type: FUNC
 */
HWTEST_F(PowerModeSettingsPluginTest, OnHandlePolicy_OldInterfaceCrossUser_NoCrossUserCheck, TestSize.Level1)
{
    std::shared_ptr<PowerModeSettingsPlugin> plugin = CreatePlugin();
    EdmDataAbilityUtils::SetResult("test success");

    MessageParcel data;
    data.WriteInt32(static_cast<int32_t>(SettingsItem::SCREEN_OFF_DC));
    data.WriteString("30000");
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"TestString", "", false};
    // Old interface (POLICY_FUNC_CODE, not POLICY_FUNC_CODE_NEW) should not trigger cross-user check
    ErrCode ret = plugin->OnHandlePolicy(GetFuncCode(FuncOperateType::SET), data, reply, handlePolicyData, 101);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: OnHandlePolicy_GetUserIdFailed_SkipCrossUserCheck
 * @tc.desc: Test OnHandlePolicy function when GetCurrentUserId fails, cross-user check is skipped.
 * @tc.type: FUNC
 */
HWTEST_F(PowerModeSettingsPluginTest, OnHandlePolicy_GetUserIdFailed_SkipCrossUserCheck, TestSize.Level1)
{
    std::shared_ptr<PowerModeSettingsPlugin> plugin = CreatePlugin();
    auto factory = std::make_shared<ExternalManagerFactoryMock>();
    auto osAccountMgrMock = std::make_shared<EdmOsAccountManagerImplMock>();
    plugin->externalManagerFactory_ = factory;
    EXPECT_CALL(*factory, CreateOsAccountManager).Times(1).WillOnce(Return(osAccountMgrMock));
    EXPECT_CALL(*osAccountMgrMock, GetCurrentUserId).Times(1).WillOnce(Return(-1));
    EdmDataAbilityUtils::SetResult("test success");

    MessageParcel data;
    data.WriteInt32(static_cast<int32_t>(SettingsItem::SCREEN_OFF_DC));
    data.WriteString("30000");
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"TestString", "", false};
    ErrCode ret = plugin->OnHandlePolicy(GetFuncCodeNew(FuncOperateType::SET), data, reply, handlePolicyData, 101);
    EXPECT_EQ(ret, ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
