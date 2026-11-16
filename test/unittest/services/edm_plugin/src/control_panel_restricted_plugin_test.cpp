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

#define private public
#define protected public
#include "control_panel_restricted_plugin.h"
#undef protected
#undef private

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "parameters.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string PARAM_CONTROL_PANEL_RESTRICTED = "persist.edm.control_panel_restricted";

class ControlPanelRestrictedPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);
    static void TearDownTestSuite(void);
};

void ControlPanelRestrictedPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void ControlPanelRestrictedPluginTest::TearDownTestSuite(void)
{
    system::SetParameter(PARAM_CONTROL_PANEL_RESTRICTED, "false");
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: Constructor_Normal_Success
 * @tc.desc: Test constructor sets policy code, name and persist param correctly.
 * @tc.type: FUNC
 */
HWTEST_F(ControlPanelRestrictedPluginTest, Constructor_Normal_Success, TestSize.Level1)
{
    ControlPanelRestrictedPlugin plugin;
    EXPECT_EQ(plugin.policyCode_, EdmInterfaceCode::CONTROL_PANEL_RESTRICTED);
    EXPECT_EQ(plugin.policyName_, PolicyName::POLICY_CONTROL_PANEL_RESTRICTED);
    EXPECT_EQ(plugin.persistParam_, PARAM_CONTROL_PANEL_RESTRICTED);
    EXPECT_TRUE(plugin.NeedSavePolicy());
}

/**
 * @tc.name: OnSetPolicy_True_Success
 * @tc.desc: Test setting restricted mode to true writes persist param directly.
 * @tc.type: FUNC
 */
HWTEST_F(ControlPanelRestrictedPluginTest, OnSetPolicy_True_Success, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    auto plugin = std::make_shared<ControlPanelRestrictedPlugin>();
    HandlePolicyData handlePolicyData{"", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::CONTROL_PANEL_RESTRICTED);
    system::SetParameter(PARAM_CONTROL_PANEL_RESTRICTED, "false");

    data.WriteBool(true);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(handlePolicyData.isChanged);
    EXPECT_EQ(system::GetParameter(PARAM_CONTROL_PANEL_RESTRICTED, "false"), "true");
}

/**
 * @tc.name: OnSetPolicy_False_Success
 * @tc.desc: Test setting restricted mode to false writes persist param directly.
 * @tc.type: FUNC
 */
HWTEST_F(ControlPanelRestrictedPluginTest, OnSetPolicy_False_Success, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    auto plugin = std::make_shared<ControlPanelRestrictedPlugin>();
    HandlePolicyData handlePolicyData{"true", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::CONTROL_PANEL_RESTRICTED);
    system::SetParameter(PARAM_CONTROL_PANEL_RESTRICTED, "true");

    data.WriteBool(false);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(handlePolicyData.isChanged);
    EXPECT_EQ(system::GetParameter(PARAM_CONTROL_PANEL_RESTRICTED, "true"), "false");
}

/**
 * @tc.name: OnSetPolicy_SameValue_NoChange
 * @tc.desc: Test setting the same value does not report a global change.
 * @tc.type: FUNC
 */
HWTEST_F(ControlPanelRestrictedPluginTest, OnSetPolicy_SameValue_NoChange, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    auto plugin = std::make_shared<ControlPanelRestrictedPlugin>();
    HandlePolicyData handlePolicyData{"true", "true", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::CONTROL_PANEL_RESTRICTED);
    system::SetParameter(PARAM_CONTROL_PANEL_RESTRICTED, "true");

    data.WriteBool(true);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(handlePolicyData.isChanged);
    EXPECT_EQ(system::GetParameter(PARAM_CONTROL_PANEL_RESTRICTED, "true"), "true");
}

/**
 * @tc.name: OnSetPolicy_FalseWins_OverOtherAdminTrue
 * @tc.desc: Test a later false from one admin overrides another admin's true.
 * @tc.type: FUNC
 */
HWTEST_F(ControlPanelRestrictedPluginTest, OnSetPolicy_FalseWins_OverOtherAdminTrue, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    auto plugin = std::make_shared<ControlPanelRestrictedPlugin>();
    HandlePolicyData handlePolicyData{"", "true", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::CONTROL_PANEL_RESTRICTED);
    system::SetParameter(PARAM_CONTROL_PANEL_RESTRICTED, "true");

    data.WriteBool(false);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(handlePolicyData.isChanged);
    EXPECT_EQ(system::GetParameter(PARAM_CONTROL_PANEL_RESTRICTED, "true"), "false");
}

/**
 * @tc.name: OnSetPolicy_TrueAfterOtherAdminFalse
 * @tc.desc: Test a later true from one admin overrides another admin's false.
 * @tc.type: FUNC
 */
HWTEST_F(ControlPanelRestrictedPluginTest, OnSetPolicy_TrueAfterOtherAdminFalse, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    auto plugin = std::make_shared<ControlPanelRestrictedPlugin>();
    HandlePolicyData handlePolicyData{"true", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::CONTROL_PANEL_RESTRICTED);
    system::SetParameter(PARAM_CONTROL_PANEL_RESTRICTED, "false");

    data.WriteBool(true);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(handlePolicyData.isChanged);
    EXPECT_EQ(system::GetParameter(PARAM_CONTROL_PANEL_RESTRICTED, "false"), "true");
}

/**
 * @tc.name: OnGetPolicy_DeviceLevelTrue_OtherAdminQuery_ReturnTrue
 * @tc.desc: Test an admin that never set the policy still gets the device-level persist value.
 * @tc.type: FUNC
 */
HWTEST_F(ControlPanelRestrictedPluginTest, OnGetPolicy_DeviceLevelTrue_OtherAdminQuery_ReturnTrue, TestSize.Level1)
{
    auto plugin = std::make_shared<ControlPanelRestrictedPlugin>();
    std::string policyData = "";
    MessageParcel data;
    MessageParcel reply;
    system::SetParameter(PARAM_CONTROL_PANEL_RESTRICTED, "true");

    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_TRUE(reply.ReadBool());
}

/**
 * @tc.name: OnGetPolicy_PersistFalse_ReturnFalse
 * @tc.desc: Test persist param is the source of truth even when policy data holds a stale true.
 * @tc.type: FUNC
 */
HWTEST_F(ControlPanelRestrictedPluginTest, OnGetPolicy_PersistFalse_ReturnFalse, TestSize.Level1)
{
    auto plugin = std::make_shared<ControlPanelRestrictedPlugin>();
    std::string policyData = EdmConstants::CONST_TRUE;
    MessageParcel data;
    MessageParcel reply;
    system::SetParameter(PARAM_CONTROL_PANEL_RESTRICTED, "false");

    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_FALSE(reply.ReadBool());
}

/**
 * @tc.name: OnGetPolicy_InvalidPersistValue_ReturnError
 * @tc.desc: Test query returns execute error when the persist value is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(ControlPanelRestrictedPluginTest, OnGetPolicy_InvalidPersistValue_ReturnError, TestSize.Level1)
{
    auto plugin = std::make_shared<ControlPanelRestrictedPlugin>();
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    system::SetParameter(PARAM_CONTROL_PANEL_RESTRICTED, "invalid");

    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
}

/**
 * @tc.name: OnAdminRemove_LastHolder_ClearPersist
 * @tc.desc: Test admin removal clears persist when no other configured admin holds true.
 * @tc.type: FUNC
 */
HWTEST_F(ControlPanelRestrictedPluginTest, OnAdminRemove_LastHolder_ClearPersist, TestSize.Level1)
{
    auto plugin = std::make_shared<ControlPanelRestrictedPlugin>();
    system::SetParameter(PARAM_CONTROL_PANEL_RESTRICTED, "true");

    ErrCode ret = plugin->OnAdminRemove("com.edm.test.admin", EdmConstants::CONST_TRUE, "", DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(system::GetParameter(PARAM_CONTROL_PANEL_RESTRICTED, "true"), "false");
}

/**
 * @tc.name: OnAdminRemove_OtherHolder_KeepPersist
 * @tc.desc: Test admin removal keeps persist when another configured admin holds true.
 * @tc.type: FUNC
 */
HWTEST_F(ControlPanelRestrictedPluginTest, OnAdminRemove_OtherHolder_KeepPersist, TestSize.Level1)
{
    auto plugin = std::make_shared<ControlPanelRestrictedPlugin>();
    system::SetParameter(PARAM_CONTROL_PANEL_RESTRICTED, "true");

    ErrCode ret = plugin->OnAdminRemove("com.edm.test.admin", EdmConstants::CONST_TRUE,
        EdmConstants::CONST_TRUE, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(system::GetParameter(PARAM_CONTROL_PANEL_RESTRICTED, "true"), "true");
}

/**
 * @tc.name: OnAdminRemove_NoReEnable
 * @tc.desc: Test removal does not re-enable the flag when persist is already false.
 * @tc.type: FUNC
 */
HWTEST_F(ControlPanelRestrictedPluginTest, OnAdminRemove_NoReEnable, TestSize.Level1)
{
    auto plugin = std::make_shared<ControlPanelRestrictedPlugin>();
    system::SetParameter(PARAM_CONTROL_PANEL_RESTRICTED, "false");

    ErrCode ret = plugin->OnAdminRemove("com.edm.test.admin", EdmConstants::CONST_FALSE,
        EdmConstants::CONST_TRUE, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(system::GetParameter(PARAM_CONTROL_PANEL_RESTRICTED, "false"), "false");
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS