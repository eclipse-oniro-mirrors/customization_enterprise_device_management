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

#include "disable_switch_datacard_plugin.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "func_code.h"
#include "parameters.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string PERSIST_EDM_SWITCH_DATACARD_DISABLE =
    "persist.edm.switch_datacard_disable";

class TestDisableSwitchDatacardPlugin : public DisableSwitchDatacardPlugin {
public:
    void SetInvalidPersistParam()
    {
        persistParam_ = "persist.edm.invalid@param name";
    }
};

class DisableSwitchDatacardPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);
    static void TearDownTestSuite(void);
};

void DisableSwitchDatacardPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmServiceEnable();
    Utils::SetEdmInitialEnv();
}

void DisableSwitchDatacardPluginTest::TearDownTestSuite(void)
{
    Utils::SetEdmServiceDisable();
    Utils::ResetTokenTypeAndUid();
    OHOS::system::SetParameter(PERSIST_EDM_SWITCH_DATACARD_DISABLE, "false");
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestSetPolicyTrue
 * @tc.desc: Test DisableSwitchDatacardPlugin::OnSetPolicy with true.
 * @tc.type: FUNC
 */
HWTEST_F(DisableSwitchDatacardPluginTest, TestSetPolicyTrue, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(true);
    std::shared_ptr<IPlugin> plugin = std::make_shared<DisableSwitchDatacardPlugin>();
    HandlePolicyData handlePolicyData{"false", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE(static_cast<std::uint32_t>(FuncOperateType::SET),
        EdmInterfaceCode::SWITCH_DATACARD_DISABLE);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_TRUE(OHOS::system::GetBoolParameter(PERSIST_EDM_SWITCH_DATACARD_DISABLE, false));
}

/**
 * @tc.name: TestSetPolicyFalse
 * @tc.desc: Test DisableSwitchDatacardPlugin::OnSetPolicy with false.
 * @tc.type: FUNC
 */
HWTEST_F(DisableSwitchDatacardPluginTest, TestSetPolicyFalse, TestSize.Level1)
{
    OHOS::system::SetParameter(PERSIST_EDM_SWITCH_DATACARD_DISABLE, "true");
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(false);
    std::shared_ptr<IPlugin> plugin = std::make_shared<DisableSwitchDatacardPlugin>();
    HandlePolicyData handlePolicyData{"true", "", true};
    std::uint32_t funcCode = POLICY_FUNC_CODE(static_cast<std::uint32_t>(FuncOperateType::SET),
        EdmInterfaceCode::SWITCH_DATACARD_DISABLE);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_FALSE(OHOS::system::GetBoolParameter(PERSIST_EDM_SWITCH_DATACARD_DISABLE, true));
}

/**
 * @tc.name: TestSetPolicyIdempotent
 * @tc.desc: Test setting true twice keeps the parameter unchanged and reports no policy change.
 * @tc.type: FUNC
 */
HWTEST_F(DisableSwitchDatacardPluginTest, TestSetPolicyIdempotent, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = std::make_shared<DisableSwitchDatacardPlugin>();
    std::uint32_t funcCode = POLICY_FUNC_CODE(static_cast<std::uint32_t>(FuncOperateType::SET),
        EdmInterfaceCode::SWITCH_DATACARD_DISABLE);
    for (int32_t i = 0; i < 2; i++) {
        MessageParcel data;
        MessageParcel reply;
        data.WriteBool(true);
        HandlePolicyData handlePolicyData{"true", "", true};
        ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
        ASSERT_EQ(ret, ERR_OK);
        ASSERT_TRUE(OHOS::system::GetBoolParameter(PERSIST_EDM_SWITCH_DATACARD_DISABLE, false));
        // The stored value is already "true" in each round, so the repeated set changes nothing.
        ASSERT_FALSE(handlePolicyData.isChanged);
    }
}

/**
 * @tc.name: TestAdminRemoveReset
 * @tc.desc: Test removing the only admin resets the parameter to false.
 * @tc.type: FUNC
 */
HWTEST_F(DisableSwitchDatacardPluginTest, TestAdminRemoveReset, TestSize.Level1)
{
    OHOS::system::SetParameter(PERSIST_EDM_SWITCH_DATACARD_DISABLE, "true");
    auto plugin = std::make_shared<DisableSwitchDatacardPlugin>();
    ErrCode ret = plugin->OnAdminRemove("com.edm.test.admin", std::string("true"), std::string(""),
        DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_FALSE(OHOS::system::GetBoolParameter(PERSIST_EDM_SWITCH_DATACARD_DISABLE, true));
}

/**
 * @tc.name: TestAdminRemoveKeepMerge
 * @tc.desc: Test removing one admin keeps the parameter when another admin still holds it.
 * @tc.type: FUNC
 */
HWTEST_F(DisableSwitchDatacardPluginTest, TestAdminRemoveKeepMerge, TestSize.Level1)
{
    OHOS::system::SetParameter(PERSIST_EDM_SWITCH_DATACARD_DISABLE, "true");
    auto plugin = std::make_shared<DisableSwitchDatacardPlugin>();
    ErrCode ret = plugin->OnAdminRemove("com.edm.test.admin", std::string("true"), std::string("true"),
        DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_TRUE(OHOS::system::GetBoolParameter(PERSIST_EDM_SWITCH_DATACARD_DISABLE, false));
}

/**
 * @tc.name: TestPermissionConfig
 * @tc.desc: Test the permission mapping of DisableSwitchDatacardPlugin.
 * @tc.type: FUNC
 */
HWTEST_F(DisableSwitchDatacardPluginTest, TestPermissionConfig, TestSize.Level1)
{
    auto plugin = std::make_shared<DisableSwitchDatacardPlugin>();
    std::string permission = plugin->GetPermission(FuncOperateType::SET,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN);
    ASSERT_EQ(permission, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_TELEPHONY);
    // The plugin declares a single permission, so every admin type resolves to the same one
    // (framework convention, see IPlugin::CheckAndGetPermissionFromConfig). BYOD is still blocked
    // by the ByodAdmin accessiblePolicies_ allowlist (fail-closed), not by an empty permission.
    std::string byodPermission = plugin->GetPermission(FuncOperateType::SET,
        IPlugin::PermissionType::BYOD_DEVICE_ADMIN);
    ASSERT_EQ(byodPermission, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_TELEPHONY);
}

/**
 * @tc.name: TestGetPolicyDisabled
 * @tc.desc: Test OnGetPolicy returns true when the policy is disabled.
 * @tc.type: FUNC
 */
HWTEST_F(DisableSwitchDatacardPluginTest, TestGetPolicyDisabled, TestSize.Level1)
{
    auto plugin = std::make_shared<DisableSwitchDatacardPlugin>();
    MessageParcel data;
    MessageParcel reply;
    std::string policyData{"true"};
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    int32_t code = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(code));
    ASSERT_EQ(code, ERR_OK);
    bool result = false;
    ASSERT_TRUE(reply.ReadBool(result));
    ASSERT_TRUE(result);
}

/**
 * @tc.name: TestGetPolicyEnabled
 * @tc.desc: Test OnGetPolicy returns false when the policy is not set.
 * @tc.type: FUNC
 */
HWTEST_F(DisableSwitchDatacardPluginTest, TestGetPolicyEnabled, TestSize.Level1)
{
    auto plugin = std::make_shared<DisableSwitchDatacardPlugin>();
    MessageParcel data;
    MessageParcel reply;
    std::string policyData{""};
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    int32_t code = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(code));
    ASSERT_EQ(code, ERR_OK);
    bool result = true;
    ASSERT_TRUE(reply.ReadBool(result));
    ASSERT_FALSE(result);
}

/**
 * @tc.name: TestSetPolicyParamFailed
 * @tc.desc: Test the error path when the system parameter cannot be written.
 * @tc.type: FUNC
 */
HWTEST_F(DisableSwitchDatacardPluginTest, TestSetPolicyParamFailed, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(true);
    auto plugin = std::make_shared<TestDisableSwitchDatacardPlugin>();
    plugin->SetInvalidPersistParam();
    HandlePolicyData handlePolicyData{"false", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE(static_cast<std::uint32_t>(FuncOperateType::SET),
        EdmInterfaceCode::SWITCH_DATACARD_DISABLE);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::SYSTEM_ABNORMALLY);
    ASSERT_FALSE(handlePolicyData.isChanged);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
