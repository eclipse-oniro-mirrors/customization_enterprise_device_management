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

#include <system_ability_definition.h>

#include "application_instance.h"
#include "bundle_mgr_interface.h"
#include "disallow_parent_control_plugin.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_sys_manager.h"
#include "ipolicy_manager.h"
#include "manage_apps_serializer.h"
#include "parameters.h"
#include "policy_manager.h"
#include "utils.h"
#include "iext_info_manager.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string PARAM_PARENT_CONTROL_DISABLE = "persist.edm.parent_control_disable";

class DisallowParentControlPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);

    void TearDown() override;

    static bool IsParentControlInstalled();
    static bool GetParentControlEnabled(bool &enabled);
    static void SetParentControlDisallowed(bool disallow);
    static void SetNonStopAppsPolicy(const std::string &policyValue);
};

void DisallowParentControlPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DisallowParentControlPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

void DisallowParentControlPluginTest::TearDown()
{
    system::SetParameter(PARAM_PARENT_CONTROL_DISABLE, "false");
    SetNonStopAppsPolicy("");
    if (IsParentControlInstalled()) {
        SetParentControlDisallowed(false);
    }
}

bool DisallowParentControlPluginTest::IsParentControlInstalled()
{
    auto remoteObejct = EdmSysManager::GetRemoteObjectOfSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObejct);
    if (proxy == nullptr) {
        return false;
    }
    AppExecFwk::ApplicationInfo appInfo;
    return proxy->GetApplicationInfo(IExtInfoManager::parentControlBundleName,
        AppExecFwk::ApplicationFlag::GET_BASIC_APPLICATION_INFO, DEFAULT_USER_ID, appInfo);
}

bool DisallowParentControlPluginTest::GetParentControlEnabled(bool &enabled)
{
    auto remoteObejct = EdmSysManager::GetRemoteObjectOfSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObejct);
    if (proxy == nullptr) {
        return false;
    }
    AppExecFwk::ApplicationInfo appInfo;
    if (!proxy->GetApplicationInfo(IExtInfoManager::parentControlBundleName,
        AppExecFwk::ApplicationFlag::GET_BASIC_APPLICATION_INFO, DEFAULT_USER_ID, appInfo)) {
        return false;
    }
    enabled = appInfo.enabled;
    return true;
}

void DisallowParentControlPluginTest::SetParentControlDisallowed(bool disallow)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(disallow);
    auto plugin = std::make_shared<DisallowParentControlPlugin>();
    HandlePolicyData handlePolicyData{"", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DISALLOW_PARENT_CONTROL);
    plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
}

void DisallowParentControlPluginTest::SetNonStopAppsPolicy(const std::string &policyValue)
{
    auto policyManager = PolicyManager::GetInstance();
    std::vector<ApplicationInstance> apps;
    std::string value = policyValue;
    if (policyValue == "parentControl") {
        apps = {{"test_app_id", IExtInfoManager::parentControlBundleName, DEFAULT_USER_ID, 0}};
        ManageAppsSerializer::GetInstance()->Serialize(apps, value);
    } else if (policyValue == "otherApp") {
        apps = {{"test_app_id", "com.test.app", DEFAULT_USER_ID, 0}};
        ManageAppsSerializer::GetInstance()->Serialize(apps, value);
    }
    policyManager->SetPolicy("com.edm.test.admin", PolicyName::POLICY_MANAGE_USER_NON_STOP_APPS,
        value, value, DEFAULT_USER_ID);
}

/**
 * @tc.name: TestOnSetPolicyDisable
 * @tc.desc: Test DisallowParentControlPlugin disable parent control writes persist param and disables app.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowParentControlPluginTest, TestOnSetPolicyDisable, TestSize.Level1)
{
    if (!IsParentControlInstalled()) {
        GTEST_SKIP() << "parentcontrol not installed on this device";
    }
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(true);
    auto plugin = std::make_shared<DisallowParentControlPlugin>();
    HandlePolicyData handlePolicyData{"", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DISALLOW_PARENT_CONTROL);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_TRUE(handlePolicyData.isChanged);
    ASSERT_EQ(handlePolicyData.policyData, "true");
    ASSERT_TRUE(system::GetBoolParameter(PARAM_PARENT_CONTROL_DISABLE, false));

    bool enabled = true;
    ASSERT_TRUE(GetParentControlEnabled(enabled));
    ASSERT_FALSE(enabled);
}

/**
 * @tc.name: TestOnSetPolicyEnable
 * @tc.desc: Test DisallowParentControlPlugin enable parent control clears persist param and enables app.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowParentControlPluginTest, TestOnSetPolicyEnable, TestSize.Level1)
{
    if (!IsParentControlInstalled()) {
        GTEST_SKIP() << "parentcontrol not installed on this device";
    }
    system::SetParameter(PARAM_PARENT_CONTROL_DISABLE, "true");
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(false);
    auto plugin = std::make_shared<DisallowParentControlPlugin>();
    HandlePolicyData handlePolicyData{"true", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DISALLOW_PARENT_CONTROL);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(handlePolicyData.policyData, "");
    ASSERT_FALSE(system::GetBoolParameter(PARAM_PARENT_CONTROL_DISABLE, true));
    bool enabled = false;
    ASSERT_TRUE(GetParentControlEnabled(enabled));
    ASSERT_TRUE(enabled);
}

/**
 * @tc.name: TestOnGetPolicyReadsPersistParam
 * @tc.desc: Test query reads persist param, so disabled state survives reboot without re-setting policy.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowParentControlPluginTest, TestOnGetPolicyReadsPersistParam, TestSize.Level1)
{
    auto plugin = std::make_shared<DisallowParentControlPlugin>();
    MessageParcel data;
    MessageParcel reply;
    std::string policyData = "";

    system::SetParameter(PARAM_PARENT_CONTROL_DISABLE, "true");
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    int32_t result = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(result));
    ASSERT_EQ(result, ERR_OK);
    bool disallow = false;
    ASSERT_TRUE(reply.ReadBool(disallow));
    ASSERT_TRUE(disallow);
}

/**
 * @tc.name: TestOnGetPolicyDefaultFalse
 * @tc.desc: Test query returns false when persist param is not set.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowParentControlPluginTest, TestOnGetPolicyDefaultFalse, TestSize.Level1)
{
    system::SetParameter(PARAM_PARENT_CONTROL_DISABLE, "false");
    auto plugin = std::make_shared<DisallowParentControlPlugin>();
    MessageParcel data;
    MessageParcel reply;
    std::string policyData = "";

    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    int32_t result = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(result));
    ASSERT_EQ(result, ERR_OK);
    bool disallow = true;
    ASSERT_TRUE(reply.ReadBool(disallow));
    ASSERT_FALSE(disallow);
}

/**
 * @tc.name: TestCheckConflictWithNonStopHit
 * @tc.desc: Test disable parent control is rejected when parentcontrol is in user non-stop apps list.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowParentControlPluginTest, TestCheckConflictWithNonStopHit, TestSize.Level1)
{
    if (!IsParentControlInstalled()) {
        GTEST_SKIP() << "parentcontrol not installed on this device";
    }
    SetNonStopAppsPolicy("parentControl");
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(true);
    auto plugin = std::make_shared<DisallowParentControlPlugin>();
    HandlePolicyData handlePolicyData{"", "", false};
    std::int32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DISALLOW_PARENT_CONTROL);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);
    ASSERT_FALSE(system::GetBoolParameter(PARAM_PARENT_CONTROL_DISABLE, false));

    bool enabled = false;
    ASSERT_TRUE(GetParentControlEnabled(enabled));
    ASSERT_TRUE(enabled);
}

/**
 * @tc.name: TestCheckConflictWithNonStopMiss
 * @tc.desc: Test disable parent control succeeds when non-stop list contains other apps.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowParentControlPluginTest, TestCheckConflictWithNonStopMiss, TestSize.Level1)
{
    if (!IsParentControlInstalled()) {
        GTEST_SKIP() << "parentcontrol not installed on this device";
    }
    SetNonStopAppsPolicy("otherApp");
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(true);
    auto plugin = std::make_shared<DisallowParentControlPlugin>();
    HandlePolicyData handlePolicyData{"", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DISALLOW_PARENT_CONTROL);

    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_TRUE(system::GetBoolParameter(PARAM_PARENT_CONTROL_DISABLE, false));
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
