/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#define protected public
#define private public
#include "manage_freeze_exempted_apps_plugin_test.h"
#include "manage_apps_serializer.h"
#include "disallowed_running_bundles_plugin.h"
#undef private
#undef protected

#include "bundle_info.h"
#include "bundle_mgr_interface.h"
#include "if_system_ability_manager.h"
#include "iremote_stub.h"
#include "iservice_registry.h"
#include "parameters.h"
#include "system_ability_definition.h"
#include "array_string_serializer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "edm_sys_manager.h"
#include "func_code.h"
#include "utils.h"
#include "edm_bundle_manager_impl.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string BOOT_OEM_MODE = "const.boot.oemmode";
const std::string DEVELOP_PARAM = "rd";
const std::string USER_MODE = "user";
void ManageFreezeExemptedAppsPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void ManageFreezeExemptedAppsPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnHandlePolicyAddFailWithNullData
 * @tc.desc: Test ManageFreezeExemptedAppsPlugin::OnHandlePolicy add when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(ManageFreezeExemptedAppsPluginTest, TestOnHandlePolicyAddFailWithNullData, TestSize.Level1)
{
    ManageFreezeExemptedAppsPlugin plugin;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    std::vector<ApplicationInstance> freezeExemptedApps;
    ApplicationInstanceHandle::WriteApplicationInstanceVector(data, freezeExemptedApps);

    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::MANAGE_FREEZE_EXEMPTED_APPS);
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnHandlePolicyRemoveFailWithNullData
 * @tc.desc: Test ManageFreezeExemptedAppsPlugin::OnHandlePolicy remove when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(ManageFreezeExemptedAppsPluginTest, TestOnHandlePolicyRemoveFailWithNullData, TestSize.Level1)
{
    ManageFreezeExemptedAppsPlugin plugin;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    std::vector<ApplicationInstance> freezeExemptedApps;
    ApplicationInstanceHandle::WriteApplicationInstanceVector(data, freezeExemptedApps);

    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::MANAGE_FREEZE_EXEMPTED_APPS);
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnHandlePolicyFailWithOversizeData
 * @tc.desc: Test ManageFreezeExemptedAppsPlugin::OnHandlePolicy when data is oversize.
 * @tc.type: FUNC
 */
HWTEST_F(ManageFreezeExemptedAppsPluginTest, TestOnHandlePolicyFailWithOversizeData, TestSize.Level1)
{
    std::string developDeviceParam = system::GetParameter(BOOT_OEM_MODE, USER_MODE);
    if (developDeviceParam == DEVELOP_PARAM) {
        ManageFreezeExemptedAppsPlugin plugin;
        MessageParcel data;
        MessageParcel reply;
        HandlePolicyData policyData;
        std::string contactsBundleName, browserBundleName, appgalleryBundleName, thememanagerBundleName;
        std::string settingsBundleName, musicBundleName, booksBundleName;
        std::string mmsBundleName, photosBundleName, cameraBundleName, himovieBundleName;
        auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
        sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
        ASSERT_TRUE(proxy != nullptr);
        ErrCode res = proxy->GetBundleNameByAppId("5765880207853624761", contactsBundleName);
        ASSERT_TRUE(res == ERR_OK);
        res = proxy->GetBundleNameByAppId("1230215522310701824", browserBundleName);
        ASSERT_TRUE(res == ERR_OK);
        res = proxy->GetBundleNameByAppId("1164531384803416384", appgalleryBundleName);
        ASSERT_TRUE(res == ERR_OK);
        res = proxy->GetBundleNameByAppId("1173750081090759360", thememanagerBundleName);
        ASSERT_TRUE(res == ERR_OK);
        res = proxy->GetBundleNameByAppId("5765880207852919475", settingsBundleName);
        ASSERT_TRUE(res == ERR_OK);
        res = proxy->GetBundleNameByAppId("5765880207853068793", mmsBundleName);
        ASSERT_TRUE(res == ERR_OK);
        res = proxy->GetBundleNameByAppId("1207824849184017472", photosBundleName);
        ASSERT_TRUE(res == ERR_OK);
        res = proxy->GetBundleNameByAppId("5765880207854258995", cameraBundleName);
        ASSERT_TRUE(res == ERR_OK);
        res = proxy->GetBundleNameByAppId("1081898888199154560", himovieBundleName);
        ASSERT_TRUE(res == ERR_OK);
        res = proxy->GetBundleNameByAppId("976752519134849856", musicBundleName);
        ASSERT_TRUE(res == ERR_OK);
        res = proxy->GetBundleNameByAppId("1062865240531676032", booksBundleName);
        ASSERT_TRUE(res == ERR_OK);
        std::vector<ApplicationInstance> freezeExemptedApps = {
            { "5765880207853624761", contactsBundleName, 100, 0 }, { "1230215522310701824", browserBundleName, 100, 0 },
            { "1164531384803416384", appgalleryBundleName, 100, 0 }, { "1062865240531676032", booksBundleName, 100, 0 },
            { "5765880207852919475", settingsBundleName, 100, 0 }, { "5765880207853068793", mmsBundleName, 100, 0 },
            { "1207824849184017472", photosBundleName, 100, 0 }, { "5765880207854258995", cameraBundleName, 100, 0 },
            { "1081898888199154560", himovieBundleName, 100, 0 }, { "976752519134849856", musicBundleName, 100, 0 },
            { "1173750081090759360", thememanagerBundleName, 100, 0 }
        };
        ApplicationInstanceHandle::WriteApplicationInstanceVector(data, freezeExemptedApps);

        std::uint32_t funcCode =
            POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::MANAGE_FREEZE_EXEMPTED_APPS);
        ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, policyData, DEFAULT_USER_ID);
        ASSERT_TRUE(ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    }
}

/**
 * @tc.name: TestOnHandlePolicyFailWithConflictData
 * @tc.desc: Test ManageFreezeExemptedAppsPlugin::OnHandlePolicy when data is conflict.
 * @tc.type: FUNC
 */
HWTEST_F(ManageFreezeExemptedAppsPluginTest, TestOnHandlePolicySucceedWithConflictData, TestSize.Level1)
{
    std::string developDeviceParam = system::GetParameter(BOOT_OEM_MODE, USER_MODE);
    if (developDeviceParam == DEVELOP_PARAM) {
        std::string settingsAppIdentifier = "5765880207852919475";
        std::string bundleName;
        auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
        sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
        ASSERT_TRUE(proxy != nullptr);
        ErrCode res = proxy->GetBundleNameByAppId(settingsAppIdentifier, bundleName);
        ASSERT_TRUE(res == ERR_OK);
        std::vector<ApplicationInstance> freezeExemptedApps = {{ settingsAppIdentifier, bundleName, 100, 0 }};
        std::vector<ApplicationInstance> currentData;
        std::vector<ApplicationInstance> mergeData;
        ManageFreezeExemptedAppsPlugin plugin;
        ErrCode ret = plugin.OnSetPolicy(freezeExemptedApps, currentData, mergeData);
        ASSERT_TRUE(ret == ERR_OK);

        ManageFreezeExemptedAppsPlugin freezeExemptedPlugin;
        MessageParcel data;
        MessageParcel reply;
        HandlePolicyData policyData;
        ApplicationInstanceHandle::WriteApplicationInstanceVector(data, freezeExemptedApps);

        std::uint32_t funcCode =
            POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::MANAGE_FREEZE_EXEMPTED_APPS);
        ret = freezeExemptedPlugin.OnHandlePolicy(funcCode, data, reply, policyData, DEFAULT_USER_ID);
        ASSERT_TRUE(ret == ERR_OK);
        mergeData.clear();
        ret = plugin.OnRemovePolicy(freezeExemptedApps, currentData, mergeData);
        ASSERT_TRUE(ret == ERR_OK);
    }
}

/**
 * @tc.name: TestOnHandlePolicyRemoveFailWithNotExistedData
 * @tc.desc: Test ManageFreezeExemptedAppsPlugin::OnHandlePolicy remove when app is not existed.
 * @tc.type: FUNC
 */
HWTEST_F(ManageFreezeExemptedAppsPluginTest, TestOnHandlePolicyRemoveFailWithNotExistedData, TestSize.Level1)
{
    std::string developDeviceParam = system::GetParameter(BOOT_OEM_MODE, USER_MODE);
    if (developDeviceParam == DEVELOP_PARAM) {
        std::string settingsAppIdentifier = "5765880207852919475";
        std::string bundleName;
        auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
        sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
        ASSERT_TRUE(proxy != nullptr);
        ErrCode res = proxy->GetBundleNameByAppId(settingsAppIdentifier, bundleName);
        ASSERT_TRUE(res == ERR_OK);
        std::vector<ApplicationInstance> freezeExemptedApps1 = { { settingsAppIdentifier, bundleName, 100, 0 } };
        std::vector<ApplicationInstance> freezeExemptedApps2 = { { "111", "com.not.existed", 100, 0 } };
        std::vector<ApplicationInstance> currentData;
        std::vector<ApplicationInstance> mergeData;
        ManageFreezeExemptedAppsPlugin plugin;

        MessageParcel data;
        MessageParcel reply;
        ApplicationInstanceHandle::WriteApplicationInstanceVector(data, freezeExemptedApps2);
        HandlePolicyData policyData;
        ManageAppsSerializer::GetInstance()->Serialize(freezeExemptedApps1, policyData.policyData);

        std::uint32_t funcCode =
            POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::MANAGE_FREEZE_EXEMPTED_APPS);
        ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, policyData, DEFAULT_USER_ID);
        ASSERT_TRUE(ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    }
}

/**
 * @tc.name: TestOnGetPolicy
 * @tc.desc: Test ManageFreezeExemptedAppsPlugin::OnGetPolicy.
 * @tc.type: FUNC
 */
HWTEST_F(ManageFreezeExemptedAppsPluginTest, TestOnGetPolicy1, TestSize.Level1)
{
    ManageFreezeExemptedAppsPlugin plugin;
    std::string adminName;
    std::string currentJsonData;
    std::string mergeJsonData;
    plugin.OnAdminRemove(adminName, currentJsonData, mergeJsonData, DEFAULT_USER_ID);

    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    std::vector<ApplicationInstance> freezeExemptedApps;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    ApplicationInstanceHandle::ReadApplicationInstanceVector(reply, freezeExemptedApps);
    ASSERT_TRUE(freezeExemptedApps.empty());
}

/**
 * @tc.name: TestOnGetPolicy
 * @tc.desc: Test ManageFreezeExemptedAppsPlugin::OnGetPolicy.
 * @tc.type: FUNC
 */
HWTEST_F(ManageFreezeExemptedAppsPluginTest, TestOnGetPolicy2, TestSize.Level1)
{
    std::string developDeviceParam = system::GetParameter(BOOT_OEM_MODE, USER_MODE);
    if (developDeviceParam == DEVELOP_PARAM) {
        ManageFreezeExemptedAppsPlugin plugin;
        HandlePolicyData policyData;
        MessageParcel data;
        MessageParcel reply;
        std::string settingsAppIdentifier = "5765880207852919475";
        std::string bundleName;
        auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
        sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
        ASSERT_TRUE(proxy != nullptr);
        ErrCode res = proxy->GetBundleNameByAppId(settingsAppIdentifier, bundleName);
        ASSERT_TRUE(res == ERR_OK);

        std::vector<ApplicationInstance> freezeExemptedApps = { { settingsAppIdentifier, bundleName, 100, 0 } };
        ErrCode ret = plugin.OnGetPolicy(policyData.policyData, data, reply, DEFAULT_USER_ID);
        ASSERT_TRUE(ret == ERR_OK);
        ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
        std::vector<ApplicationInstance> freezeExemptedApps1;
        ApplicationInstanceHandle::ReadApplicationInstanceVector(reply, freezeExemptedApps1);
        ASSERT_TRUE(freezeExemptedApps1.empty());

        std::uint32_t funcCode =
            POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::MANAGE_FREEZE_EXEMPTED_APPS);
        ApplicationInstanceHandle::WriteApplicationInstanceVector(data, freezeExemptedApps);
        ret = plugin.OnHandlePolicy(funcCode, data, reply, policyData, DEFAULT_USER_ID);
        ASSERT_TRUE(ret == ERR_OK);
        ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
        ret = plugin.OnGetPolicy(policyData.policyData, data, reply, DEFAULT_USER_ID);
        ASSERT_TRUE(ret == ERR_OK);
        ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
        std::vector<ApplicationInstance> freezeExemptedApps2;
        ApplicationInstanceHandle::ReadApplicationInstanceVector(reply, freezeExemptedApps2);
        ASSERT_TRUE(freezeExemptedApps2.size() == 1);
    }
}

/**
 * @tc.name: TestOnSetPolicy01
 * @tc.desc: Test ManageFreezeExemptedAppsPlugin::OnSetPolicy.
 * @tc.type: FUNC
 */
HWTEST_F(ManageFreezeExemptedAppsPluginTest, TestOnSetPolicy01, TestSize.Level1)
{
    std::string developDeviceParam = system::GetParameter(BOOT_OEM_MODE, USER_MODE);
    if (developDeviceParam == DEVELOP_PARAM) {
        ManageFreezeExemptedAppsPlugin plugin;
        std::string settingsAppIdentifier = "5765880207852919475";
        std::string bundleName;
        auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
        sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
        ASSERT_TRUE(proxy != nullptr);
        ErrCode res = proxy->GetBundleNameByAppId(settingsAppIdentifier, bundleName);
        ASSERT_TRUE(res == ERR_OK);
        std::vector<ApplicationInstance> freezeExemptedApps = { { settingsAppIdentifier, bundleName, 100, 0 } };
        std::vector<ApplicationInstance> currentData;
        std::vector<ApplicationInstance> mergeData;

        ErrCode ret = plugin.OnSetPolicy(freezeExemptedApps, currentData, mergeData);
        ASSERT_TRUE(ret == ERR_OK);
    }
}

/**
 * @tc.name: TestOnSetPolicy02
 * @tc.desc: Test ManageFreezeExemptedAppsPlugin::OnSetPolicy.
 * @tc.type: FUNC
 */
HWTEST_F(ManageFreezeExemptedAppsPluginTest, TestOnSetPolicy02, TestSize.Level1)
{
    std::string developDeviceParam = system::GetParameter(BOOT_OEM_MODE, USER_MODE);
    if (developDeviceParam == DEVELOP_PARAM) {
        ManageFreezeExemptedAppsPlugin plugin;
        std::string contactsBundleName, browserBundleName, appgalleryBundleName;
        auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
        sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
        ASSERT_TRUE(proxy != nullptr);
        ErrCode res = proxy->GetBundleNameByAppId("5765880207853624761", contactsBundleName);
        ASSERT_TRUE(res == ERR_OK);
        res = proxy->GetBundleNameByAppId("1230215522310701824", browserBundleName);
        ASSERT_TRUE(res == ERR_OK);
        res = proxy->GetBundleNameByAppId("1164531384803416384", appgalleryBundleName);
        ASSERT_TRUE(res == ERR_OK);

        std::vector<ApplicationInstance> freezeExemptedApps = { { "5765880207853624761", contactsBundleName, 100, 0 } };
        std::vector<ApplicationInstance> currentData = { { "1230215522310701824", browserBundleName, 100, 0 } };
        std::vector<ApplicationInstance> mergeData = { { "1164531384803416384", appgalleryBundleName, 100, 0 } };

        ErrCode ret = plugin.OnSetPolicy(freezeExemptedApps, currentData, mergeData);
        ASSERT_TRUE(ret == ERR_OK);
    }
}

/**
 * @tc.name: TestSetOtherModulePolicy
 * @tc.desc: Test ManageFreezeExemptedAppsPlugin::SetOtherModulePolicy.
 * @tc.type: FUNC
 */
HWTEST_F(ManageFreezeExemptedAppsPluginTest, TestSetOtherModulePolicy, TestSize.Level1)
{
    std::string developDeviceParam = system::GetParameter(BOOT_OEM_MODE, USER_MODE);
    if (developDeviceParam == DEVELOP_PARAM) {
        ManageFreezeExemptedAppsPlugin plugin;
        std::string settingsAppIdentifier = "5765880207852919475";
        std::string bundleName;
        auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
        sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
        ASSERT_TRUE(proxy != nullptr);
        ErrCode res = proxy->GetBundleNameByAppId(settingsAppIdentifier, bundleName);
        ASSERT_TRUE(res == ERR_OK);
        std::vector<ApplicationInstance> freezeExemptedApps = { { settingsAppIdentifier, bundleName, 100, 0 } };
        int32_t systemAbilityId = 1901;
        plugin.OnOtherServiceStart(systemAbilityId);
        ErrCode ret = plugin.SetOtherModulePolicy(freezeExemptedApps);
        ASSERT_TRUE(ret == ERR_OK);
    }
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS