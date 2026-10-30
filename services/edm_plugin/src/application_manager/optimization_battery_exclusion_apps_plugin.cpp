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

#include "optimization_battery_exclusion_apps_plugin.h"

#include <algorithm>

#include "array_string_serializer.h"
#include "bundle_mgr_interface.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_event_data.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "edm_sys_manager.h"
#include "external_manager_factory.h"
#include "func_code_utils.h"
#include "iedm_bundle_manager.h"
#include "iplugin_event_subscribe_manager.h"
#include "iplugin_manager.h"
#include "managed_event.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT =
    IPluginManager::GetInstance()->AddPlugin(std::make_shared<OptimizationBatteryExclusionAppsPlugin>());

OptimizationBatteryExclusionAppsPlugin::OptimizationBatteryExclusionAppsPlugin()
{
    policyCode_ = EdmInterfaceCode::OPTIMIZATION_BATTERY_EXCLUSION_APPS;
    policyName_ = PolicyName::POLICY_OPTIMIZATION_BATTERY_EXCLUSION_APPS;
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION);
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    maxListSize_ = EdmConstants::OPTIMIZATION_BATTERY_EXCLUSION_APPS_MAX_SIZE;
    overMaxReturnErrCode_ = EdmReturnErrCode::POLICY_LIST_OVER_SIZE;
    needSave_ = true;
}

ErrCode OptimizationBatteryExclusionAppsPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data,
    MessageParcel &reply, HandlePolicyData &policyData, int32_t userId)
{
    std::vector<std::string> inputData;
    if (!ArrayStringSerializer::GetInstance()->GetPolicy(data, inputData)) {
        EDMLOGE("OnHandlePolicy: deserialize input data failed");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::vector<std::string> currentData;
    std::vector<std::string> mergeData;
    auto serializer = ArrayStringSerializer::GetInstance();
    serializer->Deserialize(policyData.policyData, currentData);
    serializer->Deserialize(policyData.mergePolicyData, mergeData);

    FuncOperateType operateType = FuncCodeUtils::GetOperateType(funcCode);
    ErrCode ret;
    if (operateType == FuncOperateType::SET) {
        ret = OnBasicSetPolicy(inputData, currentData, mergeData, userId);
    } else if (operateType == FuncOperateType::REMOVE) {
        ret = OnBasicRemovePolicy(inputData, currentData, mergeData, userId);
    } else {
        return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
    }
    if (ret == ERR_OK) {
        serializer->Serialize(currentData, policyData.policyData);
        serializer->Serialize(mergeData, policyData.mergePolicyData);
        policyData.isChanged = true;
    }
    return ret;
}

ErrCode OptimizationBatteryExclusionAppsPlugin::SetOtherModulePolicy(const std::vector<std::string> &data,
    int32_t userId, std::vector<std::string> &failedData)
{
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    auto iBundleMgr = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (iBundleMgr == nullptr) {
        EDMLOGE("SetOtherModulePolicy: cannot get IBundleMgr");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    auto bundleMgr = std::make_shared<ExternalManagerFactory>()->CreateBundleManager();
    for (const auto &appIdentifier : data) {
        std::string bundleName;
        int32_t ret = iBundleMgr->GetBundleNameByAppId(appIdentifier, bundleName);
        if (FAILED(ret)) {
            EDMLOGE("SetOtherModulePolicy: GetBundleNameByAppId failed for %{public}s, ret=%{public}d",
                appIdentifier.c_str(), ret);
            return EdmReturnErrCode::DOCK_APP_NOT_INSTALLED;
        }
        if (!bundleMgr->IsBundleInstalled(bundleName, userId)) {
            EDMLOGE("SetOtherModulePolicy: %{public}s is not installed", bundleName.c_str());
            return EdmReturnErrCode::DOCK_APP_NOT_INSTALLED;
        }
    }
    return ERR_OK;
}

bool OptimizationBatteryExclusionAppsPlugin::SubscribeEvent()
{
    auto *manager = IPluginEventSubscribeManager::GetInstance();
    if (manager == nullptr) {
        EDMLOGE("OptimizationBatteryExclusionAppsPlugin SubscribeEvent manager is nullptr");
        return false;
    }
    return manager->SubscribeEvent(PolicyName::POLICY_OPTIMIZATION_BATTERY_EXCLUSION_APPS,
        static_cast<uint32_t>(ManagedEvent::BUNDLE_REMOVED),
        EdmInterfaceCode::OPTIMIZATION_BATTERY_EXCLUSION_APPS, true, true);
}

bool OptimizationBatteryExclusionAppsPlugin::UnsubscribeEvent()
{
    auto *manager = IPluginEventSubscribeManager::GetInstance();
    if (manager == nullptr) {
        EDMLOGE("OptimizationBatteryExclusionAppsPlugin UnsubscribeEvent manager is nullptr");
        return false;
    }
    manager->UnsubscribeEvent(PolicyName::POLICY_OPTIMIZATION_BATTERY_EXCLUSION_APPS,
        static_cast<uint32_t>(ManagedEvent::BUNDLE_REMOVED));
    return true;
}

void OptimizationBatteryExclusionAppsPlugin::OnPluginEvent(const std::string &adminName,
    HandlePolicyData &policyData, const EdmEventData &data, int32_t userId)
{
    auto want = data.commonEventData.GetWant();
    std::string bundleName = want.GetElement().GetBundleName();

    auto serializer = ArrayStringSerializer::GetInstance();
    std::vector<std::string> apps;
    serializer->Deserialize(policyData.policyData, apps);
    auto iter = std::find(apps.begin(), apps.end(), bundleName);
    if (iter == apps.end()) {
        return;
    }
    apps.erase(iter);
    std::vector<std::string> mergeApps;
    serializer->Deserialize(policyData.mergePolicyData, mergeApps);
    auto mergeIter = std::find(mergeApps.begin(), mergeApps.end(), bundleName);
    if (mergeIter != mergeApps.end()) {
        mergeApps.erase(mergeIter);
    }
    serializer->Serialize(apps, policyData.policyData);
    serializer->Serialize(mergeApps, policyData.mergePolicyData);
    EDMLOGI("OnPluginEvent: removed %{public}s from optimization battery exclusion list",
        bundleName.c_str());
}
} // namespace EDM
} // namespace OHOS
