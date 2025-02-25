/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "manage_keep_alive_apps_plugin.h"

#include <algorithm>

#include "app_control/app_control_proxy.h"
#include "array_string_serializer.h"
#include "bundle_info.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_sys_manager.h"
#include "element_name.h"
#include "func_code_utils.h"
#include "iplugin_manager.h"
#include "ipolicy_manager.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<ManageKeepAliveAppsPlugin>());
const ErrCode ERR_TARGET_BUNDLE_NOT_EXIST = 2097241;
const ErrCode ERR_NO_MAIN_ABILITY = 29360135;
const ErrCode ERR_NO_STATUS_BAR_ABILITY = 29360136;
const ErrCode ERR_NOT_ATTACHED_TO_STATUS_BAR = 29360137;
const ErrCode ERR_CAPABILITY_NOT_SUPPORT = 2097230;

ManageKeepAliveAppsPlugin::ManageKeepAliveAppsPlugin()
{
    policyCode_ = EdmInterfaceCode::MANAGE_KEEP_ALIVE_APPS;
    policyName_ = "manage_keep_alive_apps";
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION);
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = true;
    maxListSize_ = EdmConstants::KEEP_ALIVE_APPS_MAX_SIZE;
}

ErrCode ManageKeepAliveAppsPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    EDMLOGI("ManageKeepAliveAppsPlugin OnHandlePolicy.");
    uint32_t typeCode = FUNC_TO_OPERATE(funcCode);
    FuncOperateType type = FuncCodeUtils::ConvertOperateType(typeCode);
    std::vector<std::string> keepAliveApps;
    data.ReadStringVector(&keepAliveApps);
    std::vector<std::string> currentData;
    ArrayStringSerializer::GetInstance()->Deserialize(policyData.policyData, currentData);
    std::vector<std::string> mergeData;
    ArrayStringSerializer::GetInstance()->Deserialize(policyData.mergePolicyData, mergeData);
    ErrCode res = EdmReturnErrCode::PARAM_ERROR;
    std::string errMessage;
    if (type == FuncOperateType::SET) {
        res = OnBasicSetPolicy(keepAliveApps, currentData, mergeData, userId);
        GetErrorMessage(res, errMessage);
    } else if (type == FuncOperateType::REMOVE) {
        res = OnBasicRemovePolicy(keepAliveApps, currentData, mergeData, userId);
        GetErrorMessage(res, errMessage);
    }
    if (res != ERR_OK) {
        reply.WriteInt32(res);
        reply.WriteString(errMessage);
        return res;
    }
    reply.WriteInt32(ERR_OK);
    std::string afterHandle;
    std::string afterMerge;
    ArrayStringSerializer::GetInstance()->Serialize(currentData, afterHandle);
    ArrayStringSerializer::GetInstance()->Serialize(mergeData, afterMerge);
    policyData.isChanged = (policyData.policyData != afterHandle);
    policyData.policyData = afterHandle;
    policyData.mergePolicyData = afterMerge;
    return ERR_OK;
}

ErrCode ManageKeepAliveAppsPlugin::SetOtherModulePolicy(const std::vector<std::string> &keepAliveApps,
    int32_t userId, std::vector<std::string> &failedData)
{
    EDMLOGI("ManageKeepAliveAppsPlugin AddKeepAliveApps");
    auto abilityManager = GetAbilityManager();
    if (!abilityManager) {
        EDMLOGE("ManageKeepAliveAppsPlugin AddKeepAliveApps get abilityManager failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }

    auto appControlProxy = GetAppControlProxy();
    if (!appControlProxy) {
        EDMLOGE("ManageKeepAliveAppsPlugin AddKeepAliveApps appControlProxy failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }

    std::vector<std::string> disallowedRunningBundles;
    ErrCode ret = appControlProxy->GetAppRunningControlRule(userId, disallowedRunningBundles);
    if (ret != ERR_OK) {
        EDMLOGE("ManageKeepAliveAppsPlugin AddKeepAliveApps GetAppRunningControlRule failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }

    bool flag = false;
    int32_t res = ERR_OK;
    for (const auto &bundleName : keepAliveApps) {
        auto it = std::find(disallowedRunningBundles.begin(), disallowedRunningBundles.end(), bundleName);
        if (it != disallowedRunningBundles.end()) {
            EDMLOGE("ManageKeepAliveAppsPlugin AddKeepAliveApps bundleName: %{public}s is disallowed running.",
                bundleName.c_str());
            return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
        }
        res = abilityManager->SetApplicationKeepAliveByEDM(bundleName, userId, true);
        if (res != ERR_OK) {
            EDMLOGE("AddKeepAliveApps SetApplicationKeepAliveByEDM err res: %{public}d bundleName: %{public}s ",
                res, bundleName.c_str());
            failedData.push_back(bundleName);
            continue;
        }
        flag = true;
    }
    ParseErrCode(res);
    return flag ? ERR_OK : res;
}
ErrCode ManageKeepAliveAppsPlugin::RemoveOtherModulePolicy(const std::vector<std::string> &keepAliveApps,
    int32_t userId, std::vector<std::string> &failedData)
{
    EDMLOGI("ManageKeepAliveAppsPlugin RemoveKeepAliveApps");
    auto abilityManager = GetAbilityManager();
    if (!abilityManager) {
        EDMLOGE("ManageKeepAliveAppsPlugin RemoveKeepAliveApps get abilityManager failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    bool flag = false;
    int32_t res = ERR_OK;
    for (const auto &bundleName : keepAliveApps) {
        res = abilityManager->SetApplicationKeepAliveByEDM(bundleName, userId, false);
        if (res != ERR_OK) {
            EDMLOGE("RemoveKeepAliveApps SetApplicationKeepAliveByEDM err res: %{public}d bundleName: %{public}s ", res,
                bundleName.c_str());
            failedData.push_back(bundleName);
            continue;
        }
        flag = true;
    }
    ParseErrCode(res);
    return flag ? ERR_OK : res;
}

ErrCode ManageKeepAliveAppsPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("ManageKeepAliveAppsPlugin OnGetPolicy.");
    return BasicGetPolicy(policyData, data, reply, userId);
}

ErrCode ManageKeepAliveAppsPlugin::OnAdminRemove(const std::string &adminName, const std::string &currentJsonData,
    const std::string &mergeJsonData, int32_t userId)
{
    EDMLOGI("ManageKeepAliveAppsPlugin OnAdminRemoveDone");
    
    std::vector<std::string> currentData;
    ArrayStringSerializer::GetInstance()->Deserialize(currentJsonData, currentData);
    std::vector<std::string> mergeData;
    ArrayStringSerializer::GetInstance()->Deserialize(mergeJsonData, mergeData);
    return OnBasicAdminRemove(adminName, currentData, mergeData, userId);
}

ErrCode ManageKeepAliveAppsPlugin::GetOthersMergePolicyData(const std::string &adminName,
    std::string &othersMergePolicyData)
{
    std::unordered_map<std::string, std::string> adminValues;
    IPolicyManager::GetInstance()->GetAdminByPolicyName(GetPolicyName(), adminValues);
    EDMLOGI("IPluginTemplate::GetOthersMergePolicyData %{public}s value size %{public}d.", GetPolicyName().c_str(),
        (uint32_t)adminValues.size());
    if (adminValues.empty()) {
        return ERR_OK;
    }
    auto entry = adminValues.find(adminName);
    if (entry != adminValues.end()) {
        adminValues.erase(entry);
    }
    if (adminValues.empty()) {
        return ERR_OK;
    }
    auto serializer = ArrayStringSerializer::GetInstance();
    std::vector<std::vector<std::string>> data;
    for (const auto &item : adminValues) {
        std::vector<std::string> dataItem;
        if (!item.second.empty()) {
            if (!serializer->Deserialize(item.second, dataItem)) {
                return ERR_EDM_OPERATE_JSON;
            }
            data.push_back(dataItem);
        }
    }
    std::vector<std::string> result;
    if (!serializer->MergePolicy(data, result)) {
        return ERR_EDM_OPERATE_JSON;
    }
    if (!serializer->Serialize(result, othersMergePolicyData)) {
        return ERR_EDM_OPERATE_JSON;
    }
    return ERR_OK;
}

void ManageKeepAliveAppsPlugin::ParseErrCode(ErrCode &res)
{
    if (res == ERR_CAPABILITY_NOT_SUPPORT) {
        res = EdmReturnErrCode::INTERFACE_UNSUPPORTED;
        return;
    }
    if (res != ERR_TARGET_BUNDLE_NOT_EXIST && res != ERR_NO_MAIN_ABILITY && res != ERR_NO_STATUS_BAR_ABILITY &&
        res != ERR_NOT_ATTACHED_TO_STATUS_BAR) {
        res = EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
}

void ManageKeepAliveAppsPlugin::GetErrorMessage(ErrCode &errCode, std::string &errMessage)
{
    switch (errCode) {
        case ERR_TARGET_BUNDLE_NOT_EXIST:
            errCode = EdmReturnErrCode::ADD_KEEP_ALIVE_APP_FAILED;
            errMessage = "Application is not installed.";
            break;
        case ERR_NO_MAIN_ABILITY:
            errCode = EdmReturnErrCode::ADD_KEEP_ALIVE_APP_FAILED;
            errMessage = "Application does not have mainability.";
            break;
        case ERR_NO_STATUS_BAR_ABILITY:
            errCode = EdmReturnErrCode::ADD_KEEP_ALIVE_APP_FAILED;
            errMessage = "Application does not have status bar ability.";
            break;
        case ERR_NOT_ATTACHED_TO_STATUS_BAR:
            errCode = EdmReturnErrCode::ADD_KEEP_ALIVE_APP_FAILED;
            errMessage = "Application does not attach to status bar.";
            break;
        default:
            break;
    }
}

sptr<AAFwk::IAbilityManager> ManageKeepAliveAppsPlugin::GetAbilityManager()
{
    auto abilityObject = EdmSysManager::GetRemoteObjectOfSystemAbility(OHOS::ABILITY_MGR_SERVICE_ID);
    return iface_cast<AAFwk::IAbilityManager>(abilityObject);
}

sptr<AppExecFwk::IAppControlMgr> ManageKeepAliveAppsPlugin::GetAppControlProxy()
{
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (!proxy) {
        EDMLOGE("ManageKeepAliveAppsPlugin GetAppControlProxy failed.");
        return nullptr;
    }
    return proxy->GetAppControlProxy();
}
} // namespace EDM
} // namespace OHOS