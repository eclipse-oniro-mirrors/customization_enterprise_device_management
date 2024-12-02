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
#include "plugin_manager.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(std::make_shared<ManageKeepAliveAppsPlugin>());
const ErrCode ERR_TARGET_BUNDLE_NOT_EXIST = 2097241;
const ErrCode ERR_NO_MAIN_ABILITY = 29360135;
const ErrCode ERR_NO_STATUS_BAR_ABILITY = 29360136;
const ErrCode ERR_NOT_ATTACHED_TO_STATUS_BAR = 29360137;
const ErrCode ERR_CAPABILITY_NOT_SUPPORT = 2097230;

ManageKeepAliveAppsPlugin::ManageKeepAliveAppsPlugin()
{
    policyCode_ = EdmInterfaceCode::MANAGE_KEEP_ALIVE_APPS;
    policyName_ = "manage_keep_alive_apps";
    permissionConfig_.permission = "ohos.permission.ENTERPRISE_MANAGE_APPLICATION";
    permissionConfig_.permissionType = IPlugin::PermissionType::SUPER_DEVICE_ADMIN;
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = true;
}

ErrCode ManageKeepAliveAppsPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    EDMLOGI("ManageKeepAliveAppsPlugin OnHandlePolicy.");
    uint32_t typeCode = FUNC_TO_OPERATE(funcCode);
    FuncOperateType type = FuncCodeUtils::ConvertOperateType(typeCode);
    std::vector<std::string> keepAliveApps;
    data.ReadStringVector(&keepAliveApps);
    if (keepAliveApps.size() > EdmConstants::KEEP_ALIVE_APPS_MAX_SIZE) {
        EDMLOGE("ManageKeepAliveAppsPlugin OnHandlePolicy data is too large.");
        reply.WriteInt32(EdmReturnErrCode::PARAM_ERROR);
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::vector<std::string> currentData;
    ArrayStringSerializer::GetInstance()->Deserialize(policyData.policyData, currentData);
    ErrCode res = ERR_INVALID_VALUE;
    std::string errMessage;
    if (type == FuncOperateType::SET) {
        std::vector<std::string> allData =
            ArrayStringSerializer::GetInstance()->SetUnionPolicyData(keepAliveApps, currentData);
        if (allData.size() > EdmConstants::KEEP_ALIVE_APPS_MAX_SIZE) {
            EDMLOGE("ManageKeepAliveAppsPlugin OnHandlePolicy data is too large.");
            reply.WriteInt32(EdmReturnErrCode::PARAM_ERROR);
            return EdmReturnErrCode::PARAM_ERROR;
        }
        res = AddKeepAliveApps(keepAliveApps, userId);
        if (res == ERR_OK) {
            reply.WriteInt32(res);
            UpdatePolicyData(allData, currentData, policyData);
            return ERR_OK;
        }
        ParseErrCode(res, errMessage, reply);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    } else if (type == FuncOperateType::REMOVE) {
        std::vector<std::string> allData =
            ArrayStringSerializer::GetInstance()->SetDifferencePolicyData(keepAliveApps, currentData);
        res = RemoveKeepAliveApps(keepAliveApps, userId);
        if (res == ERR_OK) {
            reply.WriteInt32(res);
            UpdatePolicyData(allData, currentData, policyData);
            return ERR_OK;
        }
        ParseErrCode(res, errMessage, reply);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return EdmReturnErrCode::PARAM_ERROR;
}

ErrCode ManageKeepAliveAppsPlugin::AddKeepAliveApps(std::vector<std::string> &keepAliveApps, int32_t userId)
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

    int32_t res = EdmReturnErrCode::PARAM_ERROR;
    for (const auto &bundleName : keepAliveApps) {
        auto it = std::find(disallowedRunningBundles.begin(), disallowedRunningBundles.end(), bundleName);
        if (it != disallowedRunningBundles.end()) {
            EDMLOGE("ManageKeepAliveAppsPlugin AddKeepAliveApps bundleName: %{public}s is disallowed running.",
                bundleName.c_str());
            return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
        } else {
            res = abilityManager->SetApplicationKeepAliveByEDM(bundleName, userId, true);
            if (res != ERR_OK) {
                EDMLOGE("AddKeepAliveApps SetApplicationKeepAliveByEDM err res: %{public}d bundleName: %{public}s ",
                    res, bundleName.c_str());
                return res;
            }
        }
    }
    return res;
}
ErrCode ManageKeepAliveAppsPlugin::RemoveKeepAliveApps(std::vector<std::string> &keepAliveApps, int32_t userId)
{
    EDMLOGI("ManageKeepAliveAppsPlugin RemoveKeepAliveApps");
    auto abilityManager = GetAbilityManager();
    if (!abilityManager) {
        EDMLOGE("ManageKeepAliveAppsPlugin RemoveKeepAliveApps get abilityManager failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }

    int32_t res = EdmReturnErrCode::PARAM_ERROR;
    for (const auto &bundleName : keepAliveApps) {
        res = abilityManager->SetApplicationKeepAliveByEDM(bundleName, userId, false);
        if (res != ERR_OK) {
            EDMLOGE("RemoveKeepAliveApps SetApplicationKeepAliveByEDM err res: %{public}d bundleName: %{public}s ", res,
                bundleName.c_str());
            return res;
        }
    }
    return res;
}

ErrCode ManageKeepAliveAppsPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("ManageKeepAliveAppsPlugin OnGetPolicy.");

    auto abilityManager = GetAbilityManager();
    if (!abilityManager) {
        EDMLOGE("ManageKeepAliveAppsPlugin OnGetPolicy get abilityManager failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::vector<OHOS::AbilityRuntime::KeepAliveInfo> infoList;
    int32_t appType = static_cast<int32_t>(OHOS::AbilityRuntime::KeepAliveAppType::UNSPECIFIED);
    int32_t res = abilityManager->QueryKeepAliveApplicationsByEDM(appType, userId, infoList);
    if (res != ERR_OK) {
        EDMLOGE("ManageKeepAliveAppsPlugin OnGetPolicy QueryKeepAliveApplicationByEDM failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }

    std::vector<std::string> keepAliveAppsInfo;
    std::for_each(infoList.begin(), infoList.end(), [&](const OHOS::AbilityRuntime::KeepAliveInfo &Info) {
        if (Info.setter == OHOS::AbilityRuntime::KeepAliveSetter::SYSTEM) {
            keepAliveAppsInfo.push_back(Info.bundleName);
        }
    });
    reply.WriteInt32(ERR_OK);
    reply.WriteStringVector(keepAliveAppsInfo);
    return ERR_OK;
}

void ManageKeepAliveAppsPlugin::OnAdminRemoveDone(const std::string &adminName, const std::string &currentJsonData,
    int32_t userId)
{
    EDMLOGI("ManageKeepAliveAppsPlugin OnAdminRemoveDone");
    
    auto abilityManager = GetAbilityManager();
    if (!abilityManager) {
        EDMLOGE("ManageKeepAliveAppsPlugin OnAdminRemoveDone get abilityManager failed.");
        return;
    }

    std::vector<OHOS::AbilityRuntime::KeepAliveInfo> infoList;
    int32_t appType = static_cast<int32_t>(OHOS::AbilityRuntime::KeepAliveAppType::UNSPECIFIED);
    int32_t res = abilityManager->QueryKeepAliveApplicationsByEDM(appType, userId, infoList);
    if (res != ERR_OK) {
        EDMLOGE("ManageKeepAliveAppsPlugin OnAdminRemoveDone QueryKeepAliveApplicationByEDM failed.");
        return;
    }
    std::vector<std::string> keepAliveAppsInfo;
    std::for_each(infoList.begin(), infoList.end(), [&](const OHOS::AbilityRuntime::KeepAliveInfo &Info) {
        if (Info.setter == OHOS::AbilityRuntime::KeepAliveSetter::SYSTEM) {
            keepAliveAppsInfo.push_back(Info.bundleName);
        }
    });
    
    for (const auto &bundleName : keepAliveAppsInfo) {
        int32_t res = abilityManager->SetApplicationKeepAliveByEDM(bundleName, userId, false);
        if (res != ERR_OK) {
            EDMLOGE("ManageKeepAliveAppsPlugin OnAdminRemoveDone SetApplicationKeepAliveByEDM"
                "err res: %{public}d bundleName: %{public}s ", res, bundleName.c_str());
            return;
        }
    }
}

void ManageKeepAliveAppsPlugin::UpdatePolicyData(std::vector<std::string> &allData,
    std::vector<std::string> &currentData, HandlePolicyData &policyData)
{
    policyData.isChanged = allData != currentData;
    if (policyData.isChanged) {
        ArrayStringSerializer::GetInstance()->Serialize(allData, policyData.policyData);
    }
}

void ManageKeepAliveAppsPlugin::ParseErrCode(ErrCode &res, std::string &errMessage, MessageParcel &reply)
{
    switch (res) {
        case ERR_TARGET_BUNDLE_NOT_EXIST:
            res = EdmReturnErrCode::ADD_KEEP_ALIVE_APP_FAILED;
            errMessage = "Application is not installed";
            break;
        case ERR_NO_MAIN_ABILITY:
            res = EdmReturnErrCode::ADD_KEEP_ALIVE_APP_FAILED;
            errMessage = "Application does not have mainability";
            break;
        case ERR_NO_STATUS_BAR_ABILITY:
            res = EdmReturnErrCode::ADD_KEEP_ALIVE_APP_FAILED;
            errMessage = "Application does not have status bar ability";
            break;
        case ERR_NOT_ATTACHED_TO_STATUS_BAR:
            res = EdmReturnErrCode::ADD_KEEP_ALIVE_APP_FAILED;
            errMessage = "Application does not attach to status bar";
            break;
        case ERR_CAPABILITY_NOT_SUPPORT:
            res = EdmReturnErrCode::INTERFACE_UNSUPPORTED;
        default:
            break;
    }
    reply.WriteInt32(res);
    reply.WriteString(errMessage);
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