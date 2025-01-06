/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "manage_auto_start_apps_plugin.h"

#include <bundle_info.h>
#include <bundle_mgr_interface.h>
#include <system_ability_definition.h>

#include "ability_auto_startup_client.h"
#include "array_string_serializer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_sys_manager.h"
#include "element_name.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(ManageAutoStartAppsPlugin::GetPlugin());
const std::string SEPARATOR = "/";

void ManageAutoStartAppsPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<ManageAutoStartAppsPlugin, std::vector<std::string>>> ptr)
{
    EDMLOGI("ManageAutoStartAppsPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::MANAGE_AUTO_START_APPS, "manage_auto_start_apps",
        "ohos.permission.ENTERPRISE_MANAGE_APPLICATION", IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(ArrayStringSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&ManageAutoStartAppsPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnHandlePolicyListener(&ManageAutoStartAppsPlugin::OnRemovePolicy, FuncOperateType::REMOVE);
    ptr->SetOnAdminRemoveDoneListener(&ManageAutoStartAppsPlugin::OnAdminRemoveDone);
}

ErrCode ManageAutoStartAppsPlugin::OnSetPolicy(std::vector<std::string> &data, std::vector<std::string> &currentData,
    int32_t userId)
{
    EDMLOGI("ManageAutoStartAppsPlugin OnSetPolicy userId : %{public}d", userId);
    if (data.empty()) {
        EDMLOGW("ManageAutoStartAppsPlugin OnSetPolicy data is empty.");
        return ERR_OK;
    }

    if (data.size() > EdmConstants::AUTO_START_APPS_MAX_SIZE) {
        EDMLOGE("ManageAutoStartAppsPlugin OnSetPolicy data is too large.");
        return EdmReturnErrCode::PARAM_ERROR;
    }

    std::vector<std::string> allData =
        ArrayStringSerializer::GetInstance()->SetUnionPolicyData(data, currentData);
    if (allData.size() > EdmConstants::AUTO_START_APPS_MAX_SIZE) {
        EDMLOGE("ManageAutoStartAppsPlugin OnSetPolicy data is too large.");
        return EdmReturnErrCode::PARAM_ERROR;
    }

    auto autoStartupClient = AAFwk::AbilityAutoStartupClient::GetInstance();
    if (!autoStartupClient) {
        EDMLOGE("ManageAutoStartAppsPlugin OnSetPolicy GetAppControlProxy failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    bool flag = false;
    std::vector<std::string> mergeData;
    for (const auto &str : data) {
        std::string bundleName;
        std::string abilityName;
        if (!ParseAutoStartAppWant(str, bundleName, abilityName)) {
            continue;
        }
        if (!CheckBundleAndAbilityExited(bundleName, abilityName)) {
            EDMLOGW("CheckBundleAndAbilityExited failed bundleName: %{public}s, abilityName: %{public}s",
                bundleName.c_str(), abilityName.c_str());
            continue;
        }
        OHOS::AbilityRuntime::AutoStartupInfo autoStartupInfo;
        autoStartupInfo.bundleName = bundleName;
        autoStartupInfo.abilityName = abilityName;
        ErrCode res = autoStartupClient->SetApplicationAutoStartupByEDM(autoStartupInfo, true);
        if (res != ERR_OK) {
            EDMLOGW("OnSetPolicy SetApplicationAutoStartupByEDM err res: %{public}d bundleName: %{public}s "
                "abilityName: %{public}s", res, bundleName.c_str(), abilityName.c_str());
            break;
        }
        flag = true;
        mergeData.push_back(str);
    }
    currentData = ArrayStringSerializer::GetInstance()->SetUnionPolicyData(mergeData, currentData);
    return flag ? ERR_OK : EdmReturnErrCode::PARAM_ERROR;
}

ErrCode ManageAutoStartAppsPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("ManageAutoStartAppsPlugin OnGetPolicy policyData : %{public}s, userId : %{public}d", policyData.c_str(),
        userId);
    auto autoStartupClient = AAFwk::AbilityAutoStartupClient::GetInstance();
    if (!autoStartupClient) {
        EDMLOGE("ManageAutoStartAppsPlugin OnGetPolicy GetAppControlProxy failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::vector<OHOS::AbilityRuntime::AutoStartupInfo> infoList;
    ErrCode res = autoStartupClient->QueryAllAutoStartupApplications(infoList);
    if (res != ERR_OK) {
        EDMLOGE("ManageAutoStartAppsPlugin OnGetPolicy Faild %{public}d:", res);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }

    std::vector<std::string> autoStartAppsInfo;
    std::for_each(infoList.begin(), infoList.end(), [&](const OHOS::AbilityRuntime::AutoStartupInfo &Info) {
        std::string appInfo = Info.bundleName + SEPARATOR + Info.abilityName;
        autoStartAppsInfo.push_back(appInfo);
    });
    reply.WriteInt32(ERR_OK);
    reply.WriteStringVector(autoStartAppsInfo);
    return ERR_OK;
}

ErrCode ManageAutoStartAppsPlugin::OnRemovePolicy(std::vector<std::string> &data, std::vector<std::string> &currentData,
    int32_t userId)
{
    EDMLOGI("ManageAutoStartAppsPlugin OnRemovePolicy userId : %{public}d.", userId);
    if (data.empty()) {
        EDMLOGW("ManageAutoStartAppsPlugin OnRemovePolicy data is empty.");
        return ERR_OK;
    }

    if (data.size() > EdmConstants::AUTO_START_APPS_MAX_SIZE) {
        EDMLOGE("ManageAutoStartAppsPlugin OnRemovePolicy data is too large.");
        return EdmReturnErrCode::PARAM_ERROR;
    }

    auto autoStartupClient = AAFwk::AbilityAutoStartupClient::GetInstance();
    if (!autoStartupClient) {
        EDMLOGE("ManageAutoStartAppsPlugin OnRemovePolicy GetAppControlProxy failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    bool flag = false;
    std::vector<std::string> mergeData;
    for (const auto &str : data) {
        std::string bundleName;
        std::string abilityName;
        if (!ParseAutoStartAppWant(str, bundleName, abilityName)) {
            continue;
        }
        if (!CheckBundleAndAbilityExited(bundleName, abilityName)) {
            if (std::find(currentData.begin(), currentData.end(), str) != currentData.end()) {
                flag = true;
                mergeData.push_back(str);
            }
            EDMLOGW("CheckBundleAndAbilityExited failed bundleName: %{public}s, abilityName: %{public}s",
                bundleName.c_str(), abilityName.c_str());
            continue;
        }
        OHOS::AbilityRuntime::AutoStartupInfo autoStartupInfo;
        autoStartupInfo.bundleName = bundleName;
        autoStartupInfo.abilityName = abilityName;

        ErrCode res = autoStartupClient->CancelApplicationAutoStartupByEDM(autoStartupInfo, true);
        if (res != ERR_OK) {
            EDMLOGW("OnRemovePolicy CancelApplicationAutoStartupByEDM err res: %{public}d bundleName: %{public}s "
                "abilityName: %{public}s", res, bundleName.c_str(), abilityName.c_str());
            break;
        }
        mergeData.push_back(str);
        flag = true;
    }
    currentData = ArrayStringSerializer::GetInstance()->SetDifferencePolicyData(mergeData, currentData);
    return flag ? ERR_OK : EdmReturnErrCode::PARAM_ERROR;
}

void ManageAutoStartAppsPlugin::OnAdminRemoveDone(const std::string &adminName, std::vector<std::string> &data,
    int32_t userId)
{
    EDMLOGI("ManageAutoStartAppsPlugin OnAdminRemoveDone adminName : %{public}s userId : %{public}d", adminName.c_str(),
        userId);

    auto autoStartupClient = AAFwk::AbilityAutoStartupClient::GetInstance();
    if (!autoStartupClient) {
        EDMLOGE("ManageAutoStartAppsPlugin OnSetPolicy GetAppControlProxy failed.");
        return;
    }

    std::for_each(data.begin(), data.end(), [&](const std::string &str) {
        OHOS::AbilityRuntime::AutoStartupInfo autoStartupInfo;
        std::string bundleName;
        std::string abilityName;
        if (!ParseAutoStartAppWant(str, bundleName, abilityName)) {
            return;
        }
        autoStartupInfo.bundleName = bundleName;
        autoStartupInfo.abilityName = abilityName;
        ErrCode res = autoStartupClient->CancelApplicationAutoStartupByEDM(autoStartupInfo, true);
        EDMLOGI("ManageAutoStartAppsPlugin OnAdminRemoveDone result %{public}d:", res);
    });
}

bool ManageAutoStartAppsPlugin::ParseAutoStartAppWant(std::string appWant, std::string &bundleName,
    std::string &abilityName)
{
    size_t index = appWant.find(SEPARATOR);
    if (index != appWant.npos) {
        bundleName = appWant.substr(0, index);
        abilityName = appWant.substr(index + 1);
    } else {
        EDMLOGE("ManageAutoStartAppsPlugin ParseAutoStartAppWant parse auto start app want failed");
        return false;
    }
    return true;
}

bool ManageAutoStartAppsPlugin::CheckBundleAndAbilityExited(const std::string &bundleName,
    const std::string &abilityName)
{
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (!proxy) {
        EDMLOGE("EnterpriseDeviceMgrAbility::GetAllPermissionsByAdmin GetBundleMgr failed.");
        return false;
    }

    std::vector<AppExecFwk::AbilityInfo> abilityInfos;
    AppExecFwk::ElementName element;
    element.SetBundleName(bundleName);
    element.SetAbilityName(abilityName);
    OHOS::AppExecFwk::IBundleMgr::Want want;
    want.SetElement(element);
    std::vector<AppExecFwk::ExtensionAbilityInfo> extensionAbilityInfo;
    return proxy->QueryAbilityInfos(want, AppExecFwk::AbilityInfoFlag::GET_ABILITY_INFO_DEFAULT,
        DEFAULT_USER_ID, abilityInfos) ||
        proxy->QueryExtensionAbilityInfos(want, AppExecFwk::ExtensionAbilityType::SERVICE,
            AppExecFwk::ExtensionAbilityInfoFlag::GET_EXTENSION_INFO_DEFAULT, DEFAULT_USER_ID,
            extensionAbilityInfo);
}
} // namespace EDM
} // namespace OHOS
