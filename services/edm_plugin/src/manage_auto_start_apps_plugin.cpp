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
    ptr->SetOnHandlePolicyListener(&ManageAutoStartAppsPlugin::OnBasicSetPolicy, FuncOperateType::SET);
    ptr->SetOnHandlePolicyListener(&ManageAutoStartAppsPlugin::OnBasicRemovePolicy, FuncOperateType::REMOVE);
    ptr->SetOnAdminRemoveListener(&ManageAutoStartAppsPlugin::OnBasicAdminRemove);
    maxListSize_ = EdmConstants::AUTO_START_APPS_MAX_SIZE;
}

ErrCode ManageAutoStartAppsPlugin::SetOtherModulePolicy(const std::vector<std::string> &data,
    int32_t userId, std::vector<std::string> &failedData)
{
    return SetOrRemoveOtherModulePolicy(data, true, failedData);
}

ErrCode ManageAutoStartAppsPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("ManageAutoStartAppsPlugin OnGetPolicy policyData : %{public}s, userId : %{public}d", policyData.c_str(),
        userId);
    return BasicGetPolicy(policyData, data, reply, userId);
}

ErrCode ManageAutoStartAppsPlugin::RemoveOtherModulePolicy(const std::vector<std::string> &data, int32_t userId,
    std::vector<std::string> &failedData)
{
    return SetOrRemoveOtherModulePolicy(data, false, failedData);
}

ErrCode ManageAutoStartAppsPlugin::SetOrRemoveOtherModulePolicy(const std::vector<std::string> &data, bool isSet,
    std::vector<std::string> &failedData)
{
    EDMLOGI("ManageAutoStartAppsPlugin SetOrRemoveOtherModulePolicy: %{public}d.", isSet);
    auto autoStartupClient = AAFwk::AbilityAutoStartupClient::GetInstance();
    if (!autoStartupClient) {
        EDMLOGE("ManageAutoStartAppsPlugin SetOrRemoveOtherModulePolicy GetAppControlProxy failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    bool flag = false;
    for (const auto &str : data) {
        OHOS::AbilityRuntime::AutoStartupInfo autoStartupInfo;
        if (!ParseAutoStartAppWant(str, autoStartupInfo.bundleName, autoStartupInfo.abilityName) ||
            !CheckBundleAndAbilityExited(autoStartupInfo.bundleName, autoStartupInfo.abilityName)) {
            EDMLOGW("CheckBundleAndAbilityExited failed bundleName: %{public}s, abilityName: %{public}s",
                autoStartupInfo.bundleName.c_str(), autoStartupInfo.abilityName.c_str());
            failedData.push_back(str);
            continue;
        }
        ErrCode res;
        if (isSet) {
            res = autoStartupClient->SetApplicationAutoStartupByEDM(autoStartupInfo, true);
        } else {
            res = autoStartupClient->CancelApplicationAutoStartupByEDM(autoStartupInfo, true);
        }
        if (res != ERR_OK) {
            EDMLOGW("OnRemovePolicy SetOrCancelApplicationAutoStartupByEDM err res: %{public}d bundleName: %{public}s "
                "abilityName:%{public}s", res, autoStartupInfo.bundleName.c_str(), autoStartupInfo.abilityName.c_str());
            failedData.push_back(str);
            continue;
        }
        flag = true;
    }
    return flag ? ERR_OK : EdmReturnErrCode::PARAM_ERROR;
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
