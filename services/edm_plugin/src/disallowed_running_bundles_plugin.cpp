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

#include "disallowed_running_bundles_plugin.h"

#include <system_ability_definition.h>

#include "app_control/app_control_proxy.h"
#include "array_string_serializer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_sys_manager.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisallowedRunningBundlesPlugin::GetPlugin());

void DisallowedRunningBundlesPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<DisallowedRunningBundlesPlugin, std::vector<std::string>>> ptr)
{
    EDMLOGI("DisallowedRunningBundlesPlugin InitPlugin...");
    std::map<std::string, std::map<IPlugin::PermissionType, std::string>> tagPermissions;
    std::map<IPlugin::PermissionType, std::string> typePermissionsForTag11;
    std::map<IPlugin::PermissionType, std::string> typePermissionsForTag12;
    typePermissionsForTag11.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        "ohos.permission.ENTERPRISE_MANAGE_SET_APP_RUNNING_POLICY");
    typePermissionsForTag12.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        "ohos.permission.ENTERPRISE_MANAGE_APPLICATION");
    tagPermissions.emplace(EdmConstants::PERMISSION_TAG_VERSION_11, typePermissionsForTag11);
    tagPermissions.emplace(EdmConstants::PERMISSION_TAG_VERSION_12, typePermissionsForTag12);

    IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig(tagPermissions, IPlugin::ApiType::PUBLIC);
    ptr->InitAttribute(EdmInterfaceCode::DISALLOW_RUNNING_BUNDLES, "disallow_running_bundles", config, true);
    ptr->SetSerializer(ArrayStringSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisallowedRunningBundlesPlugin::OnBasicSetPolicy, FuncOperateType::SET);
    ptr->SetOnHandlePolicyListener(&DisallowedRunningBundlesPlugin::OnBasicRemovePolicy, FuncOperateType::REMOVE);
    ptr->SetOnAdminRemoveListener(&DisallowedRunningBundlesPlugin::OnBasicAdminRemove);
    maxListSize_ = EdmConstants::APPID_MAX_SIZE;
}

ErrCode DisallowedRunningBundlesPlugin::SetOtherModulePolicy(const std::vector<std::string> &data, int32_t userId,
    std::vector<std::string> &failedData)
{
    EDMLOGI("DisallowedRunningBundlesPlugin OnSetPolicy userId = %{public}d", userId);
    std::vector<AppExecFwk::AppRunningControlRule> controlRules;
    std::for_each(data.begin(), data.end(), [&](const std::string &str) {
        AppExecFwk::AppRunningControlRule controlRule;
        controlRule.appId = str;
        controlRules.push_back(controlRule);
    });

    auto appControlProxy = GetAppControlProxy();
    if (!appControlProxy) {
        EDMLOGE("DisallowedRunningBundlesPlugin OnSetPolicy GetAppControlProxy failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    ErrCode res = appControlProxy->AddAppRunningControlRule(controlRules, userId);
    if (res != ERR_OK) {
        EDMLOGE("DisallowedRunningBundlesPlugin OnSetPolicyDone Faild %{public}d:", res);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode DisallowedRunningBundlesPlugin::RemoveOtherModulePolicy(const std::vector<std::string> &data, int32_t userId,
    std::vector<std::string> &failedData)
{
    EDMLOGD("DisallowedRunningBundlesPlugin OnRemovePolicy userId : %{public}d:", userId);
    std::vector<AppExecFwk::AppRunningControlRule> controlRules;
    std::for_each(data.begin(), data.end(), [&](const std::string &str) {
        AppExecFwk::AppRunningControlRule controlRule;
        controlRule.appId = str;
        controlRules.push_back(controlRule);
    });
    auto appControlProxy = GetAppControlProxy();
    if (!appControlProxy) {
        EDMLOGE("DisallowedRunningBundlesPlugin OnRemovePolicy GetAppControlProxy failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    ErrCode res = appControlProxy->DeleteAppRunningControlRule(controlRules, userId);
    if (res != ERR_OK) {
        EDMLOGE("DisallowedRunningBundlesPlugin DeleteAppInstallControlRule OnRemovePolicy faild %{public}d:", res);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

sptr<AppExecFwk::IAppControlMgr> DisallowedRunningBundlesPlugin::GetAppControlProxy()
{
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    return proxy->GetAppControlProxy();
}
} // namespace EDM
} // namespace OHOS
