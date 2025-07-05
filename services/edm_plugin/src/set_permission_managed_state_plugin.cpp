/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "set_permission_managed_state_plugin.h"
#include "permission_managed_state_serializer.h"
#include "permission_managed_state_info.h"

#include "cJSON.h"
#include "edm_bundle_manager_impl.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "ipolicy_manager.h"

#include "app_control/app_control_proxy.h"
#include <system_ability_definition.h>
#include "edm_sys_manager.h"
#include "bundle_mgr_proxy.h"
#include "bundle_mgr_interface.h"
#include "accesstoken_kit.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(SetPermissionManagedStatePlugin::GetPlugin());

void SetPermissionManagedStatePlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<SetPermissionManagedStatePlugin, std::map<std::string, PermissionManagedStateInfo>>> ptr)
{
    EDMLOGI("SetPermissionManagedStatePlugin InitPlugin...");
    ptr->InitAttribute(
        EdmInterfaceCode::PERMISSION_MANAGED_STATE,
        PolicyName::POLICY_PERMISSION_MANAGED_STATE_POLICY,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_USER_GRANT_PERMISSION,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(PermissionManagedStateSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&SetPermissionManagedStatePlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&SetPermissionManagedStatePlugin::OnAdminRemove);
}

ErrCode SetPermissionManagedStatePlugin::OnSetPolicy(
    std::map<std::string, PermissionManagedStateInfo> &data,
    std::map<std::string, PermissionManagedStateInfo> &currentData,
    std::map<std::string, PermissionManagedStateInfo> &mergeData,
    int32_t userId)
{
    EDMLOGI("SetPermissionManagedStatePlugin OnSetPolicy.");
    if (data.empty()) {
        EDMLOGD("SetPermissionManagedStatePlugin data is empty.");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::map<std::string, PermissionManagedStateInfo> newDataHandle = data;
    std::map<std::string, PermissionManagedStateInfo> currentDataHandle = currentData;
    std::map<std::string, PermissionManagedStateInfo> mergeDataHandle = mergeData;

    for (const auto& pair : newDataHandle) {
        auto it = mergeDataHandle.find(pair.first);
        if (it != mergeDataHandle.end()) {
            return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
        } else {
            if (pair.second.managedState != static_cast<int32_t>(ManagedState::DEFAULT)) {
                mergeDataHandle.insert({pair.first, pair.second});
            }
        }
    }

    PermissionManagedStateInfo info;
    int32_t permissionFlagParam = 0;
    for (const auto& pair : newDataHandle) {
        // Update info fields
        info.permissionNames = pair.second.permissionNames;
        info.managedState = pair.second.managedState;
        info.accountId = pair.second.accountId;
        info.appId = pair.second.appId;
        info.appIndex = pair.second.appIndex;

        if (pair.second.managedState == static_cast<int32_t>(ManagedState::DEFAULT)) {
            permissionFlagParam = static_cast<int32_t>(PermissionFlag::PERMISSION_ADMIN_POLICYS_CANCEL);
            info.managedState = static_cast<int32_t>(ManagedState::DENIED);
        } else {
            permissionFlagParam = static_cast<int32_t>(PermissionFlag::PERMISSION_FIXED_BY_ADMIN_POLICY);
        }

        auto it = currentDataHandle.find(pair.first);
        if (pair.second.managedState == static_cast<int32_t>(ManagedState::DEFAULT)) {
            if (it != currentDataHandle.end()) {
                currentDataHandle.erase(pair.first);
            }
        } else {
            currentDataHandle[pair.first] = pair.second;
        }
    }

    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (proxy == nullptr) {
        EDMLOGE("SetPermissionManagedStatePlugin OnSetPolicy appControlProxy failed.");
        return false;
    }
    std::string bundleName = "";
    ErrCode res = proxy -> GetBundleNameByAppId(info.appId, bundleName);
    if (res != ERR_OK) {
        EDMLOGE("SetPermissionManagedStatePlugin OnSetPolicy GetBundleNameByAppId failed.");
        return false;
    }
    Security::AccessToken::AccessTokenID accessTokenId = Security::AccessToken::AccessTokenKit::GetHapTokenID(
        userId,
        bundleName,
        info.appIndex
    );
    if (accessTokenId == Security::AccessToken::INVALID_TOKENID) {
        EDMLOGE("SetPermissionManagedStatePlugin OnSetPolicy GetAccessTokenId failed.");
        return false;
    }

    int32_t rel = Security::AccessToken::AccessTokenKit::SetPermissionStatusWithPolicy(
        accessTokenId,
        info.permissionNames,
        info.managedState,
        permissionFlagParam
    );
    if (rel != ERR_OK) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    currentData = currentDataHandle;
    mergeData = mergeDataHandle;
    return ERR_OK;
}

ErrCode SetPermissionManagedStatePlugin::OnAdminRemove(
    const std::string &adminName,
    std::map<std::string, PermissionManagedStateInfo> &data,
    std::map<std::string, PermissionManagedStateInfo> &mergeData,
    int32_t userId)
{
    std::map<std::string, PermissionManagedStateInfo> currentDataHandle = data;
    std::map<std::string, PermissionManagedStateInfo> mergeDataHandle = mergeData;

    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (proxy == nullptr) {
        EDMLOGE("SetPermissionManagedStatePlugin OnAdminRemove appControlProxy failed.");
        return false;
    }

    for (const auto &pair : data) {
        std::string bundleName = "";
        ErrCode res = proxy -> GetBundleNameByAppId(pair.second.appId, bundleName);
        if (res != ERR_OK) {
            EDMLOGE("SetPermissionManagedStatePlugin OnAdminRemove GetBundleNameByAppId failed.");
            return false;
        }
        Security::AccessToken::AccessTokenID accessTokenId = Security::AccessToken::AccessTokenKit::GetHapTokenID(
            userId,
            bundleName,
            pair.second.appIndex
        );
        if (accessTokenId == Security::AccessToken::INVALID_TOKENID) {
            EDMLOGE("SetPermissionManagedStatePlugin OnAdminRemove GetAccessTokenId failed.");
            return false;
        }
        std::vector<std::string> permissionNamesParams;
        permissionNamesParams.push_back(pair.second.permissionName);
        int32_t rel = Security::AccessToken::AccessTokenKit::SetPermissionStatusWithPolicy(
            accessTokenId,
            permissionNamesParams,
            static_cast<int32_t>(ManagedState::DENIED),
            static_cast<int32_t>(PermissionFlag::PERMISSION_ADMIN_POLICYS_CANCEL)
        );
        if (rel != ERR_OK) {
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        if (mergeDataHandle.find(pair.first) != mergeDataHandle.end()) {
            mergeDataHandle.erase(pair.first);
        }
        currentDataHandle.erase(pair.first);
    }
    
    data = currentDataHandle;
    mergeData = mergeDataHandle;
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS