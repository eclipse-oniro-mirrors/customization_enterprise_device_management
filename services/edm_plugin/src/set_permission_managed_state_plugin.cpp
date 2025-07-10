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

#include "accesstoken_kit.h"

#include "edm_access_token_manager_impl.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "ipolicy_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(SetPermissionManagedStatePlugin::GetPlugin());

void SetPermissionManagedStatePlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<SetPermissionManagedStatePlugin,
    std::map<std::string, PermissionManagedStateInfo>>> ptr)
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
    if (data.empty()) {
        EDMLOGE("SetPermissionManagedStatePlugin data is empty.");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    std::map<std::string, PermissionManagedStateInfo> newDataHandle = data;
    std::map<std::string, PermissionManagedStateInfo> currentDataHandle = currentData;
    std::map<std::string, PermissionManagedStateInfo> mergeDataHandle = mergeData;
    for (const auto& pair : newDataHandle) {
        if (mergeDataHandle.find(pair.first) != mergeDataHandle.end()) {
            return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
        }
        if (pair.second.managedState != static_cast<int32_t>(ManagedState::DEFAULT)) {
            mergeDataHandle.insert({pair.first, pair.second});
        }
    }
    PermissionManagedStateInfo info;
    int32_t permissionFlagParam;
    for (const auto& pair : newDataHandle) {
        info = pair.second;
        if (currentDataHandle.find(pair.first) != currentDataHandle.end()) {
            if (pair.second.managedState == static_cast<int32_t>(ManagedState::DEFAULT)) {
                currentDataHandle.erase(pair.first);
            } else {
                currentDataHandle[pair.first] = pair.second;
            }
        } else if (pair.second.managedState != static_cast<int32_t>(ManagedState::DEFAULT)) {
            currentDataHandle.insert({pair.first, pair.second});
        }
    }
    if (info.managedState == static_cast<int32_t>(ManagedState::DEFAULT)) {
        permissionFlagParam = static_cast<int32_t>(PermissionFlag::PERMISSION_ADMIN_POLICYS_CANCEL);
        info.managedState = static_cast<int32_t>(ManagedState::DENIED);
    } else {
        permissionFlagParam = static_cast<int32_t>(PermissionFlag::PERMISSION_FIXED_BY_ADMIN_POLICY);
    }
    ErrCode rel = SetPermissionStatusWithPolicy(permissionFlagParam, info);
    if (rel != ERR_OK) {
        EDMLOGE("SetPermissionManagedStatePlugin OnSetPolicy SetPermissionStatusWithPolicy failed.");
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

    for (const auto &pair : data) {
        PermissionManagedStateInfo info = pair.second;
        info.managedState = static_cast<int32_t>(ManagedState::DENIED);
        std::vector<std::string> permissionNamesParams;
        permissionNamesParams.push_back(pair.second.permissionName);
        ErrCode rel = SetPermissionStatusWithPolicy(
            static_cast<int32_t>(PermissionFlag::PERMISSION_ADMIN_POLICYS_CANCEL),
            info);
        if (rel != ERR_OK) {
            EDMLOGE("SetPermissionManagedStatePlugin OnAdminRemove SetPermissionStatusWithPolicy failed.");
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

ErrCode SetPermissionManagedStatePlugin::SetPermissionStatusWithPolicy(
    int32_t permissionFlag,
    PermissionManagedStateInfo info)
{
    Security::AccessToken::AccessTokenID accessTokenId;
    EdmAccessTokenManagerImpl edmAccessTokenManagerImpl;
    if (!edmAccessTokenManagerImpl.GetAccessTokenId(info.accountId, info.appId, info.appIndex, accessTokenId)) {
        EDMLOGE("SetPermissionManagedStatePlugin OnSetPolicy GetAccessTokenId failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return Security::AccessToken::AccessTokenKit::SetPermissionStatusWithPolicy(accessTokenId,
        info.permissionNames, info.managedState, permissionFlag);
}

} // namespace EDM
} // namespace OHOS