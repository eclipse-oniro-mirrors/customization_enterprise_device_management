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

#include "external_storage_intercept_enable_plugin.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "iadmin_manager.h"
#include "imdm_event_relayer.h"
#include "iplugin_manager.h"
#include "ipolicy_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(
    std::make_shared<ExternalStorageInterceptEnablePlugin>());

ExternalStorageInterceptEnablePlugin::ExternalStorageInterceptEnablePlugin()
{
    EDMLOGI("ExternalStorageInterceptEnablePlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::EXTERNAL_STORAGE_INTERCEPT_ENABLE;
    policyName_ = PolicyName::POLICY_EXTERNAL_STORAGE_INTERCEPT_ENABLE;
    permissionConfig_ = IPlugin::PolicyPermissionConfig(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_USB, IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        IPlugin::ApiType::PUBLIC);
    persistParam_ = EdmConstants::PARAM_EDM_ENABLE_EXTERNAL_STORAGE_MOUNT_INTERCEPT;
}

void ExternalStorageInterceptEnablePlugin::OnHandlePolicyDone(std::uint32_t funcCode,
    const std::string &adminName, bool isGlobalChanged, int32_t userId)
{
    EDMLOGI("ExternalStorageInterceptEnablePlugin::OnHandlePolicyDone admin: %{public}s", adminName.c_str());
    std::string policyValue;
    IPolicyManager::GetInstance()->GetPolicy(adminName, policyName_, policyValue, userId);
    bool enabled = policyValue == EdmConstants::CONST_TRUE;
    std::vector<uint32_t> events = {static_cast<uint32_t>(ManagedEvent::UNMOUNT_EXTERNAL_STORAGE_DEVICE)};
    if (enabled) {
        IAdminManager::GetInstance()->SaveSubscribeEvents(events, adminName, userId);
        IMdmEventRelayer::GetInstance()->OnAdminSubscribe(adminName, userId,
            ManagedEvent::UNMOUNT_EXTERNAL_STORAGE_DEVICE);
    } else {
        IAdminManager::GetInstance()->RemoveSubscribeEvents(events, adminName, userId);
        IMdmEventRelayer::GetInstance()->OnAdminUnsubscribe(adminName, userId,
            ManagedEvent::UNMOUNT_EXTERNAL_STORAGE_DEVICE);
    }
}

void ExternalStorageInterceptEnablePlugin::OnAdminRemoveDone(const std::string &adminName,
    const std::string &currentJsonData, int32_t userId)
{
    EDMLOGI("ExternalStorageInterceptEnablePlugin::OnAdminRemoveDone admin: %{public}s", adminName.c_str());
    std::vector<uint32_t> events = {static_cast<uint32_t>(ManagedEvent::UNMOUNT_EXTERNAL_STORAGE_DEVICE)};
    IAdminManager::GetInstance()->RemoveSubscribeEvents(events, adminName, userId);
    IMdmEventRelayer::GetInstance()->OnAdminUnsubscribe(adminName, userId,
        ManagedEvent::UNMOUNT_EXTERNAL_STORAGE_DEVICE);
}
} // namespace EDM
} // namespace OHOS
