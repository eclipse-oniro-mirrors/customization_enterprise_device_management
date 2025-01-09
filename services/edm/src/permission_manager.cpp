/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "permission_manager.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
PermissionManager::PermissionManager() {}

PermissionManager::~PermissionManager()
{
    permissions_.clear();
}

ErrCode PermissionManager::AddPermission(const std::string &permission, IPlugin::PermissionType permissionType)
{
    if (permission.empty()) {
        return ERR_OK;
    }
    if (static_cast<std::int32_t>(permissionType) <
        static_cast<std::int32_t>(IPlugin::PermissionType::NORMAL_DEVICE_ADMIN) ||
        static_cast<std::int32_t>(permissionType) >= static_cast<std::int32_t>(IPlugin::PermissionType::UNKNOWN)) {
        EDMLOGE("AddPermission::unknow permission type");
        return ERR_EDM_UNKNOWN_PERMISSION;
    }
    auto entry = permissions_.find(permission);
    if (entry == permissions_.end()) {
        permissions_.insert(std::make_pair(permission, PermissionTypeToAdminType(permissionType)));
        EDMLOGI("AddPermission::insert permission : %{public}s permissionType : %{public}d",
            permission.c_str(), static_cast<int32_t>(permissionType));
    } else if (entry->second != PermissionTypeToAdminType(permissionType)) {
        EDMLOGE("AddPermission::conflict permission type");
        return ERR_EDM_DENY_PERMISSION;
    } else {
        EDMLOGI("AddPermission::same permission has been added : %{public}s", permission.c_str());
    }
    EDMLOGD("AddPermission::return ok");
    return ERR_OK;
}

AdminType PermissionManager::PermissionTypeToAdminType(IPlugin::PermissionType permissionType)
{
    if (permissionType == IPlugin::PermissionType::BYOD_DEVICE_ADMIN) {
        return AdminType::BYOD;
    }
    return static_cast<AdminType>(permissionType);
}

void PermissionManager::GetAdminGrantedPermission(const std::vector<std::string> &permissions, AdminType adminType,
    std::vector<std::string> &reqPermission)
{
    reqPermission.clear();
    for (const auto &item : permissions) {
        auto entry = permissions_.find(item);
        if (entry == permissions_.end()) {
            continue;
        }
        if (adminType == AdminType::NORMAL && (entry->second == AdminType::ENT || entry->second == AdminType::BYOD)) {
            EDMLOGE("GetAdminGrantedPermission normal admin can not request super and byod admin permission.");
            continue;
        }
        if (adminType == AdminType::BYOD && entry->second == AdminType::ENT) {
            EDMLOGE("GetAdminGrantedPermission byod admin can not request super admin permission.");
            continue;
        }
        if (adminType == AdminType::ENT && entry->second == AdminType::BYOD) {
            EDMLOGE("GetAdminGrantedPermission super admin can not request byod admin permission.");
            continue;
        }
        reqPermission.emplace_back(entry->first);
        EDMLOGI("reqPermission.emplace_back:%{public}s:", entry->first.c_str());
    }
}
} // namespace EDM
} // namespace OHOS
