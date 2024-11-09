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
        permissions_.insert(std::make_pair(permission, static_cast<AdminType>(permissionType)));
        EDMLOGI("AddPermission::insert permission : %{public}s permissionType : %{public}d",
            permission.c_str(), static_cast<int32_t>(permissionType));
    } else if (entry->second != static_cast<AdminType>(permissionType)) {
        EDMLOGE("AddPermission::conflict permission type");
        return ERR_EDM_DENY_PERMISSION;
    } else {
        EDMLOGI("AddPermission::same permission has been added : %{public}s", permission.c_str());
    }
    EDMLOGD("AddPermission::return ok");
    return ERR_OK;
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
        if (adminType == AdminType::NORMAL && entry->second == AdminType::ENT) {
            EDMLOGE("GetAdminGrantedPermission normal admin can request super admin permission.");
            continue;
        }
        reqPermission.emplace_back(entry->first);
    }
}
} // namespace EDM
} // namespace OHOS
