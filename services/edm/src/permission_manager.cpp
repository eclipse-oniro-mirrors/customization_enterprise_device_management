/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

ErrCode PermissionManager::AddPermission(const std::string &permission)
{
    for (const auto &item : ADMIN_PERMISSIONS) {
        if (permission == item.permissionName) {
            auto entry = permissions_.find(permission);
            if (entry == permissions_.end()) {
                permissions_.insert(std::make_pair(permission, item));
            }
            EDMLOGD("AddPermission::return ok");
            return ERR_OK;
        }
    }
    EDMLOGW("AddPermission::return unknow permission");
    return ERR_EDM_UNKNOWN_PERMISSION;
}

void PermissionManager::GetReqPermission(const std::vector<std::string> &permissions,
    std::vector<AdminPermission> &reqPermission)
{
    reqPermission.clear();
    if (permissions.empty()) {
        return;
    }

    for (const auto &item : permissions) {
        auto entry = permissions_.find(item);
        if (entry != permissions_.end()) {
            reqPermission.emplace_back(entry->second);
        }
    }
}

void PermissionManager::GetReqPermission(const std::vector<std::string> &permissions,
    std::vector<EdmPermission> &reqPermission)
{
    reqPermission.clear();
    for (const auto &item : permissions) {
        auto entry = permissions_.find(item);
        if (entry != permissions_.end()) {
            EdmPermission edmPermission(entry->second.permissionName, entry->second.adminType);
            reqPermission.emplace_back(edmPermission);
        }
    }
}
} // namespace EDM
} // namespace OHOS
