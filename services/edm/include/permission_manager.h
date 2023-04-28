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

#ifndef SERVICES_EDM_INCLUDE_EDM_PERMISSION_MANAGER_H
#define SERVICES_EDM_INCLUDE_EDM_PERMISSION_MANAGER_H

#include <map>
#include <string>
#include <vector>
#include "admin.h"
#include "edm_permission.h"
#include "iplugin.h"
#include "singleton.h"

namespace OHOS {
namespace EDM {
struct AdminPermission {
    std::string permissionName;
    AdminType adminType;
    AdminPermission(std::string _permissionName, AdminType _adminType) : permissionName(_permissionName),
        adminType(_adminType) {}
};

class PermissionManager : public DelayedSingleton<PermissionManager> {
DECLARE_DELAYED_SINGLETON(PermissionManager)
public:
    ErrCode AddPermission(const std::string &permission, IPlugin::PermissionType permissionType);
    void GetReqPermission(const std::vector<std::string> &permissions,
        std::vector<AdminPermission> &reqPermission);
    void GetReqPermission(const std::vector<std::string> &permissions,
        std::vector<EdmPermission> &reqPermission);

private:
    std::map<std::string, AdminPermission> permissions_;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_EDM_PERMISSION_MANAGER_H
