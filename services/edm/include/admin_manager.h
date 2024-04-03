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

#ifndef SERVICES_EDM_INCLUDE_ADMIN_MANAGER_H
#define SERVICES_EDM_INCLUDE_ADMIN_MANAGER_H

#include <map>
#include <memory>
#include <unordered_map>

#include "admin.h"
#include "admin_policies_storage_rdb.h"
#include "edm_permission.h"
#include "ent_info.h"
#include "json/json.h"

namespace OHOS {
namespace EDM {
class AdminManager : public std::enable_shared_from_this<AdminManager> {
public:
    static std::shared_ptr<AdminManager> GetInstance();
    ErrCode GetReqPermission(const std::vector<std::string> &permissions, std::vector<EdmPermission> &edmPermissions);
    bool GetAdminByUserId(int32_t userId, std::vector<std::shared_ptr<Admin>> &userAdmin);
    void GetAdminBySubscribeEvent(ManagedEvent event,
        std::unordered_map<int32_t, std::vector<std::shared_ptr<Admin>>> &subscribeAdmins);
    std::shared_ptr<Admin> GetAdminByPkgName(const std::string &packageName, int32_t userId);
    ErrCode DeleteAdmin(const std::string &packageName, int32_t userId);
    ErrCode UpdateAdmin(AppExecFwk::ExtensionAbilityInfo &abilityInfo, const std::vector<std::string> &permissions,
        int32_t userId);
    ErrCode GetGrantedPermission(std::vector<std::string> &permissions, AdminType type);
    bool IsSuperAdminExist();
    bool IsSuperAdmin(const std::string &bundleName);
    bool IsAdminExist();
    bool IsSuperOrSubSuperAdmin(const std::string &bundleName);
    void GetEnabledAdmin(AdminType role, std::vector<std::string> &packageNameList, int32_t userId);
    std::shared_ptr<Admin> GetSuperAdmin();
    void Init();
    ErrCode SetAdminValue(int32_t userId, Admin &adminItem);
    ErrCode GetEntInfo(const std::string &packageName, EntInfo &entInfo, int32_t userId);
    ErrCode SetEntInfo(const std::string &packageName, EntInfo &entInfo, int32_t userId);
    ErrCode SaveSubscribeEvents(const std::vector<uint32_t> &events, const std::string &bundleName, int32_t userId);
    ErrCode RemoveSubscribeEvents(const std::vector<uint32_t> &events, const std::string &bundleName, int32_t userId);
    ErrCode SaveAuthorizedAdmin(const std::string &bundleName, const std::vector<std::string> &permissions,
        const std::string &parentName);
    ErrCode GetSubOrSuperAdminByPkgName(const std::string &subAdminName, std::shared_ptr<Admin> &subOrSuperAdmin);
    ErrCode GetSubSuperAdminsByParentName(const std::string &parentName, std::vector<std::string> &subAdmins);
    ~AdminManager();
    void Dump();

private:
    AdminManager();

    std::unordered_map<int32_t, std::vector<std::shared_ptr<Admin>>> admins_;
    static std::mutex mutexLock_;
    static std::shared_ptr<AdminManager> instance_;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_ADMIN_MANAGER_H
