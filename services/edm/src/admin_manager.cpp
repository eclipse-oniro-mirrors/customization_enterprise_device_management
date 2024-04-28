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

#include "admin_manager.h"

#include <algorithm>
#include <ctime>
#include <fstream>
#include <iostream>

#include "directory_ex.h"
#include "edm_constants.h"
#include "edm_log.h"
#include "permission_manager.h"
#include "super_admin.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<AdminManager> AdminManager::instance_;
std::mutex AdminManager::mutexLock_;

std::shared_ptr<AdminManager> AdminManager::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> autoLock(mutexLock_);
        if (instance_ == nullptr) {
            instance_.reset(new (std::nothrow) AdminManager());
        }
    }
    return instance_;
}

AdminManager::AdminManager()
{
    EDMLOGI("AdminManager::AdminManager");
}

AdminManager::~AdminManager()
{
    EDMLOGI("AdminManager::~AdminManager");
    admins_.clear();
}

ErrCode AdminManager::GetReqPermission(const std::vector<std::string> &permissions,
    std::vector<EdmPermission> &reqPermissions)
{
    EDMLOGD("AdminManager::GetReqPermission");
    PermissionManager::GetInstance()->GetReqPermission(permissions, reqPermissions);
    return reqPermissions.empty() ? ERR_EDM_EMPTY_PERMISSIONS : ERR_OK;
}

bool AdminManager::GetAdminByUserId(int32_t userId, std::vector<std::shared_ptr<Admin>> &userAdmin)
{
    userAdmin.clear();
    auto iter = admins_.find(userId);
    if (iter == admins_.end()) {
        EDMLOGW("GetAdminByUserId::get userId Admin failed. userId = %{public}d", userId);
        return false;
    }
    userAdmin = iter->second;
    return true;
}

void AdminManager::GetAdminBySubscribeEvent(ManagedEvent event,
    std::unordered_map<int32_t, std::vector<std::shared_ptr<Admin>>> &subscribeAdmins)
{
    for (const auto &adminItem : admins_) {
        std::vector<std::shared_ptr<Admin>> subAdmin;
        for (const auto &it : adminItem.second) {
            std::vector<ManagedEvent> events = it->adminInfo_.managedEvents_;
            if (std::find(events.begin(), events.end(), event) != events.end()) {
                subAdmin.push_back(it);
            }
        }
        if (!subAdmin.empty()) {
            subscribeAdmins[adminItem.first] = subAdmin;
        }
    }
}

ErrCode AdminManager::SetAdminValue(int32_t userId, Admin &adminItem)
{
    auto adminPoliciesStorageRdb = AdminPoliciesStorageRdb::GetInstance();
    if (adminPoliciesStorageRdb == nullptr) {
        EDMLOGE("AdminManager::SetAdminValue get adminPoliciesStorageRdb failed.");
        return ERR_GET_STORAGE_RDB_FAILED;
    }
    std::vector<AdminPermission> reqPermission;
    std::vector<std::string> permissionNames;
    PermissionManager::GetInstance()->GetReqPermission(adminItem.adminInfo_.permission_, reqPermission);
    if (reqPermission.empty()) {
        EDMLOGW("SetAdminValue::the application is requesting useless permissions");
    }
    for (const auto &it : reqPermission) {
        if (adminItem.adminInfo_.adminType_ == AdminType::NORMAL && it.adminType == AdminType::ENT) {
            return ERR_EDM_DENY_PERMISSION;
        }
        permissionNames.push_back(it.permissionName);
    }
    std::shared_ptr<Admin> getAdmin = GetAdminByPkgName(adminItem.adminInfo_.packageName_, userId);
    if (getAdmin != nullptr) {
        if (!adminPoliciesStorageRdb->UpdateAdmin(userId, adminItem)) {
            EDMLOGE("AdminManager::SetAdminValue update failed.");
            return ERR_EDM_ADD_ADMIN_FAILED;
        }
        getAdmin->adminInfo_.adminType_ = adminItem.adminInfo_.adminType_;
        getAdmin->adminInfo_.entInfo_ = adminItem.adminInfo_.entInfo_;
        getAdmin->adminInfo_.permission_ = permissionNames;
        return ERR_OK;
    }
    if (!adminPoliciesStorageRdb->InsertAdmin(userId, adminItem)) {
        EDMLOGE("AdminManager::SetAdminValue insert failed.");
        return ERR_EDM_ADD_ADMIN_FAILED;
    }
    std::vector<std::shared_ptr<Admin>> admins;
    GetAdminByUserId(userId, admins);
    adminItem.adminInfo_.permission_ = permissionNames;
    std::shared_ptr<Admin> admin = std::make_shared<Admin>(adminItem);
    admins.emplace_back(admin);
    admins_[userId] = admins;
    return ERR_OK;
}

std::shared_ptr<Admin> AdminManager::GetAdminByPkgName(const std::string &packageName, int32_t userId)
{
    std::shared_ptr<Admin> subOrSuperAdmin;
    if (SUCCEEDED(GetSubOrSuperAdminByPkgName(packageName, subOrSuperAdmin))) {
        EDMLOGD("GetAdminByPkgName::get sub-super or super admin: %{public}s", packageName.c_str());
        return subOrSuperAdmin;
    }
    std::vector<std::shared_ptr<Admin>> userAdmin;
    if (!GetAdminByUserId(userId, userAdmin)) {
        EDMLOGW("GetAdminByPkgName::get userId Admin failed. userId = %{public}d", userId);
        return nullptr;
    }
    for (const auto &item : userAdmin) {
        if (item->adminInfo_.packageName_ == packageName) {
            return item;
        }
    }
    EDMLOGD("GetAdminByPkgName::get admin failed. admin size = %{public}u, packageName = %{public}s",
        (uint32_t)userAdmin.size(), packageName.c_str());
    return nullptr;
}

ErrCode AdminManager::DeleteAdmin(const std::string &packageName, int32_t userId)
{
    auto iterMap = admins_.find(userId);
    if (iterMap == admins_.end()) {
        EDMLOGW("DeleteAdmin::get userId Admin failed. userId = %{public}d", userId);
        return ERR_EDM_UNKNOWN_ADMIN;
    }
    auto adminPoliciesStorageRdb = AdminPoliciesStorageRdb::GetInstance();
    if (adminPoliciesStorageRdb == nullptr) {
        EDMLOGE("AdminManager::DeleteAdmin get adminPoliciesStorageRdb failed.");
        return ERR_GET_STORAGE_RDB_FAILED;
    }
    if (!adminPoliciesStorageRdb->DeleteAdmin(userId, packageName)) {
        EDMLOGW("delete admin (%{public}s) failed!", packageName.c_str());
        return ERR_EDM_DEL_ADMIN_FAILED;
    }
    auto iter = std::remove_if(iterMap->second.begin(), iterMap->second.end(),
        [&](std::shared_ptr<Admin> admin) { return admin->adminInfo_.packageName_ == packageName; });
    iterMap->second.erase(iter, iterMap->second.end());
    if (iterMap->second.empty()) {
        admins_.erase(iterMap);
    }
    return ERR_OK;
}

ErrCode AdminManager::GetGrantedPermission(std::vector<std::string> &permissions, AdminType type)
{
    if (permissions.empty()) {
        EDMLOGW("GetGrantedPermission::permissions is empty");
        return ERR_OK;
    }
    // filtering out non-edm permissions
    std::vector<AdminPermission> reqPermission;
    PermissionManager::GetInstance()->GetReqPermission(permissions, reqPermission);
    if (reqPermission.empty()) {
        EDMLOGW("GetGrantedPermission::edm permission is empty");
        return ERR_OK;
    }

    // filter out super permissions if admin is NORMAL
    std::vector<std::string> permissionNameList;
    for (const auto &it : reqPermission) {
        if ((type == AdminType::NORMAL) && (it.adminType == AdminType::ENT)) {
            continue;
        }
        permissionNameList.push_back(it.permissionName);
    }
    permissions.assign(permissionNameList.begin(), permissionNameList.end());
    return ERR_OK;
}

ErrCode AdminManager::UpdateAdmin(AppExecFwk::ExtensionAbilityInfo &abilityInfo,
    const std::vector<std::string> &permissions, int32_t userId)
{
    auto adminItem = GetAdminByPkgName(abilityInfo.bundleName, userId);
    if (adminItem == nullptr) {
        EDMLOGW("UpdateAdmin::get null admin, never get here");
        return ERR_EDM_UNKNOWN_ADMIN;
    }
    auto adminPoliciesStorageRdb = AdminPoliciesStorageRdb::GetInstance();
    if (adminPoliciesStorageRdb == nullptr) {
        EDMLOGE("AdminManager::UpdateAdmin get adminPoliciesStorageRdb failed.");
        return ERR_GET_STORAGE_RDB_FAILED;
    }

    std::vector<std::string> combinePermission = permissions;
    ErrCode ret = GetGrantedPermission(combinePermission, adminItem->adminInfo_.adminType_);
    if (ret != ERR_OK) {
        EDMLOGW("UpdateAdmin::GetGrantedPermission failed");
        return ret;
    }

    if (!adminPoliciesStorageRdb->UpdateAdmin(userId, abilityInfo.bundleName, abilityInfo.name, combinePermission)) {
        EDMLOGW("UpdateAdmin::update admin failed.");
        return ERR_EDM_UNKNOWN_ADMIN;
    }
    adminItem->adminInfo_.permission_ = combinePermission;
    adminItem->adminInfo_.packageName_ = abilityInfo.bundleName;
    adminItem->adminInfo_.className_ = abilityInfo.name;
    return ERR_OK;
}

// success is returned as long as there is a super administrator
bool AdminManager::IsSuperAdminExist()
{
    std::vector<std::shared_ptr<Admin>> userAdmin;
    bool ret = GetAdminByUserId(DEFAULT_USER_ID, userAdmin);
    if (!ret) {
        EDMLOGD("IsSuperAdminExist::not find super Admin");
        return false;
    }
    return std::any_of(userAdmin.begin(), userAdmin.end(),
        [](const std::shared_ptr<Admin> &admin) { return admin->adminInfo_.adminType_ == AdminType::ENT; });
}

bool AdminManager::IsSuperAdmin(const std::string &bundleName)
{
    std::shared_ptr<Admin> admin = GetAdminByPkgName(bundleName, DEFAULT_USER_ID);
    if (admin == nullptr) {
        EDMLOGW("IsSuperAdmin: admin == nullptr.");
        return false;
    }
    if (admin->adminInfo_.adminType_ == AdminType::ENT) {
        EDMLOGW("IsSuperAdmin: admin->adminInfo_.adminType_ == AdminType::ENT.");
        return true;
    }
    return false;
}

bool AdminManager::IsAdminExist()
{
    return !admins_.empty();
}

bool AdminManager::IsSuperOrSubSuperAdmin(const std::string &bundleName)
{
    std::shared_ptr<Admin> superAdmin;
    superAdmin = GetAdminByPkgName(bundleName, DEFAULT_USER_ID);
    if (superAdmin == nullptr) {
        return false;
    }
    return superAdmin->adminInfo_.adminType_ == AdminType::ENT ||
        superAdmin->adminInfo_.adminType_ == AdminType::SUB_SUPER_ADMIN;
}

/*
 * There are different administrator types according to the input parameters.
 * Returns a list of package names
 */
void AdminManager::GetEnabledAdmin(AdminType role, std::vector<std::string> &packageNameList, int32_t userId)
{
    packageNameList.clear();
    std::vector<std::shared_ptr<Admin>> userAdmin;
    bool ret = GetAdminByUserId(userId, userAdmin);
    if (!ret) {
        EDMLOGW("GetEnabledAdmin::not find enabled Admin. userId = %{public}d", userId);
        return;
    }
    EDMLOGD("AdminManager:GetEnabledAdmin adminType: %{public}d , admin size: %{public}zu", role, userAdmin.size());
    if (static_cast<int32_t>(role) >= static_cast<int32_t>(AdminType::UNKNOWN) ||
        static_cast<int32_t>(role) < static_cast<int32_t>(AdminType::NORMAL)) {
        EDMLOGD("there is no admin(%{public}u) device manager package name list!", role);
        return;
    }

    for (const auto &item : userAdmin) {
        if (item->adminInfo_.adminType_ == role) {
            std::string adminName = item->adminInfo_.packageName_ + "/" + item->adminInfo_.className_;
            packageNameList.push_back(adminName);
        }
    }
}

ErrCode AdminManager::GetSubOrSuperAdminByPkgName(const std::string &subAdminName,
    std::shared_ptr<Admin> &subOrSuperAdmin)
{
    std::vector<std::shared_ptr<Admin>> userAdmin;
    if (!GetAdminByUserId(DEFAULT_USER_ID, userAdmin)) {
        EDMLOGW("GetSubOrSuperAdminByPkgName::not find Admin under default user id");
        return ERR_EDM_SUPER_ADMIN_NOT_FOUND;
    }
    auto adminItem = std::find_if(userAdmin.begin(), userAdmin.end(), [&](const std::shared_ptr<Admin> &admin) {
        return admin->adminInfo_.packageName_ == subAdminName && (admin->adminInfo_.adminType_ == AdminType::ENT ||
            admin->adminInfo_.adminType_ == AdminType::SUB_SUPER_ADMIN);
    });
    if (adminItem == userAdmin.end()) {
        EDMLOGW("GetSubOrSuperAdminByPkgName::not find sub-super admin or super Admin");
        return ERR_EDM_SUPER_ADMIN_NOT_FOUND;
    }
    subOrSuperAdmin = *adminItem;
    return ERR_OK;
}

ErrCode AdminManager::GetSubSuperAdminsByParentName(const std::string &parentName, std::vector<std::string> &subAdmins)
{
    if (subAdmins.size() > 0) {
        subAdmins.clear();
    }
    std::vector<std::shared_ptr<Admin>> userAdmin;
    if (!GetAdminByUserId(DEFAULT_USER_ID, userAdmin)) {
        EDMLOGE("GetSubSuperAdminsByParentName::not find Admin under default user id.");
        return ERR_EDM_SUPER_ADMIN_NOT_FOUND;
    }
    for (const auto &admin : userAdmin) {
        if (admin->adminInfo_.adminType_ == AdminType::SUB_SUPER_ADMIN &&
            admin->adminInfo_.parentAdminName_ == parentName) {
            subAdmins.push_back(admin->adminInfo_.packageName_);
        }
    }
    return ERR_OK;
}

ErrCode AdminManager::GetEntInfo(const std::string &packageName, EntInfo &entInfo, int32_t userId)
{
    std::vector<std::shared_ptr<Admin>> userAdmin;
    bool ret = GetAdminByUserId(userId, userAdmin);
    if (!ret) {
        EDMLOGW("GetEntInfo::not find Admin. userId = %{public}d", userId);
        return ERR_EDM_UNKNOWN_ADMIN;
    }
    for (const auto &item : userAdmin) {
        if (item->adminInfo_.packageName_ == packageName) {
            entInfo = item->adminInfo_.entInfo_;
            return ERR_OK;
        }
    }
    return ERR_EDM_UNKNOWN_ADMIN;
}

ErrCode AdminManager::SetEntInfo(const std::string &packageName, EntInfo &entInfo, int32_t userId)
{
    std::vector<std::shared_ptr<Admin>> userAdmin;
    bool ret = GetAdminByUserId(userId, userAdmin);
    if (!ret) {
        EDMLOGW("SetEntInfo::not find Admin. userId = %{public}d", userId);
        return ERR_EDM_UNKNOWN_ADMIN;
    }
    auto adminPoliciesStorageRdb = AdminPoliciesStorageRdb::GetInstance();
    if (adminPoliciesStorageRdb == nullptr) {
        EDMLOGE("AdminManager::SetEntInfo get adminPoliciesStorageRdb failed.");
        return ERR_GET_STORAGE_RDB_FAILED;
    }
    for (auto &item : userAdmin) {
        if (item->adminInfo_.packageName_ == packageName &&
            adminPoliciesStorageRdb->UpdateEntInfo(userId, packageName, entInfo)) {
            item->adminInfo_.entInfo_ = entInfo;
            return ERR_OK;
        }
    }
    return ERR_EDM_UNKNOWN_ADMIN;
}

ErrCode AdminManager::SaveSubscribeEvents(const std::vector<uint32_t> &events, const std::string &bundleName,
    int32_t userId)
{
    std::shared_ptr<Admin> admin = GetAdminByPkgName(bundleName, userId);
    if (admin == nullptr) {
        return ERR_EDM_UNKNOWN_ADMIN;
    }
    auto adminPoliciesStorageRdb = AdminPoliciesStorageRdb::GetInstance();
    if (adminPoliciesStorageRdb == nullptr) {
        EDMLOGE("AdminManager::SaveSubscribeEvents get adminPoliciesStorageRdb failed.");
        return ERR_GET_STORAGE_RDB_FAILED;
    }
    std::vector<ManagedEvent> oldManagedEvents = admin->adminInfo_.managedEvents_;
    size_t eventsNumber = admin->adminInfo_.managedEvents_.size();
    for (const auto &event : events) {
        std::vector<ManagedEvent> managedEvents = admin->adminInfo_.managedEvents_;
        ManagedEvent subEvent = static_cast<ManagedEvent>(event);
        if (std::find(managedEvents.begin(), managedEvents.end(), subEvent) == managedEvents.end()) {
            admin->adminInfo_.managedEvents_.push_back(subEvent);
        }
    }
    if (admin->adminInfo_.managedEvents_.size() > eventsNumber &&
        !adminPoliciesStorageRdb->UpdateManagedEvents(userId, admin->adminInfo_.packageName_,
            admin->adminInfo_.managedEvents_)) {
        admin->adminInfo_.managedEvents_ = oldManagedEvents;
        return ERR_EDM_UNKNOWN_ADMIN;
    }
    return ERR_OK;
}

ErrCode AdminManager::RemoveSubscribeEvents(const std::vector<uint32_t> &events, const std::string &bundleName,
    int32_t userId)
{
    std::shared_ptr<Admin> admin = GetAdminByPkgName(bundleName, userId);
    if (admin == nullptr) {
        return ERR_EDM_UNKNOWN_ADMIN;
    }
    auto adminPoliciesStorageRdb = AdminPoliciesStorageRdb::GetInstance();
    if (adminPoliciesStorageRdb == nullptr) {
        EDMLOGE("AdminManager::RemoveSubscribeEvents get adminPoliciesStorageRdb failed.");
        return ERR_GET_STORAGE_RDB_FAILED;
    }

    std::vector<ManagedEvent> oldManagedEvents = admin->adminInfo_.managedEvents_;
    size_t eventsNumber = admin->adminInfo_.managedEvents_.size();
    auto iter = std::remove_if(admin->adminInfo_.managedEvents_.begin(), admin->adminInfo_.managedEvents_.end(),
        [&](ManagedEvent managedEvent) {
            return std::find(events.begin(), events.end(), static_cast<uint32_t>(managedEvent)) != events.end();
        });
    admin->adminInfo_.managedEvents_.erase(iter, admin->adminInfo_.managedEvents_.end());

    if (admin->adminInfo_.managedEvents_.size() < eventsNumber &&
        !adminPoliciesStorageRdb->UpdateManagedEvents(userId, admin->adminInfo_.packageName_,
            admin->adminInfo_.managedEvents_)) {
        admin->adminInfo_.managedEvents_ = oldManagedEvents;
        return ERR_EDM_UNKNOWN_ADMIN;
    }
    return ERR_OK;
}

ErrCode AdminManager::SaveAuthorizedAdmin(const std::string &bundleName, const std::vector<std::string> &permissions,
    const std::string &parentName)
{
    std::vector<std::shared_ptr<Admin>> admin;
    if (!GetAdminByUserId(DEFAULT_USER_ID, admin)) {
        return ERR_SAVE_AUTHORIZED_ADMIN_FAILED;
    }
    std::shared_ptr<Admin> adminItem = GetAdminByPkgName(bundleName, DEFAULT_USER_ID);
    if (!adminItem &&
        !AdminPoliciesStorageRdb::GetInstance()->InsertAuthorizedAdmin(bundleName, permissions, parentName)) {
        EDMLOGE("AdminManager::InsertAuthorizedAdmin save authorized failed.");
        return ERR_SAVE_AUTHORIZED_ADMIN_FAILED;
    }
    if (adminItem) {
        if (adminItem->GetAdminType() != AdminType::SUB_SUPER_ADMIN) {
            EDMLOGE("AdminManager::UpdateAuthorizedAdmin can only update sub-super admin.");
            return ERR_SAVE_AUTHORIZED_ADMIN_FAILED;
        }
        if (!AdminPoliciesStorageRdb::GetInstance()->UpdateAuthorizedAdmin(bundleName, permissions, parentName)) {
            EDMLOGE("AdminManager::UpdateAuthorizedAdmin save authorized failed.");
            return ERR_SAVE_AUTHORIZED_ADMIN_FAILED;
        }
    }
    if (!adminItem) {
        admin.emplace_back(std::make_shared<Admin>());
        admins_[DEFAULT_USER_ID] = admin;
        adminItem = admin.back();
        adminItem->adminInfo_.adminType_ = AdminType::SUB_SUPER_ADMIN;
    }
    adminItem->adminInfo_.packageName_ = bundleName;
    adminItem->adminInfo_.permission_ = permissions;
    adminItem->adminInfo_.parentAdminName_ = parentName;
    return ERR_OK;
}

std::shared_ptr<Admin> AdminManager::GetSuperAdmin()
{
    if (admins_.find(DEFAULT_USER_ID) != admins_.end()) {
        auto item = std::find_if(admins_[DEFAULT_USER_ID].begin(), admins_[DEFAULT_USER_ID].end(),
            [&](const std::shared_ptr<Admin>& admin) { return admin->GetAdminType() == AdminType::ENT; });
        if (item != admins_[DEFAULT_USER_ID].end()) {
            return *item;
        }
    }
    return nullptr;
}

// init
void AdminManager::Init()
{
    auto adminPoliciesStorageRdb = AdminPoliciesStorageRdb::GetInstance();
    if (adminPoliciesStorageRdb != nullptr) {
        admins_ = adminPoliciesStorageRdb->QueryAllAdmin();
    } else {
        EDMLOGE("AdminManager::Init failed.");
    }
}

void AdminManager::Dump()
{
    for (const auto &entry : admins_) {
        EDMLOGI("AdminManager::Dump %{public}d.", entry.first);
        for (const auto &admin : entry.second) {
            EDMLOGI("AdminManager::Dump admin info adminType_ %{public}d.",
                admin->adminInfo_.adminType_);
            EDMLOGI("AdminManager::Dump admin info packageName_ %{public}s.",
                admin->adminInfo_.packageName_.c_str());
            EDMLOGI("AdminManager::Dump admin info parentAdminName_ %{public}s.",
                admin->adminInfo_.parentAdminName_.c_str());
        }
    }
}
} // namespace EDM
} // namespace OHOS
