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

ErrCode AdminManager::SetAdminValue(int32_t userId, const Admin &adminItem)
{
    std::shared_ptr<Admin> getAdmin = GetAdminByPkgName(adminItem.adminInfo_.packageName_, userId);
    if (getAdmin != nullptr) {
        return UpdateAdmin(getAdmin, userId, adminItem);
    }
    if (!AdminPoliciesStorageRdb::GetInstance()->InsertAdmin(userId, adminItem)) {
        EDMLOGE("AdminManager::SetAdminValue insert failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::vector<std::shared_ptr<Admin>> admins;
    GetAdminByUserId(userId, admins);
    std::shared_ptr<Admin> admin = std::make_shared<Admin>(adminItem);
    admins.emplace_back(admin);
    admins_[userId] = admins;
    return ERR_OK;
}

std::shared_ptr<Admin> AdminManager::GetAdminByPkgName(const std::string &packageName, int32_t userId)
{
    std::shared_ptr<Admin> subOrSuperAdmin;
    if (userId != EdmConstants::DEFAULT_USER_ID &&
        SUCCEEDED(GetSubOrSuperAdminByPkgName(packageName, subOrSuperAdmin))) {
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

ErrCode AdminManager::UpdateAdmin(std::shared_ptr<Admin> getAdmin, int32_t userId, const Admin &adminItem)
{
    if (getAdmin == nullptr) {
        EDMLOGW("UpdateAdmin::get null admin, never get here");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (getAdmin->GetAdminType() != AdminType::NORMAL && getAdmin->GetAdminType() != adminItem.GetAdminType()) {
        EDMLOGE("AdminManager::UpdateAdmin sub-super or delegated admin can not update to another type.");
        return EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED;
    }
    if (getAdmin->GetAdminType() == AdminType::NORMAL && adminItem.GetAdminType() != AdminType::NORMAL &&
        adminItem.GetAdminType() != AdminType::ENT) {
        EDMLOGE("AdminManager::UpdateAdmin normal admin can not update to sub-super admin or delegated admin.");
        return EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED;
    }
    if (!AdminPoliciesStorageRdb::GetInstance()->UpdateAdmin(userId, adminItem)) {
        EDMLOGW("UpdateAdmin::update admin failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    getAdmin->adminInfo_.adminType_ = adminItem.adminInfo_.adminType_;
    getAdmin->adminInfo_.entInfo_ = adminItem.adminInfo_.entInfo_;
    getAdmin->adminInfo_.permission_ = adminItem.adminInfo_.permission_;
    getAdmin->adminInfo_.accessiblePolicies_ = adminItem.adminInfo_.accessiblePolicies_;
    return ERR_OK;
}

// success is returned as long as there is a super administrator
bool AdminManager::IsSuperAdminExist()
{
    std::vector<std::shared_ptr<Admin>> userAdmin;
    bool ret = GetAdminByUserId(EdmConstants::DEFAULT_USER_ID, userAdmin);
    if (!ret) {
        EDMLOGD("IsSuperAdminExist::not find super Admin");
        return false;
    }
    return std::any_of(userAdmin.begin(), userAdmin.end(),
        [](const std::shared_ptr<Admin> &admin) { return admin->adminInfo_.adminType_ == AdminType::ENT; });
}

bool AdminManager::IsSuperAdmin(const std::string &bundleName)
{
    std::shared_ptr<Admin> admin = GetAdminByPkgName(bundleName, EdmConstants::DEFAULT_USER_ID);
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
    superAdmin = GetAdminByPkgName(bundleName, EdmConstants::DEFAULT_USER_ID);
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
    if (!GetAdminByUserId(EdmConstants::DEFAULT_USER_ID, userAdmin)) {
        EDMLOGW("GetSubOrSuperAdminByPkgName::not find Admin under default user id");
        return ERR_EDM_SUPER_ADMIN_NOT_FOUND;
    }
    auto adminItem = std::find_if(userAdmin.begin(), userAdmin.end(), [&](const std::shared_ptr<Admin> &admin) {
        return admin->adminInfo_.packageName_ == subAdminName && (admin->GetAdminType() == AdminType::ENT ||
            admin->GetAdminType() == AdminType::SUB_SUPER_ADMIN || admin->GetAdminType() == AdminType::VIRTUAL_ADMIN);
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
    if (!GetAdminByUserId(EdmConstants::DEFAULT_USER_ID, userAdmin)) {
        EDMLOGE("GetSubSuperAdminsByParentName::not find Admin under default user id.");
        return ERR_EDM_SUPER_ADMIN_NOT_FOUND;
    }
    for (const auto &admin : userAdmin) {
        if ((admin->GetAdminType() == AdminType::SUB_SUPER_ADMIN ||
            admin->GetAdminType() == AdminType::VIRTUAL_ADMIN) &&
            admin->GetParentAdminName() == parentName) {
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

ErrCode AdminManager::GetPoliciesByVirtualAdmin(const std::string &bundleName, const std::string &parentName,
    std::vector<std::string> &policies)
{
    policies.clear();
    std::shared_ptr<Admin> virtualAdmin = GetAdminByPkgName(bundleName, EdmConstants::DEFAULT_USER_ID);
    if (virtualAdmin == nullptr) {
        return EdmReturnErrCode::PARAM_ERROR;
    }
    if (virtualAdmin->GetAdminType() != AdminType::VIRTUAL_ADMIN || virtualAdmin->GetParentAdminName() != parentName) {
        EDMLOGE("GetPoliciesByVirtualAdmin the administrator does not have permission to get delegated policies.");
        return EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED;
    }
    policies = virtualAdmin->adminInfo_.accessiblePolicies_;
    return ERR_OK;
}

void AdminManager::GetVirtualAdminsByPolicy(const std::string &policyName, const std::string &parentName,
    std::vector<std::string> &bundleNames)
{
    bundleNames.clear();
    std::vector<std::shared_ptr<Admin>> admins;
    GetAdminByUserId(EdmConstants::DEFAULT_USER_ID, admins);
    for (auto adminItem : admins) {
        if (adminItem->GetAdminType() != AdminType::VIRTUAL_ADMIN || adminItem->GetParentAdminName() != parentName) {
            continue;
        }
        auto policies = adminItem->adminInfo_.accessiblePolicies_;
        if (std::find(policies.begin(), policies.end(), policyName) != policies.end()) {
            bundleNames.emplace_back(adminItem->adminInfo_.packageName_);
        }
    }
}

bool AdminManager::HasPermissionToHandlePolicy(std::shared_ptr<Admin> admin, const std::string &policyName)
{
    if (admin->GetAdminType() != AdminType::VIRTUAL_ADMIN) {
        return true;
    }
    auto policies = admin->adminInfo_.accessiblePolicies_;
    return std::find(policies.begin(), policies.end(), policyName) != policies.end();
}

std::shared_ptr<Admin> AdminManager::GetSuperAdmin()
{
    if (admins_.find(EdmConstants::DEFAULT_USER_ID) != admins_.end()) {
        auto item = std::find_if(admins_[EdmConstants::DEFAULT_USER_ID].begin(),
            admins_[EdmConstants::DEFAULT_USER_ID].end(),
            [&](const std::shared_ptr<Admin>& admin) { return admin->GetAdminType() == AdminType::ENT; });
        if (item != admins_[EdmConstants::DEFAULT_USER_ID].end()) {
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
