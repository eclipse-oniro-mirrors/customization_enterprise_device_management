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

#include "admin_container.h"
#include "directory_ex.h"
#include "edm_constants.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<AdminManager> AdminManager::instance_;
std::once_flag AdminManager::flag_;
const std::string POLICY_ALLOW_ALL = "allow_all";

std::shared_ptr<AdminManager> AdminManager::GetInstance()
{
    std::call_once(flag_, []() {
        if (instance_ == nullptr) {
            instance_.reset(new (std::nothrow) AdminManager());
        }
    });
    IAdminManager::adminManagerInstance_ = instance_.get();
    return instance_;
}

AdminManager::AdminManager()
{
    EDMLOGI("AdminManager::AdminManager");
}

AdminManager::~AdminManager()
{
    EDMLOGI("AdminManager::~AdminManager");
}

bool AdminManager::GetAdminByUserId(int32_t userId, std::vector<std::shared_ptr<Admin>> &userAdmin)
{
    return AdminContainer::GetInstance()->GetAdminCopyByUserId(userId, userAdmin);
}

void AdminManager::GetAdminBySubscribeEvent(ManagedEvent event,
    std::unordered_map<int32_t, std::vector<std::shared_ptr<Admin>>> &subscribeAdmins)
{
    return AdminContainer::GetInstance()->GetAdminCopyBySubscribeEvent(event, subscribeAdmins);
}

ErrCode AdminManager::SetAdminValue(int32_t userId, const AdminInfo &adminItem)
{
    std::shared_ptr<Admin> getAdmin = GetAdminByPkgName(adminItem.packageName_, userId);
    if (getAdmin != nullptr) {
        return UpdateAdmin(userId, adminItem,
            CLASS_NAME | ENTI_NFO | PERMISSION | ACCESSIBLE_POLICIES | RUNNING_MODE);
    }
    auto adminPoliciesStorageRdb = AdminPoliciesStorageRdb::GetInstance();
    if (adminPoliciesStorageRdb == nullptr) {
        EDMLOGE("AdminManager::SetAdminValue get adminPoliciesStorageRdb failed.");
        return ERR_GET_STORAGE_RDB_FAILED;
    }
    if (!adminPoliciesStorageRdb->InsertAdmin(userId, adminItem)) {
        EDMLOGE("AdminManager::SetAdminValue insert failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    AdminContainer::GetInstance()->SetAdminByUserId(userId, adminItem);
    for (auto observer : adminObservers_) {
        observer->OnAdminAdd(adminItem.packageName_, userId, adminItem.isDebug_);
    }
    return ERR_OK;
}

std::shared_ptr<Admin> AdminManager::GetAdminByPkgName(const std::string &packageName, int32_t userId)
{
    std::shared_ptr<Admin> subOrSuperOrByodAdmin;
    if (userId != EdmConstants::DEFAULT_USER_ID &&
        SUCCEEDED(GetAllowedAcrossAccountSetPolicyAdmin(packageName, subOrSuperOrByodAdmin))) {
        EDMLOGD("GetAdminByPkgName::get sub-super or super or byod admin: %{public}s", packageName.c_str());
        return subOrSuperOrByodAdmin;
    }
    std::vector<std::shared_ptr<Admin>> userAdmin;
    if (!GetAdminByUserId(userId, userAdmin)) {
        EDMLOGW("GetAdminByPkgName::get userId Admin failed.");
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

ErrCode AdminManager::DeleteAdmin(const std::string &packageName, int32_t userId, AdminType adminType)
{
    if (!AdminContainer::GetInstance()->HasAdmin(userId)) {
        EDMLOGW("DeleteAdmin::get userId Admin failed.");
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
    AdminContainer::GetInstance()->DeleteAdmin(packageName, userId);
    for (auto observer : adminObservers_) {
        observer->OnAdminRemove(packageName, userId, adminType);
    }
    return ERR_OK;
}

ErrCode AdminManager::UpdateAdmin(int32_t userId, const AdminInfo &adminItem, uint32_t code)
{
    auto adminPoliciesStorageRdb = AdminPoliciesStorageRdb::GetInstance();
    if (adminPoliciesStorageRdb == nullptr) {
        EDMLOGE("AdminManager::UpdateAdmin get adminPoliciesStorageRdb failed.");
        return ERR_GET_STORAGE_RDB_FAILED;
    }
    if (!adminPoliciesStorageRdb->UpdateAdmin(userId, adminItem)) {
        EDMLOGW("UpdateAdmin::update admin failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    AdminContainer::GetInstance()->UpdateAdmin(userId, adminItem.packageName_, code, adminItem);
    return ERR_OK;
}

ErrCode AdminManager::UpdateAdminPermission(const std::string &bundleName, int32_t userId,
    std::vector<std::string> permissionList)
{
    AdminInfo adminInfo = {.packageName_ = bundleName, .permission_ = permissionList};
    return UpdateAdmin(userId, adminInfo, PERMISSION);
}

ErrCode AdminManager::ReplaceSuperAdminByPackageName(const std::string &packageName, const AdminInfo &newAdminInfo)
{
    auto adminPoliciesStorageRdb = AdminPoliciesStorageRdb::GetInstance();
    if (adminPoliciesStorageRdb == nullptr) {
        EDMLOGE("AdminManager::ReplaceSuperAdminByAdmin get adminPoliciesStorageRdb failed.");
        return ERR_GET_STORAGE_RDB_FAILED;
    }
    std::vector<std::string> subAdmins;
    GetSubSuperAdminsByParentName(packageName, subAdmins);
    for (const auto& subAdmin : subAdmins) {
        if (!adminPoliciesStorageRdb->UpdateParentName(subAdmin, packageName,
            newAdminInfo.packageName_)) {
            EDMLOGE("AdminManager::ReplaceSuperAdminByPackageName UpdateParentName failed.");
            return ERR_SET_PARENT_ADMIN_FAILED;
        }
    }

    if (!adminPoliciesStorageRdb->ReplaceAdmin(packageName, EdmConstants::DEFAULT_USER_ID, newAdminInfo)) {
        EDMLOGW("ReplaceSuperAdminByPackageName::update admin failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }

    AdminContainer::GetInstance()->UpdateAdmin(EdmConstants::DEFAULT_USER_ID, packageName,
        PACKAGE_NAME | CLASS_NAME, newAdminInfo);
    AdminContainer::GetInstance()->UpdateParentAdminName(EdmConstants::DEFAULT_USER_ID, packageName,
        newAdminInfo.packageName_);

    for (auto observer : adminObservers_) {
        observer->OnAdminAdd(newAdminInfo.packageName_, EdmConstants::DEFAULT_USER_ID, false);
        observer->OnAdminRemove(packageName, EdmConstants::DEFAULT_USER_ID, AdminType::ENT);
    }
    return ERR_OK;
}

// success is returned as long as there is a super administrator
bool AdminManager::IsSuperAdminExist()
{
    std::vector<std::shared_ptr<Admin>> userAdmin;
    bool ret = GetAdminByUserId(EdmConstants::DEFAULT_USER_ID, userAdmin);
    if (!ret) {
        EDMLOGD("IsSuperAdminExist::not find byod or super Admin");
        return false;
    }
    return std::any_of(userAdmin.begin(), userAdmin.end(),
        [](const std::shared_ptr<Admin> &admin) {
            return admin->adminInfo_.adminType_ == AdminType::ENT && !admin->adminInfo_.isDebug_;
        });
}

bool AdminManager::IsByodAdminExist()
{
    std::vector<std::shared_ptr<Admin>> userAdmin;
    bool ret = GetAdminByUserId(EdmConstants::DEFAULT_USER_ID, userAdmin);
    if (!ret) {
        EDMLOGD("IsByodAdminExist::not find byod or super Admin");
        return false;
    }
    return std::any_of(userAdmin.begin(), userAdmin.end(),
        [](const std::shared_ptr<Admin> &admin) {
            return admin->adminInfo_.adminType_ == AdminType::BYOD;
        });
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
    return AdminContainer::GetInstance()->IsAdminExist();
}

bool AdminManager::IsByodAdmin(const std::string &bundleName, int32_t userId)
{
    std::shared_ptr<Admin> admin = GetAdminByPkgName(bundleName, userId);
    if (admin == nullptr) {
        EDMLOGW("IsByodAdmin: admin == nullptr.");
        return false;
    }
    if (admin->adminInfo_.adminType_ == AdminType::BYOD) {
        EDMLOGI("IsByodAdmin: admin is BYOD.");
        return true;
    }
    return false;
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
        EDMLOGW("GetEnabledAdmin::not find enabled Admin.");
        return;
    }
    EDMLOGD("AdminManager:GetEnabledAdmin adminType: %{public}d , admin size: %{public}zu", role, userAdmin.size());
    if (static_cast<int32_t>(role) > static_cast<int32_t>(AdminType::BYOD) ||
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

ErrCode AdminManager::GetAllowedAcrossAccountSetPolicyAdmin(const std::string &subAdminName,
    std::shared_ptr<Admin> &subOrSuperOrByodAdmin)
{
    std::vector<std::shared_ptr<Admin>> userAdmin;
    if (!GetAdminByUserId(EdmConstants::DEFAULT_USER_ID, userAdmin)) {
        EDMLOGW("GetAllowedAcrossAccountSetPolicyAdmin::not find Admin under default user id");
        return ERR_EDM_SUPER_ADMIN_NOT_FOUND;
    }
    auto adminItem = std::find_if(userAdmin.begin(), userAdmin.end(), [&](const std::shared_ptr<Admin> &admin) {
        return admin->adminInfo_.packageName_ == subAdminName && admin->IsAllowedAcrossAccountSetPolicy();
    });
    if (adminItem == userAdmin.end()) {
        EDMLOGW("GetAllowedAcrossAccountSetPolicyAdmin::not find sub-super admin or super or byod Admin");
        return ERR_EDM_SUPER_ADMIN_NOT_FOUND;
    }
    subOrSuperOrByodAdmin = *adminItem;
    return ERR_OK;
}

void AdminManager::GetAdmins(std::vector<std::shared_ptr<Admin>> &admins, int32_t currentUserId)
{
    std::vector<std::shared_ptr<Admin>> defaultUserAdmins;
    std::vector<std::shared_ptr<Admin>> currentUserAdmins;
    GetAdminByUserId(EdmConstants::DEFAULT_USER_ID, defaultUserAdmins);
    
    if (currentUserId == EdmConstants::DEFAULT_USER_ID) {
        // 如果是默认用户，返回所有 ENT, BYOD 和 NORMAL 类型
        std::copy_if(defaultUserAdmins.begin(), defaultUserAdmins.end(), std::back_inserter(admins),
            [&](std::shared_ptr<Admin> admin) {
            return admin->adminInfo_.adminType_ == AdminType::ENT ||
                admin->adminInfo_.adminType_ == AdminType::BYOD ||
                admin->adminInfo_.adminType_ == AdminType::NORMAL;
        });
    } else {
        GetAdminByUserId(currentUserId, currentUserAdmins);
        
        // 从默认用户中筛选 ENT 和 NORMAL 类型
        std::copy_if(defaultUserAdmins.begin(), defaultUserAdmins.end(),
            std::back_inserter(admins), [&](std::shared_ptr<Admin> admin) {
            return admin->adminInfo_.adminType_ == AdminType::ENT ||
                admin->adminInfo_.adminType_ == AdminType::NORMAL;
        });
        
        // 从当前用户中筛选 BYOD 类型
        std::copy_if(currentUserAdmins.begin(), currentUserAdmins.end(),
            std::back_inserter(admins), [&](std::shared_ptr<Admin> admin) {
            return admin->adminInfo_.adminType_ == AdminType::BYOD;
        });
    }
}

std::vector<std::string> AdminManager::GetDisallowedCrossAccountAdmins(int userId)
{
    std::vector<std::shared_ptr<Admin>> userAdmins;
    AdminManager::GetInstance()->GetAdminByUserId(userId, userAdmins);
    std::vector<std::string> bundleNames;
    for (const auto& adminPtr : userAdmins) {
        if (adminPtr != nullptr && !adminPtr->IsAllowedAcrossAccountSetPolicy()) {
            bundleNames.push_back(adminPtr->adminInfo_.packageName_);
        }
    }
    return bundleNames;
}

void AdminManager::Register(std::shared_ptr<IAdminObserver> observer)
{
    if (observer != nullptr) {
        adminObservers_.push_back(observer);
    }
}

void AdminManager::GetSubSuperAdmins(int32_t userId, std::vector<std::shared_ptr<Admin>> &subAdmins)
{
    if (subAdmins.size() > 0) {
        subAdmins.clear();
    }
    std::vector<std::shared_ptr<Admin>> userAdmin;
    if (!GetAdminByUserId(userId, userAdmin)) {
        EDMLOGE("GetSubSuperAdmins::not find Admin under user id = %{public}d", userId);
        return;
    }
    for (const auto &admin : userAdmin) {
        if (admin->GetAdminType() == AdminType::SUB_SUPER_ADMIN) {
            subAdmins.push_back(admin);
        }
    }
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

ErrCode AdminManager::SetEntInfo(std::shared_ptr<Admin> admin, const EntInfo &entInfo, int32_t userId)
{
    auto adminPoliciesStorageRdb = AdminPoliciesStorageRdb::GetInstance();
    if (adminPoliciesStorageRdb == nullptr) {
        EDMLOGE("AdminManager::SetEntInfo get adminPoliciesStorageRdb failed.");
        return ERR_GET_STORAGE_RDB_FAILED;
    }
    if (adminPoliciesStorageRdb->UpdateEntInfo(userId, admin->adminInfo_.packageName_, entInfo)) {
        AdminInfo adminInfo = {.entInfo_ = entInfo};
        AdminContainer::GetInstance()->UpdateAdmin(userId, admin->adminInfo_.packageName_, ENTI_NFO, adminInfo);
        return ERR_OK;
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
        return ERR_EDM_UNKNOWN_ADMIN;
    }
    AdminContainer::GetInstance()->UpdateAdmin(userId, admin->adminInfo_.packageName_, MANAGED_EVENTS,
        admin->adminInfo_);
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

    size_t eventsNumber = admin->adminInfo_.managedEvents_.size();
    auto iter = std::remove_if(admin->adminInfo_.managedEvents_.begin(), admin->adminInfo_.managedEvents_.end(),
        [&](ManagedEvent managedEvent) {
            return std::find(events.begin(), events.end(), static_cast<uint32_t>(managedEvent)) != events.end();
        });
    admin->adminInfo_.managedEvents_.erase(iter, admin->adminInfo_.managedEvents_.end());

    if (admin->adminInfo_.managedEvents_.size() < eventsNumber &&
        !adminPoliciesStorageRdb->UpdateManagedEvents(userId, admin->adminInfo_.packageName_,
            admin->adminInfo_.managedEvents_)) {
        return ERR_EDM_UNKNOWN_ADMIN;
    }
    AdminContainer::GetInstance()->UpdateAdmin(userId, admin->adminInfo_.packageName_, MANAGED_EVENTS,
        admin->adminInfo_);
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

std::shared_ptr<Admin> AdminManager::GetSuperAdmin()
{
    std::vector<std::shared_ptr<Admin>> userAdmin;
    if (AdminContainer::GetInstance()->GetAdminCopyByUserId(EdmConstants::DEFAULT_USER_ID, userAdmin)) {
        auto item = std::find_if(userAdmin.begin(), userAdmin.end(),
            [&](const std::shared_ptr<Admin>& admin) { return admin->GetAdminType() == AdminType::ENT; });
        if (item != userAdmin.end()) {
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
        AdminContainer::GetInstance()->InitAdmins(adminPoliciesStorageRdb->QueryAllAdmin());
    } else {
        EDMLOGE("AdminManager::Init failed.");
    }
}

void AdminManager::Dump()
{
    AdminContainer::GetInstance()->Dump();
}

void AdminManager::ClearAdmins()
{
    AdminContainer::GetInstance()->ClearAdmins();
}

void AdminManager::InsertAdmins(int32_t userId, std::vector<std::shared_ptr<Admin>> admins)
{
    AdminContainer::GetInstance()->InsertAdmins(userId, admins);
}

bool AdminManager::IsExistTargetAdmin(bool isDebug)
{
    return AdminContainer::GetInstance()->IsExistTargetAdmin(isDebug);
}

int32_t AdminManager::GetSuperDeviceAdminAndDeviceAdminCount()
{
    return AdminContainer::GetInstance()->GetSuperDeviceAdminAndDeviceAdminCount();
}

AdminType AdminManager::GetAdminTypeByName(const std::string &bundleName, int32_t userId)
{
    std::shared_ptr<Admin> admin = GetAdminByPkgName(bundleName, userId);
    if (admin == nullptr) {
        EDMLOGE("AdminManager::GetAdminTypeByName get admin failed.");
        return AdminType::UNKNOWN;
    }
    return admin->adminInfo_.adminType_;
}

bool AdminManager::IsExistTargetAdmin(bool isDebug, int32_t userId)
{
    std::vector<std::shared_ptr<Admin>> admins;
    GetAdminByUserId(EdmConstants::DEFAULT_USER_ID, admins);
    if (userId == EdmConstants::DEFAULT_USER_ID) {
        auto defaultUserIter = std::find_if(admins.begin(), admins.end(), [&](std::shared_ptr<Admin> admin) {
            return admin != nullptr && admin->adminInfo_.isDebug_ == isDebug;
        });
        return defaultUserIter != admins.end();
    }
    auto acrossUserIter = std::find_if(admins.begin(), admins.end(), [&](std::shared_ptr<Admin> admin) {
        return admin != nullptr && admin->IsAllowedAcrossAccountSetPolicy() && admin->adminInfo_.isDebug_ == isDebug;
    });
    if (acrossUserIter != admins.end()) {
        return true;
    }
    GetAdminByUserId(userId, admins);
    auto currentUserIter = std::find_if(admins.begin(), admins.end(), [&](std::shared_ptr<Admin> admin) {
        return admin != nullptr && admin->adminInfo_.isDebug_ == isDebug;
    });
    return currentUserIter != admins.end();
}
} // namespace EDM
} // namespace OHOS
