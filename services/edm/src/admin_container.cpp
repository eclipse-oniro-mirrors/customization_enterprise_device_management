/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "admin_container.h"

#include "byod_admin.h"
#include "device_admin.h"
#include "sub_super_device_admin.h"
#include "super_device_admin.h"
#include "virtual_device_admin.h"
#include "edm_constants.h"
#include "edm_log.h"
 
namespace OHOS {
namespace EDM {

using ReadLock = std::shared_lock<std::shared_mutex>;
using WriteLock = std::unique_lock<std::shared_mutex>;

std::shared_ptr<AdminContainer> AdminContainer::GetInstance()
{
    static std::shared_ptr<AdminContainer> instance = std::make_shared<AdminContainer>();
    return instance;
}

AdminContainer::AdminContainer()
{
    EDMLOGI("AdminContainer::AdminContainer");
}

AdminContainer::~AdminContainer()
{
    EDMLOGI("AdminContainer::~AdminContainer");
    admins_.clear();
}

void AdminContainer::SetAdminByUserId(int32_t userId, const AdminInfo &adminItem)
{
    WriteLock lock(adminMutex_);
    std::vector<std::shared_ptr<Admin>> userAdmin;
    GetAdminByUserId(userId, userAdmin);

    std::shared_ptr<Admin> admin = CreateAdmin(adminItem);
    if (admin != nullptr) {
        userAdmin.emplace_back(admin);
        admins_[userId] = userAdmin;
    } else {
        EDMLOGE("SetAdminByUserId::failed to create admin for accountID.");
    }
}

bool AdminContainer::DeleteAdmin(const std::string &packageName, int32_t userId)
{
    WriteLock lock(adminMutex_);
    auto iterMap = admins_.find(userId);
    if (iterMap == admins_.end()) {
        EDMLOGI("DeleteAdmin::get userId Admin failed.");
        return false;
    }

    auto iter = std::remove_if(iterMap->second.begin(), iterMap->second.end(),
        [&](std::shared_ptr<Admin> admin) { return admin->adminInfo_.packageName_ == packageName; });
    iterMap->second.erase(iter, iterMap->second.end());
    if (iterMap->second.empty()) {
        admins_.erase(iterMap);
    }
    return true;
}

bool AdminContainer::GetAdminCopyByUserId(int32_t userId, std::vector<std::shared_ptr<Admin>> &admins)
{
    ReadLock lock(adminMutex_);
    admins.clear();
    auto iter = admins_.find(userId);
    if (iter == admins_.end()) {
        EDMLOGW("GetAdminCopyByUserId::get userId Admin failed.");
        return false;
    }
    for (const auto &item : iter->second) {
        auto admin = CreateAdmin(item->adminInfo_);
        if (admin != nullptr) {
            admins.emplace_back(admin);
        }
    }
    return true;
}

void AdminContainer::GetAdminCopyBySubscribeEvent(ManagedEvent event,
    std::unordered_map<int32_t, std::vector<std::shared_ptr<Admin>>> &subscribeAdmins)
{
    ReadLock lock(adminMutex_);
    for (const auto &adminItem : admins_) {
        std::vector<std::shared_ptr<Admin>> subAdmin;
        for (const auto &it : adminItem.second) {
            std::vector<ManagedEvent> events = it->adminInfo_.managedEvents_;
            if (std::find(events.begin(), events.end(), event) == events.end()) {
                continue;
            }
            auto admin = CreateAdmin(it->adminInfo_);
            if (admin != nullptr) {
                subAdmin.push_back(admin);
            }
        }
        if (!subAdmin.empty()) {
            subscribeAdmins[adminItem.first] = subAdmin;
        }
    }
}

bool AdminContainer::GetAdminByUserId(int32_t userId, std::vector<std::shared_ptr<Admin>> &userAdmin)
{
    userAdmin.clear();
    auto iter = admins_.find(userId);
    if (iter == admins_.end()) {
        EDMLOGW("GetAdminByUserId::get userId Admin failed.");
        return false;
    }
    userAdmin = iter->second;
    return true;
}

bool AdminContainer::HasAdmin(int32_t userId)
{
    ReadLock lock(adminMutex_);
    auto iter = admins_.find(userId);
    if (iter == admins_.end()) {
        return false;
    }
    return true;
}

bool AdminContainer::IsAdminExist()
{
    ReadLock lock(adminMutex_);
    return !admins_.empty();
}

void AdminContainer::UpdateAdmin(int32_t userId, const std::string &packageName, uint32_t updateCode,
    const AdminInfo &adminInfo)
{
    WriteLock lock(adminMutex_);
    std::vector<std::shared_ptr<Admin>> userAdmin;
    if (!GetAdminByUserId(userId, userAdmin)) {
        EDMLOGW("UpdateAdmin::get userId Admin failed.");
        return;
    }
    for (const auto &item : userAdmin) {
        if (item->adminInfo_.packageName_ == packageName) {
            if (updateCode & PACKAGE_NAME) {
                item->adminInfo_.packageName_ = adminInfo.packageName_;
            }
            if (updateCode & CLASS_NAME) {
                item->adminInfo_.className_ = adminInfo.className_;
            }
            if (updateCode & ENTI_NFO) {
                item->adminInfo_.entInfo_ = adminInfo.entInfo_;
            }
            if (updateCode & PERMISSION) {
                item->adminInfo_.permission_ = adminInfo.permission_;
            }
            if (updateCode & MANAGED_EVENTS) {
                item->adminInfo_.managedEvents_ = adminInfo.managedEvents_;
            }
            if (updateCode & PARENT_ADMIN_NAME) {
                item->adminInfo_.parentAdminName_ = adminInfo.parentAdminName_;
            }
            if (updateCode & ACCESSIBLE_POLICIES) {
                item->adminInfo_.accessiblePolicies_ = adminInfo.accessiblePolicies_;
            }
            if (updateCode & ADMIN_TYPE) {
                item->adminInfo_.adminType_ = adminInfo.adminType_;
            }
            if (updateCode & IS_DEBUG) {
                item->adminInfo_.isDebug_ = adminInfo.isDebug_;
            }
            if (updateCode & RUNNING_MODE) {
                item->adminInfo_.runningMode_ = adminInfo.runningMode_;
            }
        }
    }
    return;
}

void AdminContainer::UpdateParentAdminName(int32_t userId, const std::string &parentAdminName,
    const std::string &updateName)
{
    WriteLock lock(adminMutex_);
    std::vector<std::shared_ptr<Admin>> userAdmin;
    if (!GetAdminByUserId(userId, userAdmin)) {
        EDMLOGW("UpdateParentAdminName::get userId Admin failed.");
        return;
    }

    for (const auto &admin : userAdmin) {
        if ((admin->GetAdminType() == AdminType::SUB_SUPER_ADMIN ||
            admin->GetAdminType() == AdminType::VIRTUAL_ADMIN) &&
            admin->adminInfo_.parentAdminName_ == parentAdminName) {
            admin->adminInfo_.parentAdminName_ = updateName;
        }
    }
}

void AdminContainer::InitAdmins(std::unordered_map<int32_t, std::vector<AdminInfo>> adminInfos)
{
    WriteLock lock(adminMutex_);
    for (const auto &entry : adminInfos) {
        EDMLOGI("AdminContainer::Dump %{public}d.", entry.first);
        auto &itemList = admins_[entry.first];
        itemList.clear();
        for (const auto &adminInfo : entry.second) {
            auto admin = CreateAdmin(adminInfo);
            if (admin != nullptr) {
                itemList.push_back(admin);
            }
        }
    }
}

void AdminContainer::Dump()
{
    ReadLock lock(adminMutex_);
    for (const auto &entry : admins_) {
        EDMLOGI("AdminContainer::Dump %{public}d.", entry.first);
        for (const auto &admin : entry.second) {
            EDMLOGI("AdminContainer::Dump admin info adminType_ %{public}d.",
                admin->adminInfo_.adminType_);
            EDMLOGI("AdminContainer::Dump admin info packageName_ %{public}s.",
                admin->adminInfo_.packageName_.c_str());
            EDMLOGI("AdminContainer::Dump admin info parentAdminName_ %{public}s.",
                admin->adminInfo_.parentAdminName_.c_str());
        }
    }
}

void AdminContainer::ClearAdmins()
{
    WriteLock lock(adminMutex_);
    admins_.clear();
}

void AdminContainer::InsertAdmins(int32_t userId, std::vector<std::shared_ptr<Admin>> admins)
{
    WriteLock lock(adminMutex_);
    admins_[userId] = admins;
}

std::shared_ptr<Admin> AdminContainer::CreateAdmin(const AdminInfo &adminInfo)
{
    switch (adminInfo.adminType_) {
        case AdminType::ENT:
            return std::make_shared<SuperDeviceAdmin>(adminInfo);
        case AdminType::NORMAL:
            return std::make_shared<DeviceAdmin>(adminInfo);
        case AdminType::BYOD:
            return std::make_shared<ByodAdmin>(adminInfo);
        case AdminType::VIRTUAL_ADMIN:
            return std::make_shared<VirtualDeviceAdmin>(adminInfo);
        case AdminType::SUB_SUPER_ADMIN:
            return std::make_shared<SubSuperDeviceAdmin>(adminInfo);
        default:
            return nullptr;
    }
}

bool AdminContainer::IsExistTargetAdmin(bool isDebug)
{
    ReadLock lock(adminMutex_);
    return std::any_of(admins_.begin(), admins_.end(), [&](const auto &entry) {
        return std::any_of(entry.second.begin(), entry.second.end(), [&](auto item) {
            return item->adminInfo_.isDebug_ == isDebug;
        });
    });
}

int32_t AdminContainer::GetSuperDeviceAdminAndDeviceAdminCount()
{
    ReadLock lock(adminMutex_);
    int32_t count = 0;
    if (admins_.find(EdmConstants::DEFAULT_USER_ID) == admins_.end()) {
        return count;
    }
    for (const auto &item : admins_[EdmConstants::DEFAULT_USER_ID]) {
        if (item->adminInfo_.adminType_ == AdminType::ENT || item->adminInfo_.adminType_ == AdminType::NORMAL) {
            count++;
        }
    }
    return count;
}
} // namespace EDM
} // namespace OHOS