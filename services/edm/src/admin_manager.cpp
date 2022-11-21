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
#include "edm_log.h"
#include "permission_manager.h"
#include "super_admin.h"

namespace OHOS {
namespace EDM {
const std::string EDM_ADMIN_DOT = ".";
const std::string EDM_ADMIN_BASE = "/data/service/el1/public/edm/";
const std::string EDM_ADMIN_JSON_FILE = "admin_policies_";
const std::string EDM_ADMIN_JSON_EXT = ".json";
constexpr int32_t DEFAULT_USER_ID = 100;
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
        if (subAdmin.size() > 0) {
            subscribeAdmins[adminItem.first] = subAdmin;
        }
    }
}

ErrCode AdminManager::SetAdminValue(AppExecFwk::ExtensionAbilityInfo &abilityInfo, EntInfo &entInfo, AdminType role,
    std::vector<std::string> &permissions, int32_t userId)
{
    std::vector<AdminPermission> reqPermission;
    std::vector<std::string> permissionNames;
    std::vector<std::shared_ptr<Admin>> admin;
    PermissionManager::GetInstance()->GetReqPermission(permissions, reqPermission);
    if (reqPermission.empty()) {
        EDMLOGW("SetAdminValue::the application is requesting useless permissions");
    }
    for (const auto &it : reqPermission) {
        if (role == AdminType::NORMAL && it.adminType == AdminType::ENT) {
            return ERR_EDM_DENY_PERMISSION;
        }
        permissionNames.push_back(it.permissionName);
    }

    bool ret = GetAdminByUserId(userId, admin);
    std::shared_ptr<Admin> adminItem = GetAdminByPkgName(abilityInfo.bundleName, userId);
    if (role == AdminType::NORMAL) {
        admin.emplace_back(std::make_shared<Admin>());
    } else {
        admin.emplace_back(std::make_shared<SuperAdmin>());
    }
    if (!ret) {
        admins_.insert(std::pair<int32_t, std::vector<std::shared_ptr<Admin>>>(userId, admin));
        adminItem = admin.back();
    } else if (ret && !adminItem) {
        admins_[userId] = admin;
        adminItem = admin.back();
    }
    adminItem->adminInfo_.adminType_ = role;
    adminItem->adminInfo_.entInfo_ = entInfo;
    adminItem->adminInfo_.permission_ = permissionNames;
    adminItem->adminInfo_.packageName_ = abilityInfo.bundleName;
    adminItem->adminInfo_.className_ = abilityInfo.name;
    SaveAdmin(userId);
    return ERR_OK;
}

std::shared_ptr<Admin> AdminManager::GetAdminByPkgName(const std::string &packageName, int32_t userId)
{
    std::vector<std::shared_ptr<Admin>> userAdmin;
    bool ret = GetAdminByUserId(userId, userAdmin);
    if (!ret) {
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
    ErrCode retCode = ERR_EDM_UNKNOWN_ADMIN;
    auto iterMap = admins_.find(userId);
    if (iterMap == admins_.end()) {
        EDMLOGW("DeleteAdmin::get userId Admin failed. userId = %{public}d", userId);
        return retCode;
    }

    auto iter = (iterMap->second).begin();
    while (iter != (iterMap->second).end()) {
        if ((*iter)->adminInfo_.packageName_ == packageName) {
            iter = (iterMap->second).erase(iter);
            retCode = ERR_OK;
        } else {
            iter++;
        }
    }
    if (SUCCEEDED(retCode)) {
        EDMLOGD("SaveAdmin %{public}s", packageName.c_str());
        SaveAdmin(userId);
        return retCode;
    }

    EDMLOGW("delete admin (%{public}s) failed!", packageName.c_str());
    return ERR_EDM_UNKNOWN_ADMIN;
}

ErrCode AdminManager::GetGrantedPermission(AppExecFwk::ExtensionAbilityInfo& abilityInfo,
    std::vector<std::string>& permissions, AdminType type)
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

    std::vector<std::string> combinePermission = permissions;
    ErrCode ret = GetGrantedPermission(abilityInfo, combinePermission, adminItem->adminInfo_.adminType_);
    if (ret != ERR_OK) {
        EDMLOGW("UpdateAdmin::GetGrantedPermission failed");
        return ret;
    }

    adminItem->adminInfo_.permission_ = combinePermission;
    adminItem->adminInfo_.packageName_ = abilityInfo.bundleName;
    adminItem->adminInfo_.className_ = abilityInfo.name;
    SaveAdmin(userId);
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
    std::shared_ptr<Admin> superAdmin;
    superAdmin = GetAdminByPkgName(bundleName, DEFAULT_USER_ID);
    if (superAdmin == nullptr) {
        return false;
    }
    return superAdmin->adminInfo_.adminType_ == AdminType::ENT;
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
    EDMLOGD("AdminManager:GetEnabledAdmin adminType: %{public}d , admin size: %{public}zu", role,
        userAdmin.size());
    if (role >= AdminType::UNKNOWN || role < AdminType::NORMAL) {
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
    for (auto &item : userAdmin) {
        if (item->adminInfo_.packageName_ == packageName) {
            item->adminInfo_.entInfo_ = entInfo;
            SaveAdmin(userId);
            return ERR_OK;
        }
    }
    return ERR_EDM_UNKNOWN_ADMIN;
}

void AdminManager::SaveSubscribeEvents(const std::vector<uint32_t> &events,
    std::shared_ptr<Admin> &admin, int32_t userId)
{
    size_t eventsNumber = admin->adminInfo_.managedEvents_.size();
    for (auto &event : events) {
        std::vector<ManagedEvent> managedEvents = admin->adminInfo_.managedEvents_;
        ManagedEvent subEvent = static_cast<ManagedEvent>(event);
        if (std::find(managedEvents.begin(), managedEvents.end(), subEvent) == managedEvents.end()) {
            admin->adminInfo_.managedEvents_.push_back(subEvent);
        }
    }
    if (admin->adminInfo_.managedEvents_.size() > eventsNumber) {
        SaveAdmin(userId);
    }
}

void AdminManager::RemoveSubscribeEvents(const std::vector<uint32_t> &events,
    std::shared_ptr<Admin> &admin, int32_t userId)
{
    size_t eventsNumber = admin->adminInfo_.managedEvents_.size();
    for (auto &event : events) {
        auto iter = admin->adminInfo_.managedEvents_.begin();
        while (iter != admin->adminInfo_.managedEvents_.end()) {
            if (*iter == static_cast<ManagedEvent>(event)) {
                iter = admin->adminInfo_.managedEvents_.erase(iter);
            } else {
                ++iter;
            }
        }
    }
    if (admin->adminInfo_.managedEvents_.size() < eventsNumber) {
        SaveAdmin(userId);
    }
}
// init
void AdminManager::Init()
{
    RestoreAdminFromFile();
}

void FindPackageAndClass(const std::string &name, std::string &packageName, std::string &className)
{
    std::size_t initPos = name.find('/', 0);
    std::size_t len = name.size();
    packageName = name.substr(0, initPos);
    className = name.substr(initPos + 1, len - (initPos + 1));
}

void AdminManager::ReadJsonAdminType(Json::Value &admin,
    std::vector<std::shared_ptr<Admin>> &adminVector)
{
    std::shared_ptr<Admin> enabledAdmin;
    if (admin["adminType"].asUInt() == AdminType::NORMAL) {
        enabledAdmin = std::make_shared<Admin>();
    } else if (admin["adminType"].asUInt() == AdminType::ENT) {
        enabledAdmin = std::make_shared<SuperAdmin>();
    } else {
        EDMLOGD("admin type is error!");
        return;
    }

    FindPackageAndClass(admin["name"].asString(), enabledAdmin->adminInfo_.packageName_,
        enabledAdmin->adminInfo_.className_);
    enabledAdmin->adminInfo_.adminType_ = static_cast<AdminType>(admin["adminType"].asUInt());
    enabledAdmin->adminInfo_.entInfo_.enterpriseName = admin["enterpriseInfo"]["enterpriseName"].asString(); // object
    enabledAdmin->adminInfo_.entInfo_.description = admin["enterpriseInfo"]["declaration"].asString();
    uint32_t adminSize = admin["permission"].size();
    for (uint32_t i = 0; i < adminSize; i++) {
        enabledAdmin->adminInfo_.permission_.push_back(admin["permission"][i].asString()); // array
    }
    uint32_t eventsSize = admin["subscribeEvents"].size();
    for (uint32_t i = 0; i < eventsSize; i++) {
        enabledAdmin->adminInfo_.managedEvents_.push_back(
            static_cast<ManagedEvent>(admin["subscribeEvents"][i].asUInt()));
    }

    // read admin and store it in vector container
    adminVector.push_back(enabledAdmin);
}

void AdminManager::ReadJsonAdmin(const std::string &filePath, int32_t userId)
{
    std::ifstream is(filePath);
    JSONCPP_STRING errs;
    Json::Value root, lang;
    Json::CharReaderBuilder readerBuilder;
    std::vector<std::shared_ptr<Admin>> adminVector;

    if (!is.is_open()) {
        EDMLOGE("ReadJsonAdmin open admin policies file failed!");
        return;
    }
    bool res = parseFromStream(readerBuilder, is, &root, &errs);
    if (!res || !errs.empty()) {
        // no data, return
        EDMLOGW("AdminManager::read admin policies file = %{public}d , is not empty = %{public}d", res, errs.empty());
        is.close();
        return;
    }
    is.close();

    lang = root["admin"];
    EDMLOGD("AdminManager::size = %{public}u", lang.size());

    for (auto &temp : lang) {
        ReadJsonAdminType(temp, adminVector);
    }
    // not empty
    if (!(adminVector.empty())) {
        admins_.insert(std::pair<int32_t, std::vector<std::shared_ptr<Admin>>>(userId, adminVector));
    }
    EDMLOGI("AdminManager::ReadJsonAdmin empty = %{public}d", adminVector.empty());
}

// read admin from file
void AdminManager::RestoreAdminFromFile()
{
    std::vector<std::string> paths;
    OHOS::GetDirFiles(EDM_ADMIN_BASE, paths);
    for (size_t i = 0; i < paths.size(); i++) {
        std::string::size_type pos = paths[i].find(EDM_ADMIN_DOT);
        std::string::size_type posHead = paths[i].find(EDM_ADMIN_JSON_FILE);
        if (pos == std::string::npos || posHead == std::string::npos) {
            continue;
        }
        size_t start = (EDM_ADMIN_BASE + EDM_ADMIN_JSON_FILE).length();
        std::string user = paths[i].substr(start, (pos - start));
        if (!std::all_of(user.begin(), user.end(), ::isdigit)) {
            continue;
        }
        // Indicates 0 user, and other user ID is 100
        if ((std::stoi(user)) < DEFAULT_USER_ID) {
            continue;
        }
        std::string path = EDM_ADMIN_BASE + EDM_ADMIN_JSON_FILE + user +
            EDM_ADMIN_JSON_EXT;
        // admin information storage location
        ReadJsonAdmin(path, (std::stoi(user)));
    }
    EDMLOGD("RestoreAdminFromFile success! size = %{public}zu", paths.size());
}

void AdminManager::WriteJsonAdminType(std::shared_ptr<Admin> &enabledAdmin, Json::Value &tree)
{
    Json::Value entTree;
    Json::Value permissionTree;
    Json::Value eventsTree;

    tree["name"] = enabledAdmin->adminInfo_.packageName_ + "/" + enabledAdmin->adminInfo_.className_;
    tree["adminType"] = enabledAdmin->adminInfo_.adminType_;

    entTree["enterpriseName"] = enabledAdmin->adminInfo_.entInfo_.enterpriseName;
    entTree["declaration"] = enabledAdmin->adminInfo_.entInfo_.description;
    tree["enterpriseInfo"] = entTree;

    for (auto &it : enabledAdmin->adminInfo_.permission_) {
        permissionTree.append(it);
    }
    tree["permission"] = permissionTree;

    for (auto &it : enabledAdmin->adminInfo_.managedEvents_) {
        eventsTree.append(static_cast<uint32_t>(it));
    }
    tree["subscribeEvents"] = eventsTree;
}

void AdminManager::WriteJsonAdmin(const std::string &filePath, int32_t userId)
{
    Json::Value root, tree, temp;

    auto iterMap = admins_.find(userId);
    if (iterMap == admins_.end()) {
        EDMLOGW("WriteJsonAdmin::not find Admin. userId = %{public}d", userId);
        return;
    }
    EDMLOGD("WriteJsonAdmin start!  size = %{public}u  empty = %{public}d", (uint32_t)(iterMap->second).size(),
        (iterMap->second).empty());
    // structure of each admin
    for (std::uint32_t i = 0; i < (iterMap->second).size(); i++) {
        WriteJsonAdminType((iterMap->second).at(i), temp);
        tree.append(temp);
    }
    // root
    root["admin"] = tree;

    double time1 = clock();
    // write to file
    std::ofstream ofs(filePath);
    if (!ofs.is_open()) {
        EDMLOGE("WriteJsonAdmin open admin policies file failed!");
        return;
    }

    Json::StreamWriterBuilder builder;
    builder["indentation"] = "    ";
    const std::unique_ptr<Json::StreamWriter> writer(builder.newStreamWriter());
    writer->write(root, &ofs);
    ofs.flush();
    ofs.close();
    double time2 = clock();
    if (time1 != 0 && time2 != 0) {
        EDMLOGD("WriteJsonAdmin spend time %{public}f", (time2 - time1) / CLOCKS_PER_SEC);
    }
    if (!ChangeModeFile(filePath, S_IRUSR | S_IWUSR)) {
        EDMLOGW("AdminManager::ChangeModeFile failed");
    }
    if ((iterMap->second).empty()) {
        admins_.erase(iterMap);
        // delete current userId file
        bool delFlag = OHOS::RemoveFile(filePath);
        EDMLOGD("WriteJsonAdmin delete userId = %{public}d map value; delFlag = %{public}d",
            userId, delFlag);
    }
}

// write admin to file
void AdminManager::SaveAdmin(int32_t userId)
{
    std::string path = EDM_ADMIN_BASE + EDM_ADMIN_JSON_FILE + std::to_string(userId) +
        EDM_ADMIN_JSON_EXT;
    WriteJsonAdmin(path, userId);
}
} // namespace EDM
} // namespace OHOS
