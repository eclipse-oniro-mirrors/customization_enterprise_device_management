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
#include "edm_log.h"
#include "permission_manager.h"
#include "super_admin.h"

namespace OHOS {
namespace EDM {
const std::string EDM_ADMIN_JSON_FILE = "/data/system/admin_policies.json";
std::shared_ptr<AdminManager> AdminManager::instance_;
std::mutex AdminManager::mutexLock_;

std::shared_ptr<AdminManager> AdminManager::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> autoLock(mutexLock_);
        if (instance_ == nullptr) {
            instance_.reset(new AdminManager());
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

ErrCode AdminManager::SetAdminValue(AppExecFwk::AbilityInfo &abilityInfo, EntInfo &entInfo, AdminType role,
    std::vector<std::string> &permissions)
{
    std::vector<AdminPermission> reqPermission;
    std::vector<std::string> permissionNames;
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

    std::shared_ptr<Admin> adminItem = GetAdminByPkgName(abilityInfo.bundleName);
    if (adminItem == nullptr) {
        if (role == NORMAL) {
            admins_.emplace_back(std::make_shared<Admin>());
        } else {
            admins_.emplace_back(std::make_shared<SuperAdmin>());
        }
        adminItem = admins_.back();
    }
    adminItem->adminInfo_.adminType_ = role;
    adminItem->adminInfo_.entInfo_ = entInfo;
    adminItem->adminInfo_.permission_ = permissionNames;
    adminItem->adminInfo_.packageName_ = abilityInfo.bundleName;
    adminItem->adminInfo_.className_ = abilityInfo.name;
    SaveAdmin();
    return ERR_OK;
}

void AdminManager::GetAllAdmin(std::vector<std::shared_ptr<Admin>> &allAdmin)
{
    allAdmin = admins_;
}

std::shared_ptr<Admin> AdminManager::GetAdminByPkgName(const std::string &packageName)
{
    for (auto &item : admins_) {
        if (item->adminInfo_.packageName_ == packageName) {
            return item;
        }
    }
    EDMLOGD("GetAdminByPkgName:get admin failed. admin size= %{public}u, packageName= %{public}s",
        (uint32_t)admins_.size(), packageName.c_str());
    return nullptr;
}

ErrCode AdminManager::DeleteAdmin(const std::string &packageName)
{
    ErrCode retCode;
    auto iter = admins_.begin();
    while (iter != admins_.end()) {
        if ((*iter)->adminInfo_.packageName_ == packageName) {
            iter = admins_.erase(iter);
            retCode = ERR_OK;
        } else {
            iter++;
        }
    }
    if (SUCCEEDED(retCode)) {
        EDMLOGD("SaveAdmin %{public}s", packageName.c_str());
        SaveAdmin();
        return retCode;
    }

    EDMLOGW("delete admin (%{public}s) failed!", packageName.c_str());
    return ERR_EDM_UNKNOWN_ADMIN;
}

ErrCode AdminManager::GetGrantedPermission(AppExecFwk::AbilityInfo &abilityInfo, std::vector<std::string> &permissions,
    AdminType type)
{
    if (permissions.empty()) {
        EDMLOGW("GetGrantedPermission: permissions is empty");
        return ERR_OK;
    }
    // filtering out non-edm permissions
    std::vector<AdminPermission> reqPermission;
    PermissionManager::GetInstance()->GetReqPermission(permissions, reqPermission);
    if (reqPermission.empty()) {
        EDMLOGW("GetGrantedPermission: edm permission is empty");
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

ErrCode AdminManager::UpdateAdmin(AppExecFwk::AbilityInfo &abilityInfo, const std::vector<std::string> &permissions)
{
    auto adminItem = GetAdminByPkgName(abilityInfo.bundleName);
    if (adminItem == nullptr) {
        EDMLOGW("UpdateAdmin: get null admin, never get here");
        return ERR_EDM_UNKNOWN_ADMIN;
    }

    std::vector<std::string> combinePermission = permissions;
    ErrCode ret = GetGrantedPermission(abilityInfo, combinePermission, adminItem->adminInfo_.adminType_);
    if (ret != ERR_OK) {
        EDMLOGW("UpdateAdmin: GetGrantedPermission failed");
        return ret;
    }

    adminItem->adminInfo_.permission_ = combinePermission;
    adminItem->adminInfo_.packageName_ = abilityInfo.bundleName;
    adminItem->adminInfo_.className_ = abilityInfo.className;
    SaveAdmin();
    return ERR_OK;
}

// success is returned as long as there is a super administrator
bool AdminManager::IsSuperAdminExist()
{
    return std::any_of(admins_.begin(), admins_.end(),
        [](const std::shared_ptr<Admin> &admin) { return admin->adminInfo_.adminType_ == AdminType::ENT; });
}

/*
 * There are different administrator types according to the input parameters.
 * Returns a list of package names
 */
void AdminManager::GetActiveAdmin(AdminType role, std::vector<std::string> &packageNameList)
{
    EDMLOGD("AdminManager:GetActiveAdmin adminType: %{public}d , admin size: %{public}zu", role, admins_.size());
    packageNameList.clear();
    if (role >= AdminType::UNKNOWN || role < AdminType::NORMAL) {
        EDMLOGD("there is no admin(%{public}u) device manager package name list!", role);
        return;
    }

    for (auto &item : admins_) {
        if (item->adminInfo_.adminType_ == role) {
            std::string adminName = item->adminInfo_.packageName_ + "/" + item->adminInfo_.className_;
            packageNameList.push_back(adminName);
        }
    }
}

ErrCode AdminManager::GetEntInfo(const std::string &packageName, EntInfo &entInfo)
{
    for (auto &item : admins_) {
        if (item->adminInfo_.packageName_ == packageName) {
            entInfo = item->adminInfo_.entInfo_;
            return ERR_OK;
        }
    }
    return ERR_EDM_UNKNOWN_ADMIN;
}

ErrCode AdminManager::SetEntInfo(const std::string &packageName, EntInfo &entInfo)
{
    for (auto &item : admins_) {
        if (item->adminInfo_.packageName_ == packageName) {
            item->adminInfo_.entInfo_ = entInfo;
            SaveAdmin();
            return ERR_OK;
        }
    }
    return ERR_EDM_UNKNOWN_ADMIN;
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

void AdminManager::ReadJsonAdminType(Json::Value &admin)
{
    std::shared_ptr<Admin> activeAdmin;
    if (admin["adminType"].asUInt() == AdminType::NORMAL) {
        activeAdmin = std::make_shared<Admin>();
    } else if (admin["adminType"].asUInt() == AdminType::ENT) {
        activeAdmin = std::make_shared<SuperAdmin>();
    } else {
        EDMLOGD("admin type is error!");
        return;
    }

    FindPackageAndClass(admin["name"].asString(), activeAdmin->adminInfo_.packageName_,
        activeAdmin->adminInfo_.className_);
    activeAdmin->adminInfo_.adminType_ = static_cast<AdminType>(admin["adminType"].asUInt());
    activeAdmin->adminInfo_.entInfo_.enterpriseName = admin["enterpriseInfo"]["enterpriseName"].asString(); // object
    activeAdmin->adminInfo_.entInfo_.description = admin["enterpriseInfo"]["declaration"].asString();
    unsigned int adminSize = admin["permission"].size();
    for (unsigned int i = 0; i < adminSize; i++) {
        activeAdmin->adminInfo_.permission_.push_back(admin["permission"][i].asString()); // array
    }

    // read admin and store it in vector container
    admins_.push_back(activeAdmin);
}

void AdminManager::ReadJsonAdmin(const std::string &filePath)
{
    std::ifstream is(filePath);
    JSONCPP_STRING errs;
    Json::Value root, lang;
    Json::CharReaderBuilder readerBuilder;

    if (!is.is_open()) {
        EDMLOGE("ReadJsonAdmin open admin policies file failed!");
        return;
    }
    bool res = parseFromStream(readerBuilder, is, &root, &errs);
    if (!res || !errs.empty()) {
        // no data, return
        EDMLOGW("AdminManager:read admin policies file is :%{public}d , is not empty: %{public}d", res, errs.empty());
        is.close();
        return;
    }
    is.close();

    lang = root["admin"];
    EDMLOGD("AdminManager: size of %{public}u", lang.size());

    for (auto temp : lang) {
        ReadJsonAdminType(temp);
    }
}

// read admin from file
void AdminManager::RestoreAdminFromFile()
{
    // admin information storage location
    ReadJsonAdmin(EDM_ADMIN_JSON_FILE);
}

void AdminManager::WriteJsonAdminType(std::shared_ptr<Admin> &activeAdmin, Json::Value &tree)
{
    Json::Value entTree;
    Json::Value permissionTree;

    tree["name"] = activeAdmin->adminInfo_.packageName_ + "/" + activeAdmin->adminInfo_.className_;
    tree["adminType"] = activeAdmin->adminInfo_.adminType_;

    entTree["enterpriseName"] = activeAdmin->adminInfo_.entInfo_.enterpriseName;
    entTree["declaration"] = activeAdmin->adminInfo_.entInfo_.description;
    tree["enterpriseInfo"] = entTree;

    for (auto &it : activeAdmin->adminInfo_.permission_) {
        permissionTree.append(it);
    }
    tree["permission"] = permissionTree;
}

void AdminManager::WriteJsonAdmin(const std::string &filePath)
{
    Json::Value root, tree, temp;

    EDMLOGD("WriteJsonAdmin start!  size = %{public}u  empty = %{public}d", (uint32_t)admins_.size(), admins_.empty());
    // structure of each admin
    for (std::uint32_t i = 0; i < admins_.size(); i++) {
        WriteJsonAdminType(admins_.at(i), temp);
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
}

// write admin to file
void AdminManager::SaveAdmin()
{
    WriteJsonAdmin(EDM_ADMIN_JSON_FILE);
}
} // namespace EDM
} // namespace OHOS
