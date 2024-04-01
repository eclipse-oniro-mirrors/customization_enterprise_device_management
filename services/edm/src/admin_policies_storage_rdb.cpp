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

#include "admin_policies_storage_rdb.h"

#include "edm_constants.h"
#include "edm_log.h"
#include "edm_rdb_filed_const.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<AdminPoliciesStorageRdb> AdminPoliciesStorageRdb::instance_ = nullptr;
std::mutex AdminPoliciesStorageRdb::mutexLock_;

AdminPoliciesStorageRdb::AdminPoliciesStorageRdb()
{
    EDMLOGD("AdminPoliciesStorageRdb::create database.");
    std::string createTableSql = "CREATE TABLE IF NOT EXISTS ";
    createTableSql.append(EdmRdbFiledConst::ADMIN_POLICIES_RDB_TABLE_NAME + " (")
        .append(EdmRdbFiledConst::FILED_ID + " INTEGER PRIMARY KEY AUTOINCREMENT,")
        .append(EdmRdbFiledConst::FILED_USER_ID + " INTEGER NOT NULL,")
        .append(EdmRdbFiledConst::FILED_ADMIN_TYPE + " INTEGER NOT NULL,")
        .append(EdmRdbFiledConst::FILED_PACKAGE_NAME + " TEXT NOT NULL,")
        .append(EdmRdbFiledConst::FILED_CLASS_NAME + " TEXT NOT NULL,")
        .append(EdmRdbFiledConst::FILED_ENT_NAME + " TEXT,")
        .append(EdmRdbFiledConst::FILED_ENT_DESC + " TEXT,")
        .append(EdmRdbFiledConst::FILED_PERMISSIONS + " TEXT,")
        .append(EdmRdbFiledConst::FILED_SUBSCRIBE_EVENTS + " TEXT,")
        .append(EdmRdbFiledConst::FILED_PARENT_ADMIN + " TEXT,")
        .append(EdmRdbFiledConst::FILED_IS_DEBUG + " TEXT);");
    auto edmRdbDataManager = EdmRdbDataManager::GetInstance();
    if (edmRdbDataManager != nullptr) {
        edmRdbDataManager->CreateTable(createTableSql);
    } else {
        EDMLOGE("AdminPoliciesStorageRdb::create database admin_policies failed.");
    }
}

std::shared_ptr<AdminPoliciesStorageRdb> AdminPoliciesStorageRdb::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutexLock_);
        if (instance_ == nullptr) {
            instance_ = std::make_shared<AdminPoliciesStorageRdb>();
        }
    }
    return instance_;
}

bool AdminPoliciesStorageRdb::InsertAdmin(int32_t userId, const Admin &admin)
{
    EDMLOGD("AdminPoliciesStorageRdb::Insert data start.");
    auto edmRdbDataManager = EdmRdbDataManager::GetInstance();
    if (edmRdbDataManager == nullptr) {
        EDMLOGE("AdminPoliciesStorageRdb::InsertAdmin get edmRdbDataManager failed.");
        return false;
    }
    // insert into admin_policies(user_id, admin_type, package_name, class_name, ent_name, ent_desc, permissions,
    //     is_debug) values(?, ?, ?, ?, ?, ?, ?)
    return edmRdbDataManager->Insert(EdmRdbFiledConst::ADMIN_POLICIES_RDB_TABLE_NAME,
        CreateValuesBucket(userId, admin));
}

bool AdminPoliciesStorageRdb::UpdateAdmin(int32_t userId, const Admin &admin)
{
    EDMLOGD("AdminPoliciesStorageRdb::Insert data start.");
    auto edmRdbDataManager = EdmRdbDataManager::GetInstance();
    if (edmRdbDataManager == nullptr) {
        EDMLOGE("AdminPoliciesStorageRdb::UpdateAdmin get edmRdbDataManager failed.");
        return false;
    }
    // update admin_policies set user_id=?, admin_type=?, package_name=?, class_name=?, ent_name=?, ent_desc=?,
    //     permissions=? where user_id=? and package_name=?
    NativeRdb::AbsRdbPredicates predicates(EdmRdbFiledConst::ADMIN_POLICIES_RDB_TABLE_NAME);
    predicates.EqualTo(EdmRdbFiledConst::FILED_USER_ID, std::to_string(userId));
    predicates.EqualTo(EdmRdbFiledConst::FILED_PACKAGE_NAME, admin.adminInfo_.packageName_);
    return edmRdbDataManager->Update(CreateValuesBucket(userId, admin), predicates);
}

NativeRdb::ValuesBucket AdminPoliciesStorageRdb::CreateValuesBucket(int32_t userId, const Admin &admin)
{
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutInt(EdmRdbFiledConst::FILED_USER_ID, userId);
    valuesBucket.PutInt(EdmRdbFiledConst::FILED_ADMIN_TYPE, static_cast<int>(admin.adminInfo_.adminType_));
    valuesBucket.PutString(EdmRdbFiledConst::FILED_PACKAGE_NAME, admin.adminInfo_.packageName_);
    valuesBucket.PutString(EdmRdbFiledConst::FILED_CLASS_NAME, admin.adminInfo_.className_);
    valuesBucket.PutString(EdmRdbFiledConst::FILED_ENT_NAME, admin.adminInfo_.entInfo_.enterpriseName);
    valuesBucket.PutString(EdmRdbFiledConst::FILED_ENT_DESC, admin.adminInfo_.entInfo_.description);

    if (!admin.adminInfo_.permission_.empty()) {
        Json::StreamWriterBuilder builder;
        builder.settings_["indentation"] = "";
        Json::Value permissionJson;
        for (const auto &it : admin.adminInfo_.permission_) {
            permissionJson.append(it);
        }
        valuesBucket.PutString(EdmRdbFiledConst::FILED_PERMISSIONS, Json::writeString(builder, permissionJson));
    }
    valuesBucket.PutBool(EdmRdbFiledConst::FILED_IS_DEBUG, admin.adminInfo_.isDebug_);
    return valuesBucket;
}

bool AdminPoliciesStorageRdb::DeleteAdmin(int32_t userId, const std::string &packageName)
{
    EDMLOGD("AdminPoliciesStorageRdb::DeleteAdmin.");
    auto edmRdbDataManager = EdmRdbDataManager::GetInstance();
    if (edmRdbDataManager == nullptr) {
        EDMLOGE("AdminPoliciesStorageRdb::DeleteAdmin get edmRdbDataManager failed.");
        return false;
    }
    // delete from admin_policies where user_id=? and package_name=?
    NativeRdb::AbsRdbPredicates predicates(EdmRdbFiledConst::ADMIN_POLICIES_RDB_TABLE_NAME);
    predicates.EqualTo(EdmRdbFiledConst::FILED_USER_ID, std::to_string(userId));
    predicates.EqualTo(EdmRdbFiledConst::FILED_PACKAGE_NAME, packageName);
    return edmRdbDataManager->Delete(predicates);
}

bool AdminPoliciesStorageRdb::UpdateAdmin(int32_t userId, const std::string &packageName, const std::string &className,
    const std::vector<std::string> &permissions)
{
    EDMLOGD("AdminPoliciesStorageRdb::UpdateAdmin.");
    auto edmRdbDataManager = EdmRdbDataManager::GetInstance();
    if (edmRdbDataManager == nullptr) {
        EDMLOGE("AdminPoliciesStorageRdb::UpdateAdmin get edmRdbDataManager failed.");
        return false;
    }
    // update admin_policies set package_name=?, class_name=?, permissions=? where user_id=? and package_name=?
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(EdmRdbFiledConst::FILED_PACKAGE_NAME, packageName);
    valuesBucket.PutString(EdmRdbFiledConst::FILED_CLASS_NAME, className);

    Json::StreamWriterBuilder builder;
    builder.settings_["indentation"] = "";
    Json::Value permissionJson;
    for (const auto &it : permissions) {
        permissionJson.append(it);
    }
    valuesBucket.PutString(EdmRdbFiledConst::FILED_PERMISSIONS, Json::writeString(builder, permissionJson));

    NativeRdb::AbsRdbPredicates predicates(EdmRdbFiledConst::ADMIN_POLICIES_RDB_TABLE_NAME);
    predicates.EqualTo(EdmRdbFiledConst::FILED_USER_ID, std::to_string(userId));
    predicates.EqualTo(EdmRdbFiledConst::FILED_PACKAGE_NAME, packageName);
    return edmRdbDataManager->Update(valuesBucket, predicates);
}

bool AdminPoliciesStorageRdb::UpdateEntInfo(int32_t userId, const std::string &packageName, const EntInfo &entInfo)
{
    EDMLOGD("AdminPoliciesStorageRdb::UpdateEntInfo.");
    auto edmRdbDataManager = EdmRdbDataManager::GetInstance();
    if (edmRdbDataManager == nullptr) {
        EDMLOGE("AdminPoliciesStorageRdb::UpdateEntInfo get edmRdbDataManager failed.");
        return false;
    }
    // update admin_policies set ent_name=?, ent_desc=? where user_id=? and package_name=?
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(EdmRdbFiledConst::FILED_ENT_NAME, entInfo.enterpriseName);
    valuesBucket.PutString(EdmRdbFiledConst::FILED_ENT_DESC, entInfo.description);

    NativeRdb::AbsRdbPredicates predicates(EdmRdbFiledConst::ADMIN_POLICIES_RDB_TABLE_NAME);
    predicates.EqualTo(EdmRdbFiledConst::FILED_USER_ID, std::to_string(userId));
    predicates.EqualTo(EdmRdbFiledConst::FILED_PACKAGE_NAME, packageName);
    return edmRdbDataManager->Update(valuesBucket, predicates);
}

bool AdminPoliciesStorageRdb::UpdateManagedEvents(int32_t userId, const std::string &packageName,
    const std::vector<ManagedEvent> &managedEvents)
{
    EDMLOGD("AdminPoliciesStorageRdb::UpdateManagedEvents.");
    auto edmRdbDataManager = EdmRdbDataManager::GetInstance();
    if (edmRdbDataManager == nullptr) {
        EDMLOGE("AdminPoliciesStorageRdb::UpdateManagedEvents get edmRdbDataManager failed.");
        return false;
    }
    // update admin_policies set subscribe_events=? where user_id=? and package_name=?
    NativeRdb::ValuesBucket valuesBucket;
    Json::StreamWriterBuilder builder;
    builder.settings_["indentation"] = "";
    Json::Value managedEventsJson;
    for (const auto &it : managedEvents) {
        managedEventsJson.append(static_cast<uint32_t>(it));
    }
    valuesBucket.PutString(EdmRdbFiledConst::FILED_SUBSCRIBE_EVENTS, Json::writeString(builder, managedEventsJson));

    NativeRdb::AbsRdbPredicates predicates(EdmRdbFiledConst::ADMIN_POLICIES_RDB_TABLE_NAME);
    predicates.EqualTo(EdmRdbFiledConst::FILED_USER_ID, std::to_string(userId));
    predicates.EqualTo(EdmRdbFiledConst::FILED_PACKAGE_NAME, packageName);
    return edmRdbDataManager->Update(valuesBucket, predicates);
}

std::unordered_map<int32_t, std::vector<std::shared_ptr<Admin>>> AdminPoliciesStorageRdb::QueryAllAdmin()
{
    EDMLOGD("AdminPoliciesStorageRdb::QueryAllAdmin.");
    auto edmRdbDataManager = EdmRdbDataManager::GetInstance();
    std::unordered_map<int32_t, std::vector<std::shared_ptr<Admin>>> admins;
    if (edmRdbDataManager == nullptr) {
        EDMLOGE("AdminPoliciesStorageRdb::QueryAllAdmin get edmRdbDataManager failed.");
        return admins;
    }
    // select * from admin_policies
    NativeRdb::AbsRdbPredicates predicates(EdmRdbFiledConst::ADMIN_POLICIES_RDB_TABLE_NAME);
    auto resultSet = edmRdbDataManager->Query(predicates, std::vector<std::string>());
    if (resultSet == nullptr) {
        return admins;
    }
    int resultSetNum = resultSet->GoToFirstRow();
    while (resultSetNum == NativeRdb::E_OK) {
        std::shared_ptr<Admin> item = std::make_shared<Admin>();
        int32_t userId = 0;
        resultSet->GetInt(EdmRdbFiledConst::FILED_COLUMN_INDEX_ONE, userId);
        SetAdminItems(resultSet, item);
        if (admins.find(userId) != admins.end()) {
            admins[userId].push_back(item);
        } else {
            std::vector<std::shared_ptr<Admin>> adminItems{item};
            admins[userId] = adminItems;
        }
        resultSetNum = resultSet->GoToNextRow();
    }
    resultSet->Close();
    return admins;
}

void AdminPoliciesStorageRdb::SetAdminItems(std::shared_ptr<NativeRdb::ResultSet> resultSet,
    std::shared_ptr<Admin> item)
{
    if (item == nullptr) {
        EDMLOGE("AdminPoliciesStorageRdb::SetAdminItems failed.");
        return;
    }
    int32_t adminType = 0;
    resultSet->GetInt(EdmRdbFiledConst::FILED_COLUMN_INDEX_TWO, adminType);
    item->adminInfo_.adminType_ = static_cast<AdminType>(adminType);
    resultSet->GetString(EdmRdbFiledConst::FILED_COLUMN_INDEX_THREE, item->adminInfo_.packageName_);
    resultSet->GetString(EdmRdbFiledConst::FILED_COLUMN_INDEX_FOUR, item->adminInfo_.className_);
    resultSet->GetString(EdmRdbFiledConst::FILED_COLUMN_INDEX_FIVE, item->adminInfo_.entInfo_.enterpriseName);
    resultSet->GetString(EdmRdbFiledConst::FILED_COLUMN_INDEX_SIX, item->adminInfo_.entInfo_.description);
    std::string permissionStr;
    resultSet->GetString(EdmRdbFiledConst::FILED_COLUMN_INDEX_SEVEN, permissionStr);
    if (!permissionStr.empty() && permissionStr != "null") {
        Json::Value permissionJson;
        ConvertStrToJson(permissionStr, permissionJson);
        for (uint32_t i = 0; i < permissionJson.size(); i++) {
            if (permissionJson[i].isString()) {
                item->adminInfo_.permission_.push_back(permissionJson[i].asString());
            }
        }
    }
    std::string managedEventsStr;
    resultSet->GetString(EdmRdbFiledConst::FILED_COLUMN_INDEX_EIGHT, managedEventsStr);
    if (!managedEventsStr.empty() && managedEventsStr != "null") {
        Json::Value managedEventsJson;
        ConvertStrToJson(managedEventsStr, managedEventsJson);
        for (uint32_t i = 0; i < managedEventsJson.size(); i++) {
            if (managedEventsJson[i].isUInt()) {
                item->adminInfo_.managedEvents_.push_back(static_cast<ManagedEvent>(managedEventsJson[i].asUInt()));
            }
        }
    }
    resultSet->GetString(EdmRdbFiledConst::FILED_COLUMN_INDEX_NINE, item->adminInfo_.parentAdminName_);
    int isDebug = 0;
    resultSet->GetInt(EdmRdbFiledConst::FILED_COLUMN_INDEX_TEN, isDebug);
    item->adminInfo_.isDebug_ = isDebug != 0;
}

void AdminPoliciesStorageRdb::ConvertStrToJson(const std::string &str, Json::Value &json)
{
    Json::String err;
    Json::CharReaderBuilder builder;
    std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    reader->parse(str.c_str(), str.c_str() + str.length(), &json, &err);
}

bool AdminPoliciesStorageRdb::InsertAuthorizedAdmin(const std::string &bundleName,
    const std::vector<std::string> &permissions, const std::string &parentName)
{
    EDMLOGD("AdminPoliciesStorageRdb::InsertAuthorizedAdmin.");
    // insert into admin_policies(user_id, admin_type, package_name, class_name, permissions, parent_admin)
    //    values(?, ?, ?, ?, ?, ?)
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutInt(EdmRdbFiledConst::FILED_USER_ID, EdmConstants::DEFAULT_USER_ID);
    valuesBucket.PutInt(EdmRdbFiledConst::FILED_ADMIN_TYPE, static_cast<int32_t>(AdminType::SUB_SUPER_ADMIN));
    valuesBucket.PutString(EdmRdbFiledConst::FILED_PACKAGE_NAME, bundleName);
    valuesBucket.PutString(EdmRdbFiledConst::FILED_CLASS_NAME, "");
    Json::StreamWriterBuilder builder;
    builder.settings_["indentation"] = "";
    Json::Value permissionJson;
    for (const auto &permission : permissions) {
        permissionJson.append(permission);
    }
    valuesBucket.PutString(EdmRdbFiledConst::FILED_PERMISSIONS, Json::writeString(builder, permissionJson));
    valuesBucket.PutString(EdmRdbFiledConst::FILED_PARENT_ADMIN, parentName);
    return EdmRdbDataManager::GetInstance()->Insert(EdmRdbFiledConst::ADMIN_POLICIES_RDB_TABLE_NAME, valuesBucket);
}

bool AdminPoliciesStorageRdb::UpdateAuthorizedAdmin(const std::string &bundleName,
    const std::vector<std::string> &permissions, const std::string &parentName)
{
    EDMLOGD("AdminPoliciesStorageRdb::SaveAuthorizedAdmin.");
    // update admin_policies set permissions=? where user_id=100 and package_name=? and parent_name=?
    NativeRdb::ValuesBucket valuesBucket;
    Json::StreamWriterBuilder builder;
    builder.settings_["indentation"] = "";
    Json::Value permissionJson;
    for (const auto &permission : permissions) {
        permissionJson.append(permission);
    }
    valuesBucket.PutString(EdmRdbFiledConst::FILED_PERMISSIONS, Json::writeString(builder, permissionJson));

    NativeRdb::AbsRdbPredicates predicates(EdmRdbFiledConst::ADMIN_POLICIES_RDB_TABLE_NAME);
    predicates.EqualTo(EdmRdbFiledConst::FILED_USER_ID, std::to_string(EdmConstants::DEFAULT_USER_ID));
    predicates.EqualTo(EdmRdbFiledConst::FILED_PACKAGE_NAME, bundleName);
    predicates.EqualTo(EdmRdbFiledConst::FILED_PARENT_ADMIN, parentName);
    return EdmRdbDataManager::GetInstance()->Update(valuesBucket, predicates);
}
} // namespace EDM
} // namespace OHOS