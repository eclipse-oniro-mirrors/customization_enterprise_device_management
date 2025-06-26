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

#include "cjson_check.h"
#include "edm_constants.h"
#include "edm_log.h"
#include "edm_rdb_filed_const.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<AdminPoliciesStorageRdb> AdminPoliciesStorageRdb::instance_ = nullptr;
std::once_flag AdminPoliciesStorageRdb::flag_;
bool AdminPoliciesStorageRdb::isAdminPoliciesTableInit_ = false;

AdminPoliciesStorageRdb::AdminPoliciesStorageRdb()
{
    EDMLOGD("AdminPoliciesStorageRdb::create database.");
}

bool AdminPoliciesStorageRdb::CreateAdminPoliciesTable()
{
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
        .append(EdmRdbFiledConst::FILED_IS_DEBUG + " INTEGER,")
        .append(EdmRdbFiledConst::FILED_ACCESSIBLE_POLICIES + " TEXT,")
        .append(EdmRdbFiledConst::FILED_RUNNING_MODE + " INTEGER);");
    auto edmRdbDataManager = EdmRdbDataManager::GetInstance();
    if (edmRdbDataManager != nullptr) {
        return edmRdbDataManager->CreateTable(createTableSql);
    }
    EDMLOGE("AdminPoliciesStorageRdb::create database admin_policies failed.");
    return false;
}

std::shared_ptr<AdminPoliciesStorageRdb> AdminPoliciesStorageRdb::GetInstance()
{
    if (!isAdminPoliciesTableInit_) {
        isAdminPoliciesTableInit_ = CreateAdminPoliciesTable();
    }
    if (!isAdminPoliciesTableInit_) {
        return nullptr;
    }
    std::call_once(flag_, []() {
        if (instance_ == nullptr) {
            instance_ = std::make_shared<AdminPoliciesStorageRdb>();
        }
    });
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
    //     parent_admin, is_debug, accessible_policies) values(?, ?, ?, ?, ?, ?, ?, ?, ?)
    return edmRdbDataManager->Insert(EdmRdbFiledConst::ADMIN_POLICIES_RDB_TABLE_NAME,
        CreateInsertValuesBucket(userId, admin));
}

bool AdminPoliciesStorageRdb::UpdateAdmin(int32_t userId, const Admin &admin)
{
    EDMLOGD("AdminPoliciesStorageRdb::Insert data start.");
    auto edmRdbDataManager = EdmRdbDataManager::GetInstance();
    if (edmRdbDataManager == nullptr) {
        EDMLOGE("AdminPoliciesStorageRdb::UpdateAdmin get edmRdbDataManager failed.");
        return false;
    }
    // update admin_policies set admin_type=?, ent_name=?, ent_desc=?, permissions=?, accessible_policies=?
    //     where user_id=? and package_name=?
    NativeRdb::AbsRdbPredicates predicates(EdmRdbFiledConst::ADMIN_POLICIES_RDB_TABLE_NAME);
    predicates.EqualTo(EdmRdbFiledConst::FILED_USER_ID, std::to_string(userId));
    predicates.EqualTo(EdmRdbFiledConst::FILED_PACKAGE_NAME, admin.adminInfo_.packageName_);
    NativeRdb::ValuesBucket valuesBucket;
    CreateUpdateValuesBucket(userId, admin, valuesBucket);
    return edmRdbDataManager->Update(valuesBucket, predicates);
}

bool AdminPoliciesStorageRdb::ReplaceAdmin(const std::string packageName, int32_t userId, const Admin &newAdmin)
{
    EDMLOGD("AdminPoliciesStorageRdb::ReplaceAdmin data start.");
    auto edmRdbDataManager = EdmRdbDataManager::GetInstance();
    if (edmRdbDataManager == nullptr) {
        EDMLOGE("AdminPoliciesStorageRdb::UpdateAdmin get edmRdbDataManager failed.");
        return false;
    }
    // update admin_policies set package_name=?, permissions=? where user_id=? and package_name=?
    NativeRdb::AbsRdbPredicates predicates(EdmRdbFiledConst::ADMIN_POLICIES_RDB_TABLE_NAME);
    predicates.EqualTo(EdmRdbFiledConst::FILED_USER_ID, std::to_string(userId));
    predicates.EqualTo(EdmRdbFiledConst::FILED_PACKAGE_NAME, packageName);
    return edmRdbDataManager->Update(CreateInsertValuesBucket(userId, newAdmin), predicates);
}

bool AdminPoliciesStorageRdb::UpdateParentName(const std::string packageName, const std::string currentParentName,
    const std::string targetParentName)
{
    EDMLOGD("AdminPoliciesStorageRdb::UpdateParentName data start.");
    auto edmRdbDataManager = EdmRdbDataManager::GetInstance();
    if (edmRdbDataManager == nullptr) {
        EDMLOGE("AdminPoliciesStorageRdb::UpdateParentName get edmRdbDataManager failed.");
        return false;
    }
    // update admin_policies set ParentName=? where packageName=? and ParentName=?
    NativeRdb::AbsRdbPredicates predicates(EdmRdbFiledConst::ADMIN_POLICIES_RDB_TABLE_NAME);
    predicates.EqualTo(EdmRdbFiledConst::FILED_PARENT_ADMIN, currentParentName);
    predicates.EqualTo(EdmRdbFiledConst::FILED_PACKAGE_NAME, packageName);
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(EdmRdbFiledConst::FILED_PARENT_ADMIN, targetParentName);
    return edmRdbDataManager->Update(valuesBucket, predicates);
}

NativeRdb::ValuesBucket AdminPoliciesStorageRdb::CreateInsertValuesBucket(int32_t userId, const Admin &admin)
{
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutInt(EdmRdbFiledConst::FILED_RUNNING_MODE, static_cast<int>(admin.adminInfo_.runningMode_));
    CreateUpdateValuesBucket(userId, admin, valuesBucket);
    valuesBucket.PutInt(EdmRdbFiledConst::FILED_USER_ID, userId);
    valuesBucket.PutString(EdmRdbFiledConst::FILED_PACKAGE_NAME, admin.adminInfo_.packageName_);
    valuesBucket.PutString(EdmRdbFiledConst::FILED_CLASS_NAME, admin.adminInfo_.className_);
    valuesBucket.PutString(EdmRdbFiledConst::FILED_PARENT_ADMIN, admin.adminInfo_.parentAdminName_);
    valuesBucket.PutBool(EdmRdbFiledConst::FILED_IS_DEBUG, admin.adminInfo_.isDebug_);
    return valuesBucket;
}

void AdminPoliciesStorageRdb::CreateUpdateValuesBucket(int32_t userId, const Admin &admin,
    NativeRdb::ValuesBucket &valuesBucket)
{
    valuesBucket.PutInt(EdmRdbFiledConst::FILED_ADMIN_TYPE, static_cast<int>(admin.adminInfo_.adminType_));

    if (!admin.adminInfo_.entInfo_.enterpriseName.empty()) {
        valuesBucket.PutString(EdmRdbFiledConst::FILED_ENT_NAME, admin.adminInfo_.entInfo_.enterpriseName);
    }

    if (!admin.adminInfo_.entInfo_.description.empty()) {
        valuesBucket.PutString(EdmRdbFiledConst::FILED_ENT_DESC, admin.adminInfo_.entInfo_.description);
    }

    cJSON *permissionsArray = nullptr;
    CJSON_CREATE_ARRAY_AND_CHECK_VOID(permissionsArray);
    for (const auto &permission : admin.adminInfo_.permission_) {
        cJSON* itemJson = cJSON_CreateString(permission.c_str());
        if (itemJson == nullptr) {
            cJSON_Delete(permissionsArray);
            return;
        }
        CJSON_ADD_ITEM_TO_ARRAY_AND_CHECK_AND_CLEAR_VOID(itemJson, permissionsArray);
    }
    char *permissionsStr = cJSON_PrintUnformatted(permissionsArray);
    if (permissionsStr != nullptr) {
        valuesBucket.PutString(EdmRdbFiledConst::FILED_PERMISSIONS, permissionsStr);
        free(permissionsStr);
    }
    cJSON_Delete(permissionsArray);

    if (admin.adminInfo_.adminType_ == AdminType::VIRTUAL_ADMIN) {
        cJSON *policiesArray = nullptr;
        CJSON_CREATE_ARRAY_AND_CHECK_VOID(permissionsArray);
        for (const auto &policy : admin.adminInfo_.accessiblePolicies_) {
            cJSON* itemJson = cJSON_CreateString(policy.c_str());
            if (itemJson == nullptr) {
                cJSON_Delete(policiesArray);
                return;
            }
            CJSON_ADD_ITEM_TO_ARRAY_AND_CHECK_AND_CLEAR_VOID(itemJson, policiesArray);
        }
        char *policiesStr = cJSON_PrintUnformatted(policiesArray);
        if (policiesStr != nullptr) {
            valuesBucket.PutString(EdmRdbFiledConst::FILED_ACCESSIBLE_POLICIES, policiesStr);
            free(policiesStr);
        }
        cJSON_Delete(policiesArray);
    }

    // Add running mode if not default
    RunningMode runningMode = admin.adminInfo_.runningMode_;
    if (runningMode != RunningMode::DEFAULT) {
        valuesBucket.PutInt(EdmRdbFiledConst::FILED_RUNNING_MODE, static_cast<uint32_t>(runningMode));
    }
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

    cJSON *managedEventsArray = nullptr;
    CJSON_CREATE_ARRAY_AND_CHECK(managedEventsArray, false);
    for (const auto &it : managedEvents) {
        cJSON* itemJson = cJSON_CreateNumber(static_cast<uint32_t>(it));
        if (itemJson == nullptr) {
            cJSON_Delete(managedEventsArray);
            return false;
        }
        CJSON_ADD_ITEM_TO_ARRAY_AND_CHECK_AND_CLEAR(itemJson, managedEventsArray, false);
    }
    char *managedEventsStr = cJSON_PrintUnformatted(managedEventsArray);
    if (managedEventsStr != nullptr) {
        valuesBucket.PutString(EdmRdbFiledConst::FILED_SUBSCRIBE_EVENTS, managedEventsStr);
        free(managedEventsStr);
    }
    cJSON_Delete(managedEventsArray);

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

void AdminPoliciesStorageRdb::SetAdminStringInfo(const std::string &stringInfo, std::vector<std::string> &info)
{
    if (stringInfo.empty() || stringInfo == "null") {
        return;
    }
    cJSON *jsonInfo = cJSON_Parse(stringInfo.c_str());
    if (jsonInfo == nullptr) {
        EDMLOGE("AdminPoliciesStorageRdb::SetAdminStringInfo failed: JSON parsing failed.");
        return;
    }

    if (cJSON_IsArray(jsonInfo)) {
        int arraySize = cJSON_GetArraySize(jsonInfo);
        if (arraySize > EdmConstants::DEFAULT_LOOP_MAX_SIZE) {
            EDMLOGE("AdminPoliciesStorageRdb::SetAdminStringInfo failed: Array size exceeds limit.");
            cJSON_Delete(jsonInfo);
            return;
        }

        cJSON *element = nullptr;
        cJSON_ArrayForEach(element, jsonInfo) {
            if (cJSON_IsString(element)) {
                info.emplace_back(element->valuestring);
            }
        }
    }

    cJSON_Delete(jsonInfo);
}

void AdminPoliciesStorageRdb::SetAdminItems(std::shared_ptr<NativeRdb::ResultSet> resultSet,
    std::shared_ptr<Admin> item)
{
    if (resultSet == nullptr || item == nullptr) {
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
    SetAdminStringInfo(permissionStr, item->adminInfo_.permission_);
    bool isManagedEventStrNull = false;
    resultSet->IsColumnNull(EdmRdbFiledConst::FILED_COLUMN_INDEX_EIGHT, isManagedEventStrNull);
    if (!isManagedEventStrNull) {
        SetManagedEventStr(resultSet, item);
    }
    resultSet->GetString(EdmRdbFiledConst::FILED_COLUMN_INDEX_NINE, item->adminInfo_.parentAdminName_);
    int isDebug = 0;
    resultSet->GetInt(EdmRdbFiledConst::FILED_COLUMN_INDEX_TEN, isDebug);
    item->adminInfo_.isDebug_ = isDebug != 0;
    std::string policiesStr;
    resultSet->GetString(EdmRdbFiledConst::FILED_COLUMN_INDEX_ELEVEN, policiesStr);
    SetAdminStringInfo(policiesStr, item->adminInfo_.accessiblePolicies_);
    int32_t runningMode = 0;
    resultSet->GetInt(EdmRdbFiledConst::FILED_COLUMN_INDEX_TWELVE, runningMode);
    item->adminInfo_.runningMode_ = static_cast<RunningMode>(runningMode);
}

void AdminPoliciesStorageRdb::SetManagedEventStr(std::shared_ptr<NativeRdb::ResultSet> resultSet,
    std::shared_ptr<Admin> item)
{
    std::string managedEventsStr;
    resultSet->GetString(EdmRdbFiledConst::FILED_COLUMN_INDEX_EIGHT, managedEventsStr);
    if (managedEventsStr.empty() || managedEventsStr == "null") {
        return;
    }

    cJSON* managedEventsJson = cJSON_Parse(managedEventsStr.c_str());
    if (managedEventsJson == nullptr) {
        return;
    }
    
    if (cJSON_GetArraySize(managedEventsJson) > EdmConstants::DEFAULT_LOOP_MAX_SIZE) {
        cJSON_Delete(managedEventsJson);
        return;
    }

    cJSON* element = nullptr;
    cJSON_ArrayForEach(element, managedEventsJson) {
        if (cJSON_IsNumber(element)) {
            item->adminInfo_.managedEvents_.push_back(static_cast<ManagedEvent>(element->valueint));
        }
    }
    
    cJSON_Delete(managedEventsJson);
}

void AdminPoliciesStorageRdb::ConvertStrToJson(const std::string &str, cJSON *json)
{
    if (str.empty()) {
        EDMLOGE("AdminPoliciesStorageRdb::ConvertStrToJson failed: str is empty.");
        json = nullptr;
        return;
    }

    json = cJSON_Parse(str.c_str());
}
} // namespace EDM
} // namespace OHOS