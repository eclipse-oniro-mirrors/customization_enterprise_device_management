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

#include "device_policies_storage_rdb.h"
#include "edm_log.h"
#include "edm_rdb_filed_const.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<DevicePoliciesStorageRdb> DevicePoliciesStorageRdb::instance_ = nullptr;
std::mutex DevicePoliciesStorageRdb::mutexLock_;

DevicePoliciesStorageRdb::DevicePoliciesStorageRdb()
{
    CreateDeviceAdminPoliciesTable();
    CreateDeviceCombinedPoliciesTable();
}

void DevicePoliciesStorageRdb::CreateDeviceAdminPoliciesTable()
{
    EDMLOGI("DevicePoliciesStorageRdb::CreateDeviceAdminPoliciesTable.");
    std::string createTableSql = "CREATE TABLE IF NOT EXISTS ";
    createTableSql.append(EdmRdbFiledConst::DEVICE_ADMIN_POLICIES_RDB_TABLE_NAME + " (")
        .append(EdmRdbFiledConst::FILED_ID + " INTEGER PRIMARY KEY AUTOINCREMENT,")
        .append(EdmRdbFiledConst::FILED_USER_ID + " INTEGER NOT NULL,")
        .append(EdmRdbFiledConst::FILED_ADMIN_NAME + " TEXT NOT NULL,")
        .append(EdmRdbFiledConst::FILED_POLICY_NAME + " TEXT,")
        .append(EdmRdbFiledConst::FILED_POLICY_VALUE + " TEXT);");
    auto edmRdbDataManager = EdmRdbDataManager::GetInstance();
    if (edmRdbDataManager != nullptr) {
        edmRdbDataManager->CreateTable(createTableSql);
    } else {
        EDMLOGE("DevicePoliciesStorageRdb::create database device_admin_policies failed.");
    }
}

void DevicePoliciesStorageRdb::CreateDeviceCombinedPoliciesTable()
{
    EDMLOGI("DevicePoliciesStorageRdb::CreateDeviceCombinedPoliciesTable.");
    std::string createTableSql = "CREATE TABLE IF NOT EXISTS ";
    createTableSql.append(EdmRdbFiledConst::DEVICE_COMBINED_POLICIES_RDB_TABLE_NAME + " (")
        .append(EdmRdbFiledConst::FILED_ID + " INTEGER PRIMARY KEY AUTOINCREMENT,")
        .append(EdmRdbFiledConst::FILED_USER_ID + " INTEGER NOT NULL,")
        .append(EdmRdbFiledConst::FILED_POLICY_NAME + " TEXT,")
        .append(EdmRdbFiledConst::FILED_POLICY_VALUE + " TEXT);");
    auto edmRdbDataManager = EdmRdbDataManager::GetInstance();
    if (edmRdbDataManager != nullptr) {
        edmRdbDataManager->CreateTable(createTableSql);
    } else {
        EDMLOGE("DevicePoliciesStorageRdb::create database device_combined_policies failed.");
    }
}

std::shared_ptr<DevicePoliciesStorageRdb> DevicePoliciesStorageRdb::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutexLock_);
        if (instance_ == nullptr) {
            instance_ = std::make_shared<DevicePoliciesStorageRdb>();
        }
    }
    return instance_;
}

bool DevicePoliciesStorageRdb::InsertAdminPolicy(int32_t userId, const std::string &adminName,
    const std::string &policyName, const std::string &policyValue)
{
    EDMLOGD("DevicePoliciesStorageRdb::InsertAdminPolicy.");
    auto edmRdbDataManager = EdmRdbDataManager::GetInstance();
    if (edmRdbDataManager == nullptr) {
        EDMLOGE("DevicePoliciesStorageRdb::InsertAdminPolicy get edmRdbDataManager failed.");
        return false;
    }
    // insert into device_admin_policies(user_id, admin_name, policy_name, policy_value) values(?, ?, ?, ?)
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutInt(EdmRdbFiledConst::FILED_USER_ID, userId);
    valuesBucket.PutString(EdmRdbFiledConst::FILED_ADMIN_NAME, adminName);
    valuesBucket.PutString(EdmRdbFiledConst::FILED_POLICY_NAME, policyName);
    valuesBucket.PutString(EdmRdbFiledConst::FILED_POLICY_VALUE, policyValue);
    return edmRdbDataManager->Insert(EdmRdbFiledConst::DEVICE_ADMIN_POLICIES_RDB_TABLE_NAME, valuesBucket);
}

bool DevicePoliciesStorageRdb::UpdateAdminPolicy(int32_t userId, const std::string &adminName,
    const std::string &policyName, const std::string &policyValue)
{
    EDMLOGD("DevicePoliciesStorageRdb::UpdateAdminPolicy.");
    auto edmRdbDataManager = EdmRdbDataManager::GetInstance();
    if (edmRdbDataManager == nullptr) {
        EDMLOGE("DevicePoliciesStorageRdb::UpdateAdminPolicy get edmRdbDataManager failed.");
        return false;
    }
    // update device_admin_policies set policy_value=? where user_id=? and admin_name=? and policy_name=?
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(EdmRdbFiledConst::FILED_POLICY_VALUE, policyValue);
    NativeRdb::AbsRdbPredicates predicates(EdmRdbFiledConst::DEVICE_ADMIN_POLICIES_RDB_TABLE_NAME);
    predicates.EqualTo(EdmRdbFiledConst::FILED_USER_ID, std::to_string(userId));
    predicates.EqualTo(EdmRdbFiledConst::FILED_ADMIN_NAME, adminName);
    predicates.EqualTo(EdmRdbFiledConst::FILED_POLICY_NAME, policyName);
    return edmRdbDataManager->Update(valuesBucket, predicates);
}

bool DevicePoliciesStorageRdb::DeleteAdminPolicy(int32_t userId, const std::string &adminName,
    const std::string &policyName)
{
    EDMLOGD("AdminPoliciesStorageRdb::DeleteAdminPolicy.");
    auto edmRdbDataManager = EdmRdbDataManager::GetInstance();
    if (edmRdbDataManager == nullptr) {
        EDMLOGE("DevicePoliciesStorageRdb::DeleteAdminPolicy get edmRdbDataManager failed.");
        return false;
    }
    // delete from device_admin_policies where user_id=? and admin_name=? and policy_name=?
    NativeRdb::AbsRdbPredicates predicates(EdmRdbFiledConst::DEVICE_ADMIN_POLICIES_RDB_TABLE_NAME);
    predicates.EqualTo(EdmRdbFiledConst::FILED_USER_ID, std::to_string(userId));
    predicates.EqualTo(EdmRdbFiledConst::FILED_ADMIN_NAME, adminName);
    predicates.EqualTo(EdmRdbFiledConst::FILED_POLICY_NAME, policyName);
    return edmRdbDataManager->Delete(predicates);
}

bool DevicePoliciesStorageRdb::QueryAdminPolicy(int32_t userId, std::unordered_map<std::string,
    PolicyItemsMap> &adminPolicies, std::unordered_map<std::string, AdminValueItemsMap> &policyAdmins)
{
    EDMLOGD("DevicePoliciesStorageRdb::QueryAdminPolicy.");
    auto edmRdbDataManager = EdmRdbDataManager::GetInstance();
    if (edmRdbDataManager == nullptr) {
        EDMLOGE("DevicePoliciesStorageRdb::QueryAdminPolicy get edmRdbDataManager failed.");
        return false;
    }
    // select * from device_admin_policies
    NativeRdb::AbsRdbPredicates predicates(EdmRdbFiledConst::DEVICE_ADMIN_POLICIES_RDB_TABLE_NAME);
    predicates.EqualTo(EdmRdbFiledConst::FILED_USER_ID, std::to_string(userId));
    auto resultSet = edmRdbDataManager->Query(predicates, std::vector<std::string>());
    if (resultSet == nullptr) {
        EDMLOGD("DevicePoliciesStorageRdb::QueryAdminPolicy failed.");
        return false;
    }
    int resultSetNum = resultSet->GoToFirstRow();
    while (resultSetNum == NativeRdb::E_OK) {
        std::string adminName;
        std::string policyName;
        std::string policyValue;
        resultSet->GetString(EdmRdbFiledConst::FILED_COLUMN_INDEX_TWO, adminName);
        resultSet->GetString(EdmRdbFiledConst::FILED_COLUMN_INDEX_THREE, policyName);
        resultSet->GetString(EdmRdbFiledConst::FILED_COLUMN_INDEX_FOUR, policyValue);
        PraseAdminPolicies(adminName, policyName, policyValue, adminPolicies);
        PrasePolicyAdmins(adminName, policyName, policyValue, policyAdmins);
        resultSetNum = resultSet->GoToNextRow();
    };
    resultSet->Close();
    return true;
}

void DevicePoliciesStorageRdb::PraseAdminPolicies(const std::string &adminName, const std::string &policyName,
    const std::string &policyValue, std::unordered_map<std::string, PolicyItemsMap> &adminPolicies)
{
    auto iter = adminPolicies.find(adminName);
    if (iter == adminPolicies.end()) {
        PolicyItemsMap itemMap;
        itemMap.insert(std::pair<std::string, std::string>(policyName, policyValue));
        adminPolicies.insert(std::pair<std::string, PolicyItemsMap>(adminName, itemMap));
        return;
    }
    iter->second.insert(std::pair<std::string, std::string>(policyName, policyValue));
}

void DevicePoliciesStorageRdb::PrasePolicyAdmins(const std::string &adminName, const std::string &policyName,
    const std::string &policyValue, std::unordered_map<std::string, AdminValueItemsMap> &policyAdmins)
{
    auto iter = policyAdmins.find(policyName);
    if (iter == policyAdmins.end()) {
        AdminValueItemsMap adminValueItem;
        adminValueItem.insert(std::pair<std::string, std::string>(adminName, policyValue));
        policyAdmins.insert(std::pair<std::string, AdminValueItemsMap>(policyName, adminValueItem));
        return;
    }
    iter->second.insert(std::pair<std::string, std::string>(adminName, policyValue));
}

bool DevicePoliciesStorageRdb::InsertCombinedPolicy(int32_t userId, const std::string &policyName,
    const std::string &policyValue)
{
    EDMLOGD("DevicePoliciesStorageRdb::InsertCombinedPolicy.");
    auto edmRdbDataManager = EdmRdbDataManager::GetInstance();
    if (edmRdbDataManager == nullptr) {
        EDMLOGE("DevicePoliciesStorageRdb::InsertCombinedPolicy get edmRdbDataManager failed.");
        return false;
    }
    // insert into device_combined_policies(user_id, policy_name, policy_value) values(?, ?, ?)
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutInt(EdmRdbFiledConst::FILED_USER_ID, userId);
    valuesBucket.PutString(EdmRdbFiledConst::FILED_POLICY_NAME, policyName);
    valuesBucket.PutString(EdmRdbFiledConst::FILED_POLICY_VALUE, policyValue);
    return edmRdbDataManager->Insert(EdmRdbFiledConst::DEVICE_COMBINED_POLICIES_RDB_TABLE_NAME,
        valuesBucket);
}

bool DevicePoliciesStorageRdb::UpdateCombinedPolicy(int32_t userId, const std::string &policyName,
    const std::string &policyValue)
{
    EDMLOGD("DevicePoliciesStorageRdb::UpdateCombinedPolicy.");
    auto edmRdbDataManager = EdmRdbDataManager::GetInstance();
    if (edmRdbDataManager == nullptr) {
        EDMLOGE("DevicePoliciesStorageRdb::UpdateCombinedPolicy get edmRdbDataManager failed.");
        return false;
    }
    // update device_combined_policies set policy_value=? where user_id=? and policy_name=?
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(EdmRdbFiledConst::FILED_POLICY_VALUE, policyValue);
    NativeRdb::AbsRdbPredicates predicates(EdmRdbFiledConst::DEVICE_COMBINED_POLICIES_RDB_TABLE_NAME);
    predicates.EqualTo(EdmRdbFiledConst::FILED_USER_ID, std::to_string(userId));
    predicates.EqualTo(EdmRdbFiledConst::FILED_POLICY_NAME, policyName);
    return edmRdbDataManager->Update(valuesBucket, predicates);
}

bool DevicePoliciesStorageRdb::DeleteCombinedPolicy(int32_t userId, const std::string &policyName)
{
    EDMLOGD("DevicePoliciesStorageRdb::DeleteCombinedPolicy.");
    auto edmRdbDataManager = EdmRdbDataManager::GetInstance();
    if (edmRdbDataManager == nullptr) {
        EDMLOGE("DevicePoliciesStorageRdb::DeleteCombinedPolicy get edmRdbDataManager failed.");
        return false;
    }
    // delete from device_combined_policies where user_id=? and policy_name=?
    NativeRdb::AbsRdbPredicates predicates(EdmRdbFiledConst::DEVICE_COMBINED_POLICIES_RDB_TABLE_NAME);
    predicates.EqualTo(EdmRdbFiledConst::FILED_USER_ID, std::to_string(userId));
    predicates.EqualTo(EdmRdbFiledConst::FILED_POLICY_NAME, policyName);
    return edmRdbDataManager->Delete(predicates);
}

bool DevicePoliciesStorageRdb::QueryCombinedPolicy(int32_t userId, PolicyItemsMap &itemsMap)
{
    EDMLOGD("DevicePoliciesStorageRdb::QueryCombinedPolicy.");
    auto edmRdbDataManager = EdmRdbDataManager::GetInstance();
    if (edmRdbDataManager == nullptr) {
        EDMLOGE("DevicePoliciesStorageRdb::QueryCombinedPolicy get edmRdbDataManager failed.");
        return false;
    }
    // select * from device_combined_policies
    NativeRdb::AbsRdbPredicates predicates(EdmRdbFiledConst::DEVICE_COMBINED_POLICIES_RDB_TABLE_NAME);
    predicates.EqualTo(EdmRdbFiledConst::FILED_USER_ID, std::to_string(userId));
    auto resultSet = edmRdbDataManager->Query(predicates, std::vector<std::string>());
    if (resultSet == nullptr) {
        EDMLOGD("DevicePoliciesStorageRdb::QueryCombinedPolicy failed.");
        return false;
    }
    int resultSetNum = resultSet->GoToFirstRow();
    while (resultSetNum == NativeRdb::E_OK) {
        std::string policyName;
        std::string policyValue;
        resultSet->GetString(EdmRdbFiledConst::FILED_COLUMN_INDEX_TWO, policyName);
        resultSet->GetString(EdmRdbFiledConst::FILED_COLUMN_INDEX_THREE, policyValue);
        itemsMap.insert(std::pair<std::string, std::string>(policyName, policyValue));
        resultSetNum = resultSet->GoToNextRow();
    };
    resultSet->Close();
    return true;
}

bool DevicePoliciesStorageRdb::QueryAllUserId(std::vector<int32_t> &userIds)
{
    EDMLOGD("DevicePoliciesStorageRdb::QueryAllUserId.");
    auto edmRdbDataManager = EdmRdbDataManager::GetInstance();
    if (edmRdbDataManager == nullptr) {
        EDMLOGE("DevicePoliciesStorageRdb::QueryAllUserId get edmRdbDataManager failed.");
        return false;
    }
    // select user_id from device_admin_policies
    NativeRdb::AbsRdbPredicates predicates(EdmRdbFiledConst::DEVICE_ADMIN_POLICIES_RDB_TABLE_NAME);
    predicates.Distinct();
    std::vector<std::string> queryColumns = { EdmRdbFiledConst::FILED_USER_ID };
    auto resultSet = edmRdbDataManager->Query(predicates, queryColumns);
    if (resultSet == nullptr) {
        EDMLOGD("DevicePoliciesStorageRdb::QueryAllUserId failed.");
        return false;
    }
    int resultSetNum = resultSet->GoToFirstRow();
    while (resultSetNum == NativeRdb::E_OK) {
        int32_t userId = 0;
        resultSet->GetInt(EdmRdbFiledConst::FILED_COLUMN_INDEX_ZERO, userId);
        userIds.push_back(userId);
        resultSetNum = resultSet->GoToNextRow();
    };
    resultSet->Close();
    return true;
}
} // namespace EDM
} // namespace OHOS