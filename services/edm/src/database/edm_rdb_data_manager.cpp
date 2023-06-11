/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "edm_rdb_data_manager.h"
#include "edm_log.h"
#include "edm_rdb_filed_const.h"
#include "edm_rdb_open_callback.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<NativeRdb::RdbStore> EdmRdbDataManager::rdbStore_ = nullptr;
std::shared_ptr<EdmRdbDataManager> EdmRdbDataManager::instance_ = nullptr;
std::mutex EdmRdbDataManager::mutexLock_;

std::shared_ptr<EdmRdbDataManager> EdmRdbDataManager::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutexLock_);
        if (instance_ == nullptr) {
            instance_ = std::make_shared<EdmRdbDataManager>();
        }
    }
    return instance_;
}

std::shared_ptr<NativeRdb::RdbStore> EdmRdbDataManager::GetRdbStore()
{
    EDMLOGD("EdmRdbDataManager GetRdbStore.");
    if (rdbStore_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutexLock_);
        if (rdbStore_ == nullptr) {
            NativeRdb::RdbStoreConfig rdbStoreConfig(EdmRdbFiledConst::EDM_SERVICE_DATABASE_PATH +
                EdmRdbFiledConst::EDM_RDB_NAME);
            int32_t errCode = NativeRdb::E_OK;
            EdmRdbOpenCallback edmRdbOpenCallback;
            rdbStore_ = NativeRdb::RdbHelper::GetRdbStore(rdbStoreConfig, EdmRdbFiledConst::EDM_RDB_VERSION,
                edmRdbOpenCallback, errCode);
        }
    }
    return rdbStore_;
}

bool EdmRdbDataManager::CreateTable(const std::string &createTableSql)
{
    EDMLOGD("EdmRdbDataManager CreateTable start.");
    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        EDMLOGE("EdmRdbDataManager GetRdbStore failed.");
        return false;
    }
    if (createTableSql.empty()) {
        EDMLOGE("EdmRdbDataManager createTableSql is empty.");
        return false;
    }
    int32_t ret = rdbStore->ExecuteSql(createTableSql);
    if (ret != NativeRdb::E_OK) {
        EDMLOGE("CreateTable failed, ret: %{public}d", ret);
        return false;
    }
    return true;
}

bool EdmRdbDataManager::Insert(const std::string &tableName, const NativeRdb::ValuesBucket &valuesBucket)
{
    EDMLOGD("EdmRdbDataManager Insert data start.");
    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        EDMLOGE("EdmRdbDataManager GetRdbStore failed.");
        return false;
    }
    int64_t rowId = -1;
    auto ret = rdbStore->InsertWithConflictResolution(rowId, tableName, valuesBucket,
        NativeRdb::ConflictResolution::ON_CONFLICT_REPLACE);
    return ret == NativeRdb::E_OK;
}

bool EdmRdbDataManager::Delete(const NativeRdb::AbsRdbPredicates &predicates)
{
    EDMLOGD("EdmRdbDataManager Delete data start.");
    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        EDMLOGE("EdmRdbDataManager GetRdbStore failed.");
        return false;
    }
    int32_t rowId = -1;
    auto ret = rdbStore->Delete(rowId, predicates);
    return ret == NativeRdb::E_OK;
}

bool EdmRdbDataManager::Update(const NativeRdb::ValuesBucket &valuesBucket,
    const NativeRdb::AbsRdbPredicates &predicates)
{
    EDMLOGD("EdmRdbDataManager Update data start.");
    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        EDMLOGE("EdmRdbDataManager GetRdbStore failed.");
        return false;
    }
    int32_t rowId = -1;
    auto ret = rdbStore->Update(rowId, valuesBucket, predicates);
    return ret == NativeRdb::E_OK;
}

std::shared_ptr<NativeRdb::ResultSet> EdmRdbDataManager::Query(const NativeRdb::AbsRdbPredicates &predicates,
    const std::vector<std::string> &columns)
{
    EDMLOGD("EdmRdbDataManager Query data start.");
    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        EDMLOGE("EdmRdbDataManager GetRdbStore failed.");
        return nullptr;
    }
    auto absSharedResultSet = rdbStore->Query(predicates, columns);
    if (absSharedResultSet == nullptr || !absSharedResultSet->HasBlock()) {
        EDMLOGE("EdmRdbDataManager query date failed.");
        return nullptr;
    }
    return absSharedResultSet;
}
} // namespace EDM
} // namespace OHOS