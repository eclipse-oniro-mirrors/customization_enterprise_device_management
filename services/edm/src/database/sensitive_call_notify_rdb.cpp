/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "sensitive_call_notify_rdb.h"

#include "edm_log.h"
#include "edm_rdb_filed_const.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<SensitiveCallNotifyRdb> SensitiveCallNotifyRdb::instance_;
std::once_flag SensitiveCallNotifyRdb::flag_;
std::once_flag SensitiveCallNotifyRdb::tableFlag_;
std::atomic<bool> SensitiveCallNotifyRdb::isTableInit_{false};

bool SensitiveCallNotifyRdb::CreateTable()
{
    EDMLOGI("SensitiveCallNotifyRdb::CreateTable.");
    std::string sql = "CREATE TABLE IF NOT EXISTS ";
    sql.append(EdmRdbFiledConst::SENSITIVE_CALL_NOTIFIED_RDB_TABLE_NAME + " (")
        .append(EdmRdbFiledConst::FILED_ID + " INTEGER PRIMARY KEY AUTOINCREMENT,")
        .append(EdmRdbFiledConst::FILED_USER_ID + " INTEGER NOT NULL,")
        .append(EdmRdbFiledConst::FILED_ADMIN_NAME + " TEXT NOT NULL,")
        .append(EdmRdbFiledConst::FILED_APP_INDEX + " INTEGER NOT NULL,")
        .append(EdmRdbFiledConst::FILED_SENSITIVE_ID + " TEXT NOT NULL,")
        .append(EdmRdbFiledConst::FILED_NOTIFIED_TIME + " INTEGER NOT NULL,")
        .append("UNIQUE(" + EdmRdbFiledConst::FILED_USER_ID + "," + EdmRdbFiledConst::FILED_ADMIN_NAME +
            "," + EdmRdbFiledConst::FILED_APP_INDEX + "," + EdmRdbFiledConst::FILED_SENSITIVE_ID + "));");
    auto mgr = EdmRdbDataManager::GetInstance();
    if (mgr != nullptr) {
        return mgr->CreateTable(sql);
    }
    EDMLOGE("SensitiveCallNotifyRdb::CreateTable failed, rdb data manager null.");
    return false;
}

std::shared_ptr<SensitiveCallNotifyRdb> SensitiveCallNotifyRdb::GetInstance()
{
    if (!isTableInit_.load()) {
        std::call_once(tableFlag_, []() {
            bool ok = CreateTable();
            isTableInit_.store(ok);
        });
    }
    if (!isTableInit_.load()) {
        EDMLOGE("SensitiveCallNotifyRdb::GetInstance table init failed.");
        return nullptr;
    }
    std::call_once(flag_, []() {
        if (instance_ == nullptr) {
            instance_.reset(new (std::nothrow) SensitiveCallNotifyRdb());
        }
    });
    return instance_;
}

bool SensitiveCallNotifyRdb::Insert(const SensitiveCallRecord &record)
{
    EDMLOGD("SensitiveCallNotifyRdb::Insert id=%{public}s", record.sensitiveId.c_str());
    auto mgr = EdmRdbDataManager::GetInstance();
    if (mgr == nullptr) {
        EDMLOGE("SensitiveCallNotifyRdb::Insert rdb data manager null.");
        return false;
    }
    NativeRdb::ValuesBucket bucket;
    bucket.PutInt(EdmRdbFiledConst::FILED_USER_ID, record.userId);
    bucket.PutString(EdmRdbFiledConst::FILED_ADMIN_NAME, record.adminName);
    bucket.PutInt(EdmRdbFiledConst::FILED_APP_INDEX, record.appIndex);
    bucket.PutString(EdmRdbFiledConst::FILED_SENSITIVE_ID, record.sensitiveId);
    bucket.PutInt(EdmRdbFiledConst::FILED_NOTIFIED_TIME, static_cast<int64_t>(record.notifiedTime));
    // Insert uses ON_CONFLICT_REPLACE, so the UNIQUE constraint makes repeated
    // inserts idempotent (no duplicate rows).
    return mgr->Insert(EdmRdbFiledConst::SENSITIVE_CALL_NOTIFIED_RDB_TABLE_NAME, bucket);
}

bool SensitiveCallNotifyRdb::Query(const std::string &adminName, int32_t userId, int32_t appIndex,
    const std::string &sensitiveId)
{
    auto mgr = EdmRdbDataManager::GetInstance();
    if (mgr == nullptr) {
        EDMLOGE("SensitiveCallNotifyRdb::Query rdb data manager null.");
        return false;
    }
    NativeRdb::AbsRdbPredicates predicates(EdmRdbFiledConst::SENSITIVE_CALL_NOTIFIED_RDB_TABLE_NAME);
    predicates.EqualTo(EdmRdbFiledConst::FILED_USER_ID, std::to_string(userId));
    predicates.EqualTo(EdmRdbFiledConst::FILED_ADMIN_NAME, adminName);
    predicates.EqualTo(EdmRdbFiledConst::FILED_APP_INDEX, std::to_string(appIndex));
    predicates.EqualTo(EdmRdbFiledConst::FILED_SENSITIVE_ID, sensitiveId);
    auto resultSet = mgr->Query(predicates, std::vector<std::string>());
    if (resultSet == nullptr) {
        EDMLOGE("SensitiveCallNotifyRdb::Query resultSet null.");
        return false;
    }
    bool exists = (resultSet->GoToFirstRow() == NativeRdb::E_OK);
    resultSet->Close();
    return exists;
}

bool SensitiveCallNotifyRdb::DeleteByAdmin(const std::string &adminName, int32_t userId)
{
    EDMLOGI("SensitiveCallNotifyRdb::DeleteByAdmin admin=%{public}s", adminName.c_str());
    auto mgr = EdmRdbDataManager::GetInstance();
    if (mgr == nullptr) {
        EDMLOGE("SensitiveCallNotifyRdb::DeleteByAdmin rdb data manager null.");
        return false;
    }
    NativeRdb::AbsRdbPredicates predicates(EdmRdbFiledConst::SENSITIVE_CALL_NOTIFIED_RDB_TABLE_NAME);
    predicates.EqualTo(EdmRdbFiledConst::FILED_USER_ID, std::to_string(userId));
    predicates.EqualTo(EdmRdbFiledConst::FILED_ADMIN_NAME, adminName);
    return mgr->Delete(predicates);
}

bool SensitiveCallNotifyRdb::DeleteByApp(const std::string &bundleName, int32_t appIndex)
{
    EDMLOGI("SensitiveCallNotifyRdb::DeleteByApp bundle=%{public}s appIndex=%{public}d",
        bundleName.c_str(), appIndex);
    auto mgr = EdmRdbDataManager::GetInstance();
    if (mgr == nullptr) {
        EDMLOGE("SensitiveCallNotifyRdb::DeleteByApp rdb data manager null.");
        return false;
    }
    NativeRdb::AbsRdbPredicates predicates(EdmRdbFiledConst::SENSITIVE_CALL_NOTIFIED_RDB_TABLE_NAME);
    predicates.EqualTo(EdmRdbFiledConst::FILED_ADMIN_NAME, bundleName);
    predicates.EqualTo(EdmRdbFiledConst::FILED_APP_INDEX, std::to_string(appIndex));
    return mgr->Delete(predicates);
}
} // namespace EDM
} // namespace OHOS
