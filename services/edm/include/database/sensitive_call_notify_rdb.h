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

#ifndef SERVICES_EDM_INCLUDE_DATABASE_SENSITIVE_CALL_NOTIFY_RDB_H
#define SERVICES_EDM_INCLUDE_DATABASE_SENSITIVE_CALL_NOTIFY_RDB_H

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>

#include "edm_rdb_data_manager.h"

namespace OHOS {
namespace EDM {
// One "already notified" record. user_id is the OS account id (== requirement
// "account" dimension). sensitive_id merges operation type + identifier
// (e.g. "POLICY:1002" / "EVENT:27"), so a single TEXT column covers all op
// kinds without a discriminator column.
struct SensitiveCallRecord {
    std::string adminName;
    int32_t userId = 0;
    int32_t appIndex = 0;
    std::string sensitiveId;
    int64_t notifiedTime = 0;
};

// CRUD for the dedicated table sensitive_call_notified. Singleton + lazy
// table creation, mirrors DevicePoliciesStorageRdb. Independent of the policy
// tables to avoid entangling RemoveAdminPolicy/RemoveAdminItem (which would
// fail for plugin-less policy names and abort admin deactivation).
class SensitiveCallNotifyRdb {
public:
    static std::shared_ptr<SensitiveCallNotifyRdb> GetInstance();
    bool Insert(const SensitiveCallRecord &record);
    bool Query(const std::string &adminName, int32_t userId, int32_t appIndex,
        const std::string &sensitiveId);
    bool DeleteByAdmin(const std::string &adminName, int32_t userId);
    bool DeleteByApp(const std::string &bundleName, int32_t appIndex);
    ~SensitiveCallNotifyRdb() = default;
private:
    SensitiveCallNotifyRdb() = default;
    static bool CreateTable();
    static std::shared_ptr<SensitiveCallNotifyRdb> instance_;
    static std::once_flag flag_;
    static std::once_flag tableFlag_;
    static std::atomic<bool> isTableInit_;
};
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_INCLUDE_DATABASE_SENSITIVE_CALL_NOTIFY_RDB_H
