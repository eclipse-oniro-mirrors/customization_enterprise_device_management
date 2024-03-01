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

#ifndef SERVICES_EDM_INCLUDE_ADMIN_POLICIES_STORAGE_RDB_H
#define SERVICES_EDM_INCLUDE_ADMIN_POLICIES_STORAGE_RDB_H

#include <unordered_map>

#include "admin.h"
#include "edm_rdb_data_manager.h"
#include "json/json.h"

namespace OHOS {
namespace EDM {
class AdminPoliciesStorageRdb {
public:
    AdminPoliciesStorageRdb();
    static std::shared_ptr<AdminPoliciesStorageRdb> GetInstance();
    bool InsertAdmin(int32_t userId, const Admin &admin);
    bool UpdateAdmin(int32_t userId, const Admin &admin);
    bool DeleteAdmin(int32_t userId, const std::string &packageName);
    bool UpdateAdmin(int32_t userId, const std::string &packageName, const std::string &className,
        const std::vector<std::string> &permissions);
    bool UpdateEntInfo(int32_t userId, const std::string &packageName, const EntInfo &entInfo);
    bool UpdateManagedEvents(int32_t userId, const std::string &packageName,
        const std::vector<ManagedEvent> &managedEvents);
    std::unordered_map<int32_t, std::vector<std::shared_ptr<Admin>>> QueryAllAdmin();
    bool InsertAuthorizedAdmin(const std::string &bundleName, const std::vector<std::string> &permissions,
        const std::string &parentName);
    bool UpdateAuthorizedAdmin(const std::string &bundleName, const std::vector<std::string> &permissions,
        const std::string &parentName);

private:
    NativeRdb::ValuesBucket CreateValuesBucket(int32_t userId, const Admin &admin);
    void SetAdminItems(std::shared_ptr<NativeRdb::ResultSet> resultSet, std::shared_ptr<Admin> item);
    void ConvertStrToJson(const std::string &str, Json::Value &json);
    static std::shared_ptr<AdminPoliciesStorageRdb> instance_;
    static std::mutex mutexLock_;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_ADMIN_POLICIES_STORAGE_RDB_H