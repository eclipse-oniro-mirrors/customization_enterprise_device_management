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

#ifndef SERVICES_EDM_INCLUDE_DEVICE_POLICIES_STORAGE_RDB_H
#define SERVICES_EDM_INCLUDE_DEVICE_POLICIES_STORAGE_RDB_H

#include <unordered_map>
#include "edm_rdb_data_manager.h"

namespace OHOS {
namespace EDM {
using PolicyItemsMap = std::unordered_map<std::string, std::string>;     /* PolicyName and PolicyValue pair */
using AdminValueItemsMap = std::unordered_map<std::string, std::string>; /* AdminName and PolicyValue pair */

class DevicePoliciesStorageRdb {
public:
    DevicePoliciesStorageRdb();
    ~DevicePoliciesStorageRdb() = default;
    static std::shared_ptr<DevicePoliciesStorageRdb> GetInstance();
    bool InsertAdminPolicy(int32_t userId, const std::string &adminName, const std::string &policyName,
        const std::string &policyValue);
    bool UpdateAdminPolicy(int32_t userId, const std::string &adminName, const std::string &policyName,
        const std::string &policyValue);
    bool DeleteAdminPolicy(int32_t userId, const std::string &adminName, const std::string &policyName);
    bool QueryAdminPolicy(int32_t userId, std::unordered_map<std::string, PolicyItemsMap> &adminPolicies,
        std::unordered_map<std::string, AdminValueItemsMap> &policyAdmins);
    bool InsertCombinedPolicy(int32_t userId, const std::string &policyName, const std::string &policyValue);
    bool UpdateCombinedPolicy(int32_t userId, const std::string &policyName, const std::string &policyValue);
    bool DeleteCombinedPolicy(int32_t userId, const std::string &policyName);
    bool QueryCombinedPolicy(int32_t userId, PolicyItemsMap &itemsMap);
    bool QueryAllUserId(std::vector<int32_t> &userIds);
private:
    void CreateDeviceAdminPoliciesTable();
    void CreateDeviceCombinedPoliciesTable();
    void PraseAdminPolicies(const std::string &adminName, const std::string &policyName, const std::string &policyValue,
        std::unordered_map<std::string, PolicyItemsMap> &adminPolicies);
    void PrasePolicyAdmins(const std::string &adminName, const std::string &policyName, const std::string &policyValue,
        std::unordered_map<std::string, AdminValueItemsMap> &policyAdmins);
    static std::shared_ptr<DevicePoliciesStorageRdb> instance_;
    static std::mutex mutexLock_;
};
}  // namespace EDM
}  // namespace OHOS

#endif  // SERVICES_EDM_INCLUDE_DEVICE_POLICIES_STORAGE_RDB_H