/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef SERVICES_EDM_INCLUDE_EDM_POLICY_MANAGER_H
#define SERVICES_EDM_INCLUDE_EDM_POLICY_MANAGER_H

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include "device_policies_storage_rdb.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "json/json.h"
#include "ipolicy_manager.h"
#include "user_policy_manager.h"

namespace OHOS {
namespace EDM {

class PolicyManager final: public IPolicyManager {
public:
    ErrCode GetAdminByPolicyName(const std::string &policyName, AdminValueItemsMap &adminValueItems,
        int32_t userId = EdmConstants::DEFAULT_USER_ID) override;

    ErrCode GetPolicy(const std::string &adminName, const std::string &policyName, std::string &policyValue,
        int32_t userId = EdmConstants::DEFAULT_USER_ID) override;

    void Init(std::vector<int32_t> userIds);

    ErrCode SetPolicy(const std::string &adminName, const std::string &policyName, const std::string &adminPolicyValue,
        const std::string &mergedPolicyValue, int32_t userId = EdmConstants::DEFAULT_USER_ID);

    ErrCode GetAllPolicyByAdmin(const std::string &adminName, PolicyItemsMap &allAdminPolicy,
        int32_t userId = EdmConstants::DEFAULT_USER_ID);

    void GetPolicyUserIds(std::vector<int32_t> &userIds);

    void Dump();

private:
    std::shared_ptr<UserPolicyManager> GetUserPolicyMgr(int32_t userId);

    std::map<std::int32_t, std::shared_ptr<UserPolicyManager>> policyMgrMap_;
    std::shared_ptr<UserPolicyManager> defaultPolicyMgr_;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_EDM_POLICY_MANAGER_H
