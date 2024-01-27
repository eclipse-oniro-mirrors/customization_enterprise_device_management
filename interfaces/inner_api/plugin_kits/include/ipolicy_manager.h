/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef SERVICES_EDM_INCLUDE_EDM_IPOLICY_MANAGER_H
#define SERVICES_EDM_INCLUDE_EDM_IPOLICY_MANAGER_H

#include <string>
#include <unordered_map>
#include "edm_constants.h"
#include "edm_errors.h"

namespace OHOS {
namespace EDM {
using AdminValueItemsMap = std::unordered_map<std::string, std::string>;

class IPolicyManager {
public:
    static IPolicyManager *GetInstance();
    virtual ErrCode GetAdminByPolicyName(const std::string &policyName, AdminValueItemsMap &adminValueItems,
        int32_t userId = EdmConstants::DEFAULT_USER_ID)
    {
        return ERR_OK;
    }
    virtual ErrCode GetPolicy(const std::string &adminName, const std::string &policyName, std::string &policyValue,
        int32_t userId = EdmConstants::DEFAULT_USER_ID)
    {
        return ERR_OK;
    }

    static IPolicyManager* policyManagerInstance_;
};

} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_EDM_IPOLICY_MANAGER_H
