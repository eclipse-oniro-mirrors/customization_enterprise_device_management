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

#ifndef SERVICES_EDM_INCLUDE_QUERY_POLICY_POLICY_QUERY_FACTORY_H
#define SERVICES_EDM_INCLUDE_QUERY_POLICY_POLICY_QUERY_FACTORY_H

#include <memory>
#include <shared_mutex>
#include <unordered_map>

#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "ipolicy_query.h"
#include "policy_query_config.h"
#include "policy_query_config_table.h"

namespace OHOS {
namespace EDM {

class PolicyQueryFactory {
public:
    static std::shared_ptr<IPolicyQuery> CreateQuery(uint32_t policyCode);
    
    static ErrCode CheckFeatureEnabled(uint32_t policyCode);
    
private:
    static std::shared_ptr<IPolicyQuery> CreateGenericQuery(const PolicyQueryConfig& config);
    static std::shared_ptr<IPolicyQuery> CreateCustomQuery(
        uint32_t policyCode, const PolicyQueryConfig& config);
    static std::shared_ptr<IPolicyQuery> CreateCustomDeviceInfoQuery(uint32_t policyCode);
    static std::shared_ptr<IPolicyQuery> CreateCustomSecurityQuery(uint32_t policyCode);
    static std::shared_ptr<IPolicyQuery> CreateCustomAppManageQuery(uint32_t policyCode);
    static std::shared_ptr<IPolicyQuery> CreateCustomOtherQuery(uint32_t policyCode);
    
    static std::shared_mutex mutex_;
    static std::unordered_map<uint32_t, std::shared_ptr<IPolicyQuery>> queryCache_;
};

} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_QUERY_POLICY_POLICY_QUERY_FACTORY_H