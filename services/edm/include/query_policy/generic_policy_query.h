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

#ifndef SERVICES_EDM_INCLUDE_QUERY_POLICY_GENERIC_POLICY_QUERY_H
#define SERVICES_EDM_INCLUDE_QUERY_POLICY_GENERIC_POLICY_QUERY_H

#include "ipolicy_query.h"
#include "policy_query_config.h"

namespace OHOS {
namespace EDM {

class GenericPolicyQuery : public IPolicyQuery {
public:
    explicit GenericPolicyQuery(const PolicyQueryConfig& config)
        : config_(config), dataType_(config.dataType) {}

    ~GenericPolicyQuery() override = default;

    IPlugin::ApiType GetApiType() override
    {
        return config_.apiType;
    }

    std::string GetPolicyName() override
    {
        return config_.policyName;
    }

    std::string GetPermission(IPlugin::PermissionType type,
        const std::string &permissionTag) override
    {
        return config_.permissionConfig.GetPermission(type, permissionTag);
    }

    bool IsPolicySaved() override
    {
        return config_.isPolicySaved;
    }

    ErrCode QueryPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
        int32_t userId) override;

private:
    PolicyQueryConfig config_;
    PolicyDataType dataType_;
};

} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_QUERY_POLICY_GENERIC_POLICY_QUERY_H