/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef SERVICES_EDM_INCLUDE_QUERY_POLICY_IPOLICY_QUERY_H
#define SERVICES_EDM_INCLUDE_QUERY_POLICY_IPOLICY_QUERY_H

#include <string>

#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "iplugin.h"
#include "message_parcel.h"
#include "policy_manager.h"

namespace OHOS {
namespace EDM {
class IPolicyQuery {
public:
    virtual ~IPolicyQuery() = default;

    ErrCode GetPolicy(std::shared_ptr<PolicyManager> policyManager, uint32_t code, MessageParcel &data,
        MessageParcel &reply, int32_t userId);

protected:
    virtual IPlugin::ApiType GetApiType();

    virtual std::string GetPolicyName() = 0;

    virtual std::string GetPermission(IPlugin::PermissionType, const std::string &permissionTag) = 0;

    virtual bool IsPolicySaved();

    virtual ErrCode GetBoolSystemParamSuccess(MessageParcel &reply, std::string paramKey, bool defaultValue);

    virtual ErrCode QueryPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId) = 0;

private:
    void CreateSecurityContent(const std::string &bundleName, const std::string &abilityName, uint32_t code,
        const std::string &policyName, ErrCode errorCode);
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_QUERY_POLICY_IPOLICY_QUERY_H
