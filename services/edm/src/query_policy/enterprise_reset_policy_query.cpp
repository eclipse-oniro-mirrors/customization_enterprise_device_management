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

#include "enterprise_reset_policy_query.h"

#include "edm_constants.h"
#include "edm_log.h"
#include "edm_errors.h"
#include "managed_policy.h"
#include "parameters.h"
#include <string_ex.h>

namespace OHOS {
namespace EDM {

std::string EnterpriseResetPolicyQuery::GetPolicyName()
{
    return PolicyName::POLICY_ENTERPRISE_RESET_POLICY;
}

std::string EnterpriseResetPolicyQuery::GetPermission(IPlugin::PermissionType, const std::string &permissionTag)
{
    return EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY;
}

ErrCode EnterpriseResetPolicyQuery::QueryPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    std::string paramValue = system::GetParameter(
        EdmConstants::SecurityManager::PARAM_EDM_ENTERPRISE_RESET_POLICY, "0");
    int32_t policy = 0;
    if (!OHOS::StrToInt(paramValue, policy)) {
        EDMLOGE("EnterpriseResetPolicyQuery QueryPolicy parse failed.");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    if (policy < static_cast<int32_t>(EnterpriseResetPolicy::DEFAULT) ||
        policy > static_cast<int32_t>(EnterpriseResetPolicy::ENTERPRISE_ACCOUNT_AUTH_OFF)) {
        EDMLOGE("EnterpriseResetPolicyQuery QueryPolicy invalid policy value: %{public}d.", policy);
        policy = static_cast<int32_t>(EnterpriseResetPolicy::DEFAULT);
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteInt32(policy);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
