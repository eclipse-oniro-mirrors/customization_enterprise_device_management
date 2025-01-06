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

#include "password_policy_query.h"

#include "edm_log.h"
#include "password_policy.h"
#include "password_policy_serializer.h"

namespace OHOS {
namespace EDM {
std::string PasswordPolicyQuery::GetPolicyName()
{
    return "password_policy";
}

std::string PasswordPolicyQuery::GetPermission(IPlugin::PermissionType, const std::string &permissionTag)
{
    return "ohos.permission.ENTERPRISE_MANAGE_SECURITY";
}

ErrCode PasswordPolicyQuery::QueryPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    PasswordPolicy policy;
    if (!PasswordSerializer::GetInstance()->Deserialize(policyData, policy)) {
        EDMLOGD("PasswordPolicyPlugin Deserialize error!");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteString(policy.complexityReg);
    reply.WriteInt64(policy.validityPeriod);
    reply.WriteString(policy.additionalDescription);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS