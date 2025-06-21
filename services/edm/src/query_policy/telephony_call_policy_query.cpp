/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "telephony_call_policy_query.h"

#include "telephony_call_policy_serializer.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
std::string TelephonyCallPolicyQuery::GetPolicyName()
{
    return PolicyName::POLICY_TELEPHONY_CALL_POLICY;
}

std::string TelephonyCallPolicyQuery::GetPermission(IPlugin::PermissionType, const std::string &permissionTag)
{
    return EdmPermission::PERMISSION_ENTERPRISE_MANAGE_TELEPHONY;
}

ErrCode TelephonyCallPolicyQuery::QueryPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    const std::string callType = data.ReadString();
    const int32_t flag = data.ReadInt32();
    EDMLOGI("TelephonyCallPolicyPlugin::OnGetPolicy callType:%{public}s, flag:%{public}d", callType.c_str(), flag);
    
    auto serializer = TelephonyCallPolicySerializer::GetInstance();
    std::map<std::string, TelephonyCallPolicyType> policies;
    if (!serializer->Deserialize(policyData, policies)) {
        EDMLOGE("TelephonyCallPolicyPlugin::OnGetPolicy Deserialize fail");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    reply.WriteInt32(ERR_OK);
    int32_t size = 0;
    auto it = policies.find(callType);
    if (it == policies.end()) {
        reply.WriteInt32(size);
    } else {
        if (flag == it->second.policyFlag) {
            reply.WriteStringVector(it->second.numberList);
        } else {
            reply.WriteInt32(size);
        }
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS