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

#include "is_allowed_telephony_call_query.h"

#include <algorithm>

#include "edm_constants.h"
#include "edm_log.h"
#include "policy_flag.h"
#include "telephony_call_policy_serializer.h"

namespace OHOS {
namespace EDM {
std::string IsAllowedTelephonyCallQuery::GetPolicyName()
{
    return PolicyName::POLICY_TELEPHONY_CALL_POLICY;
}

std::string IsAllowedTelephonyCallQuery::GetPermission(IPlugin::PermissionType,
    const std::string &permissionTag)
{
    return EdmPermission::PERMISSION_ENTERPRISE_MANAGE_TELEPHONY;
}

ErrCode IsAllowedTelephonyCallQuery::QueryPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    const std::string callType = data.ReadString();
    const std::string number = data.ReadString();
    EDMLOGI("IsAllowedTelephonyCallQuery::QueryPolicy callType:%{public}s, number:%{public}s",
        callType.c_str(), number.c_str());
    auto serializer = TelephonyCallPolicySerializer::GetInstance();
    std::map<std::string, TelephonyCallPolicyType> policies;
    if (!serializer->Deserialize(policyData, policies)) {
        EDMLOGE("IsAllowedTelephonyCallQuery::QueryPolicy Deserialize failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    bool isAllowed = true;
    auto iter = policies.find(callType);
    if (iter != policies.end()) {
        const std::vector<std::string> &numberList = iter->second.numberList;
        bool isFind = std::find(numberList.begin(), numberList.end(), number) != numberList.end();
        if (iter->second.policyFlag == static_cast<int32_t>(PolicyFlag::TRUST_LIST)) {
            isAllowed = isFind;
        } else {
            isAllowed = !isFind;
        }
    }
    EDMLOGI("IsAllowedTelephonyCallQuery::QueryPolicy isAllowed=%{public}d", isAllowed);
    reply.WriteInt32(ERR_OK);
    reply.WriteBool(isAllowed);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
