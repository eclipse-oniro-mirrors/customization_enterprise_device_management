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

#include "is_allowed_telephony_sms_query.h"

#include <algorithm>

#include "edm_constants.h"
#include "edm_log.h"
#include "policy_flag.h"
#include "telephony_sms_policy_serializer.h"

namespace OHOS {
namespace EDM {
std::string IsAllowedTelephonySmsQuery::GetPolicyName()
{
    return PolicyName::POLICY_TELEPHONY_SMS_POLICY;
}

std::string IsAllowedTelephonySmsQuery::GetPermission(IPlugin::PermissionType,
    const std::string &permissionTag)
{
    return EdmPermission::PERMISSION_ENTERPRISE_MANAGE_TELEPHONY;
}

ErrCode IsAllowedTelephonySmsQuery::QueryPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    const std::string smsType = data.ReadString();
    const std::string number = data.ReadString();
    std::string maskedNumber = number.length() > 7 ? number.substr(0, 3) + "****" +
    number.substr(number.length() - 4) : "****";
    EDMLOGI("IsAllowedTelephonySmsQuery::QueryPolicy smsType:%{public}s, number:%{public}s",
        smsType.c_str(), maskedNumber.c_str());
    auto serializer = TelephonySmsPolicySerializer::GetInstance();
    std::map<std::string, TelephonySmsPolicyType> policies;
    if (!serializer->Deserialize(policyData, policies)) {
        EDMLOGE("IsAllowedTelephonySmsQuery::QueryPolicy Deserialize failed");
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    bool isAllowed = true;
    auto iter = policies.find(smsType);
    if (iter != policies.end()) {
        const std::vector<std::string> &numberList = iter->second.numberList;
        bool isFind = std::find(numberList.begin(), numberList.end(), number) != numberList.end();
        if (iter->second.policyFlag == static_cast<int32_t>(PolicyFlag::TRUST_LIST)) {
            isAllowed = isFind;
        } else {
            isAllowed = !isFind;
        }
    }
    EDMLOGI("IsAllowedTelephonySmsQuery::QueryPolicy isAllowed=%{public}d", isAllowed);
    reply.WriteInt32(ERR_OK);
    reply.WriteBool(isAllowed);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS