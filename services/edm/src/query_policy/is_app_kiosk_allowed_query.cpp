/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "is_app_kiosk_allowed_query.h"

#include "array_string_serializer.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
std::string IsAppKioskAllowedQuery::GetPolicyName()
{
    return PolicyName::POLICY_ALLOWED_KIOSK_APPS;
}

std::string IsAppKioskAllowedQuery::GetPermission(IPlugin::PermissionType permissionType,
    const std::string &permissionTag)
{
    return "";
}

ErrCode IsAppKioskAllowedQuery::QueryPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    std::string appIdentifier = data.ReadString();
    EDMLOGI("IsAppKioskAllowedQuery::QueryPolicy appIdentifier:%{public}s", appIdentifier.c_str());
    std::vector<std::string> appIdentifierList;
    ArrayStringSerializer::GetInstance()->Deserialize(policyData, appIdentifierList);
    auto it = std::find(appIdentifierList.begin(), appIdentifierList.end(), appIdentifier);
    bool isAllowed = (it != appIdentifierList.end());
    reply.WriteInt32(ERR_OK);
    reply.WriteBool(isAllowed);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS