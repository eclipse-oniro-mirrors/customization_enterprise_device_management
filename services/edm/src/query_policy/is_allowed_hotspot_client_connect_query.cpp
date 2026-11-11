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

#include "is_allowed_hotspot_client_connect_query.h"

#include "array_string_serializer.h"
#include "edm_constants.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
std::string IsAllowedHotspotClientConnectQuery::GetPolicyName()
{
    return PolicyName::POLICY_ALLOWED_HOTSPOT_CLIENT_LIST;
}

std::string IsAllowedHotspotClientConnectQuery::GetPermission(IPlugin::PermissionType,
    const std::string &permissionTag)
{
    return EdmPermission::PERMISSION_ENTERPRISE_MANAGE_WIFI;
}

ErrCode IsAllowedHotspotClientConnectQuery::QueryPolicy(std::string &policyData, MessageParcel &data,
    MessageParcel &reply, int32_t userId)
{
    EDMLOGI("IsAllowedHotspotClientConnectQuery QueryPolicy");
    std::string macAddress = data.ReadString();
    std::vector<std::string> macAddresses;
    if (!ArrayStringSerializer::GetInstance()->Deserialize(policyData, macAddresses)) {
        EDMLOGE("IsAllowedHotspotClientConnectQuery::QueryPolicy Deserialize failed");
        reply.WriteInt32(EdmReturnErrCode::EXECUTE_TIME_OUT);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    bool isAllowed = true;
    if (!macAddresses.empty()) {
        auto found = std::find(macAddresses.begin(), macAddresses.end(), macAddress);
        isAllowed = (found != macAddresses.end());
    }
    EDMLOGI("IsAllowedHotspotClientConnectQuery::QueryPolicy isAllowed=%{public}d", isAllowed);
    reply.WriteInt32(ERR_OK);
    reply.WriteBool(isAllowed);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
