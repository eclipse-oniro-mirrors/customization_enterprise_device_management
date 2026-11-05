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

#include "allowed_hotspot_client_list_query.h"

#include "array_string_serializer.h"
#include "edm_constants.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
std::string AllowedHotspotClientListQuery::GetPolicyName()
{
    return PolicyName::POLICY_ALLOWED_HOTSPOT_CLIENT_LIST;
}

std::string AllowedHotspotClientListQuery::GetPermission(IPlugin::PermissionType,
    const std::string &permissionTag)
{
    return EdmPermission::PERMISSION_ENTERPRISE_MANAGE_WIFI;
}

ErrCode AllowedHotspotClientListQuery::QueryPolicy(std::string &policyData, MessageParcel &data,
    MessageParcel &reply, int32_t userId)
{
    EDMLOGI("AllowedHotspotClientListQuery QueryPolicy");
    std::vector<std::string> macAddresses;
    if (!ArrayStringSerializer::GetInstance()->Deserialize(policyData, macAddresses)) {
        EDMLOGE("AllowedHotspotClientListQuery Deserialize error");
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    reply.WriteInt32(ERR_OK);
    if (!ArrayStringSerializer::GetInstance()->WritePolicy(reply, macAddresses)) {
        EDMLOGE("AllowedHotspotClientListQuery WritePolicy failed");
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    EDMLOGI("AllowedHotspotClientListQuery QueryPolicy return %{public}zu macAddresses", macAddresses.size());
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
