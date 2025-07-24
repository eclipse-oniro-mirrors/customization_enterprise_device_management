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

#include "allowed_wifi_list_query.h"

#include "array_wifi_id_serializer.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
std::string AllowedWifiListQuery::GetPolicyName()
{
    return PolicyName::POLICY_ALLOWED_WIFI_LIST;
}

std::string AllowedWifiListQuery::GetPermission(IPlugin::PermissionType, const std::string &permissionTag)
{
    return EdmPermission::PERMISSION_ENTERPRISE_MANAGE_WIFI;
}

ErrCode AllowedWifiListQuery::QueryPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("AllowedWifiListQuery OnGetPolicy");
    return ArrayWifiIdSerializer::GetInstance()->QueryWifiListPolicy(policyData, reply);
}
} // namespace EDM
} // namespace OHOS