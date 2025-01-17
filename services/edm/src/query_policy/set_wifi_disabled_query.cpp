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

#include "set_wifi_disabled_query.h"

#include "edm_log.h"

namespace OHOS {
namespace EDM {
const std::string KEY_DISABLE_WIFI = "persist.edm.wifi_enable";

std::string SetWifiDisabledQuery::GetPolicyName()
{
    return "disable_wifi";
}

std::string SetWifiDisabledQuery::GetPermission(IPlugin::PermissionType permissionType,
    const std::string &permissionTag)
{
    if (permissionTag == EdmConstants::PERMISSION_TAG_VERSION_11) {
        return "ohos.permission.ENTERPRISE_MANAGE_WIFI";
    }
    if (permissionType == IPlugin::PermissionType::BYOD_DEVICE_ADMIN) {
        return "ohos.permission.PERSONAL_MANAGE_RESTRICTIONS";
    }
    return "ohos.permission.ENTERPRISE_MANAGE_RESTRICTIONS";
}

ErrCode SetWifiDisabledQuery::QueryPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    return GetBoolPolicy(policyData, reply);
}
} // namespace EDM
} // namespace OHOS