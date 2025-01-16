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

#include "disable_bluetooth_query.h"

#include "edm_constants.h"
#include "edm_log.h"
#include "parameters.h"

namespace OHOS {
namespace EDM {
const std::string DisableBluetoothQuery::PERSIST_BLUETOOTH_CONTROL = "persist.edm.prohibit_bluetooth";

std::string DisableBluetoothQuery::GetPolicyName()
{
    return "disabled_bluetooth";
}

std::string DisableBluetoothQuery::GetPermission(IPlugin::PermissionType permissionType,
    const std::string &permissionTag)
{
    if (permissionType == IPlugin::PermissionType::BYOD_DEVICE_ADMIN) {
        return "ohos.permission.PERSONAL_MANAGE_RESTRICTIONS";
    }
    if (permissionTag == EdmConstants::PERMISSION_TAG_VERSION_11) {
        return "ohos.permission.ENTERPRISE_MANAGE_BLUETOOTH";
    }
    return "ohos.permission.ENTERPRISE_MANAGE_RESTRICTIONS";
}

ErrCode DisableBluetoothQuery::QueryPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    return GetBoolPolicy(policyData, reply);
}
} // namespace EDM
} // namespace OHOS