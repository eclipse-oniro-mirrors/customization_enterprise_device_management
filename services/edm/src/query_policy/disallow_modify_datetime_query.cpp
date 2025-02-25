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

#include "disallow_modify_datetime_query.h"

#include "bool_serializer.h"
#include "edm_constants.h"
#include "edm_log.h"
#include "parameters.h"

namespace OHOS {
namespace EDM {

std::string DisallowModifyDateTimeQuery::GetPolicyName()
{
    return "disallow_modify_datetime";
}

std::string DisallowModifyDateTimeQuery::GetPermission(IPlugin::PermissionType, const std::string &permissionTag)
{
    if (permissionTag == EdmConstants::PERMISSION_TAG_VERSION_11) {
        return EdmPermission::PERMISSION_ENTERPRISE_SET_DATETIME;
    }
    return EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
}

ErrCode DisallowModifyDateTimeQuery::QueryPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    return GetBoolPolicy(policyData, reply);
}
} // namespace EDM
} // namespace OHOS