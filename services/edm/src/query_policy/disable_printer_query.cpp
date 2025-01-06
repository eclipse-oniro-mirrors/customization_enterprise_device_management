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

#include "disable_printer_query.h"

#include "bool_serializer.h"
#include "edm_constants.h"
#include "edm_log.h"
#include "parameters.h"

namespace OHOS {
namespace EDM {
std::string DisablePrinterQuery::GetPolicyName()
{
    return "disabled_printer";
}

std::string DisablePrinterQuery::GetPermission(IPlugin::PermissionType, const std::string &permissionTag)
{
    if (permissionTag == EdmConstants::PERMISSION_TAG_VERSION_11) {
        return "ohos.permission.ENTERPRISE_RESTRICT_POLICY";
    }
    return "ohos.permission.ENTERPRISE_MANAGE_RESTRICTIONS";
}

ErrCode DisablePrinterQuery::QueryPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("DisablePrinterQuery OnGetPolicy %{public}s...", policyData.c_str());
    bool isDisabled = false;
    BoolSerializer::GetInstance()->Deserialize(policyData, isDisabled);
    EDMLOGI("DisablePrinterQuery isDisabled= %{public}d...", isDisabled);
    reply.WriteInt32(ERR_OK);
    reply.WriteBool(isDisabled);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS