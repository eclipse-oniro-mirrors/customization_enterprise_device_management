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

#include "usb_read_only_query.h"

#include "edm_constants.h"
#include "edm_log.h"
#include "edm_utils.h"


namespace OHOS {
namespace EDM {
std::string UsbReadOnlyQuery::GetPolicyName()
{
    return PolicyName::POLICY_USB_READ_ONLY;
}

std::string UsbReadOnlyQuery::GetPermission(IPlugin::PermissionType, const std::string &permissionTag)
{
    return EdmPermission::PERMISSION_ENTERPRISE_MANAGE_USB;
}

ErrCode UsbReadOnlyQuery::QueryPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("UsbReadOnlyQuery OnGetPolicy: %{public}s", policyData.c_str());
    policyData = policyData.empty() ? "0" : policyData;
    int32_t result = EdmConstants::STORAGE_USB_POLICY_READ_ONLY;
    ErrCode parseRet = EdmUtils::ParseStringToInt(policyData, result);
    if (FAILED(parseRet)) {
        reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteInt32(result);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS