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

#include "ntp_server_query.h"

#include "edm_log.h"
#include "parameters.h"

namespace OHOS {
namespace EDM {
const std::string KEY_NTP_SERVER = "persist.time.ntpserver_specific";

std::string NTPServerQuery::GetPolicyName()
{
    return PolicyName::POLICY_NTP_SERVER;
}

std::string NTPServerQuery::GetPermission(IPlugin::PermissionType, const std::string &permissionTag)
{
    return EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SYSTEM;
}

ErrCode NTPServerQuery::QueryPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId)
{
    EDMLOGI("NTPServerQuery OnGetPolicy");
    std::string result = system::GetParameter(KEY_NTP_SERVER, "");
    reply.WriteInt32(ERR_OK);
    reply.WriteString(result);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS