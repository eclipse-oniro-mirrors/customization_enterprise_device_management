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

#include "get_display_version_query.h"

#include "edm_log.h"
#include "parameter.h"

namespace OHOS {
namespace EDM {
IPlugin::ApiType GetDisplayVersionQuery::GetApiType()
{
    return IPlugin::ApiType::SYSTEM;
}

std::string GetDisplayVersionQuery::GetPolicyName()
{
    return "get_display_version";
}

std::string GetDisplayVersionQuery::GetPermission(IPlugin::PermissionType, const std::string &permissionTag)
{
    return "ohos.permission.ENTERPRISE_GET_DEVICE_INFO";
}

ErrCode GetDisplayVersionQuery::QueryPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("GetDisplayVersionQuery OnGetPolicy.");
    std::string version = GetDisplayVersion();
    reply.WriteInt32(ERR_OK);
    reply.WriteString(version);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS