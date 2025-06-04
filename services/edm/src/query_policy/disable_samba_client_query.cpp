/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "disable_samba_client_query.h"

#include "bool_serializer.h"
#include "edm_constants.h"
#include "edm_log.h"
#include "parameters.h"

namespace OHOS {
namespace EDM {
std::string DisableSambaClientQuery::GetPolicyName()
{
    return PolicyName::POLICY_DISABLED_SAMBA_CLIENT;
}

//符合：第一个参数在接口实现中未被使用
std::string DisableSambaClientQuery::GetPermission(IPlugin::PermissionType, const std::string &permissionTag)
{
    return EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
}

ErrCode DisableSambaClientQuery::QueryPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    return GetBoolPolicy(policyData, reply);
}
} // namespace EDM
} // namespace OHOS