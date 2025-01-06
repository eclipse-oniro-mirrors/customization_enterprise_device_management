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

#include "disallow_add_local_account_query.h"

#include "bool_serializer.h"
#include "edm_log.h"
#include "parameters.h"

namespace OHOS {
namespace EDM {
std::string DisallowAddLocalAccountQuery::GetPolicyName()
{
    return "disallow_add_local_account";
}

std::string DisallowAddLocalAccountQuery::GetPermission(IPlugin::PermissionType, const std::string &permissionTag)
{
    return "ohos.permission.ENTERPRISE_SET_ACCOUNT_POLICY";
}

ErrCode DisallowAddLocalAccountQuery::QueryPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("DisallowAddLocalAccountQuery OnGetPolicy %{public}s...", policyData.c_str());
    bool isDisallowed = false;
    BoolSerializer::GetInstance()->Deserialize(policyData, isDisallowed);
    reply.WriteInt32(ERR_OK);
    reply.WriteBool(isDisallowed);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS