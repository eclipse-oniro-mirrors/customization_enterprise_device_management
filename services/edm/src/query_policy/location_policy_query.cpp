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

#include "location_policy_query.h"

#include "edm_log.h"
#include "location_policy.h"
#include "parameters.h"

namespace OHOS {
namespace EDM {
const std::string PARAM_EDM_LOCATION_POLICY = "persist.edm.location_policy";
std::string LocationPolicyQuery::GetPolicyName()
{
    return PolicyName::POLICY_LOCATION_POLICY;
}

std::string LocationPolicyQuery::GetPermission(IPlugin::PermissionType, const std::string &permissionTag)
{
    return EdmPermission::PERMISSION_ENTERPRISE_MANAGE_LOCATION;
}

ErrCode LocationPolicyQuery::QueryPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("LocationPolicyQuery OnGetPolicy");
    std::string res = system::GetParameter(PARAM_EDM_LOCATION_POLICY, "");
    EDMLOGI("LocationPolicyQuery OnGetPolicy res = %{public}s", res.c_str());
    if (res == "none") {
        reply.WriteInt32(ERR_OK);
        reply.WriteInt32(static_cast<int32_t>(LocationPolicy::DEFAULT_LOCATION_SERVICE));
    } else if (res == "disallow") {
        reply.WriteInt32(ERR_OK);
        reply.WriteInt32(static_cast<int32_t>(LocationPolicy::DISALLOW_LOCATION_SERVICE));
    } else if (res == "force_open") {
        reply.WriteInt32(ERR_OK);
        reply.WriteInt32(static_cast<int32_t>(LocationPolicy::FORCE_OPEN_LOCATION_SERVICE));
    } else {
        EDMLOGD("LocationPolicyQuery get location policy illegal. Value = %{public}s.", res.c_str());
        reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS