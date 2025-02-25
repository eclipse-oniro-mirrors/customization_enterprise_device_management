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

#include "disallowed_running_bundles_query.h"

#include "array_string_serializer.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
std::string DisallowedRunningBundlesQuery::GetPolicyName()
{
    return "disallow_running_bundles";
}

std::string DisallowedRunningBundlesQuery::GetPermission(IPlugin::PermissionType, const std::string &permissionTag)
{
    if (permissionTag == EdmConstants::PERMISSION_TAG_VERSION_11) {
        return EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SET_APP_RUNNING_POLICY;
    }
    return EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION;
}

ErrCode DisallowedRunningBundlesQuery::QueryPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("DisallowedRunningBundlesQuery OnGetPolicy policyData : %{public}s, userId : %{public}d",
        policyData.c_str(), userId);
    return GetArrayStringPolicy(policyData, reply);
}
} // namespace EDM
} // namespace OHOS