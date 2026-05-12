/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "allowed_permission_bundle_query.h"

#include "allowed_permission_bundle_serializer.h"
#include "application_instance.h"
#include "edm_constants.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {

std::string AllowedPermissionBundleQuery::GetPolicyName()
{
    return PolicyName::POLICY_ALLOWED_PERMISSION_BUNDLE;
}

std::string AllowedPermissionBundleQuery::GetPermission(IPlugin::PermissionType permissionType,
    const std::string &permissionTag)
{
    return EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY;
}

ErrCode AllowedPermissionBundleQuery::QueryPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    std::string permissionName;
    if (!data.ReadString(permissionName)) {
        EDMLOGE("AllowedPermissionBundleQuery::QueryPolicy read permissionName failed");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    if (permissionName.empty()) {
        EDMLOGE("AllowedPermissionBundleQuery permissionName is empty");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    std::map<std::string, std::vector<ApplicationInstance>> policyMap;
    AllowedPermissionBundleSerializer::GetInstance()->Deserialize(policyData, policyMap);

    std::vector<ApplicationInstance> appList;
    auto it = policyMap.find(permissionName);
    if (it != policyMap.end()) {
        appList = it->second;
    }

    reply.WriteInt32(ERR_OK);
    reply.WriteUint32(appList.size());
    for (const ApplicationInstance &app : appList) {
        reply.WriteString(app.appIdentifier);
        reply.WriteInt32(userId);
        reply.WriteInt32(app.appIndex);
    }

    EDMLOGI("AllowedPermissionBundleQuery::QueryPolicy permission=%{public}s count=%{public}zu",
        permissionName.c_str(), appList.size());
    return ERR_OK;
}

} // namespace EDM
} // namespace OHOS