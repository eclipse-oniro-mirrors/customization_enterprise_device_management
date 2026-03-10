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

#include "allowed_notification_bundles_query.h"

#include "allowed_notification_bundles_serializer.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
std::string AllowedNotificationBundlesQuery::GetPolicyName()
{
    return PolicyName::POLICY_ALLOWED_NOTIFICATION_BUNDLES;
}

std::string AllowedNotificationBundlesQuery::GetPermission(IPlugin::PermissionType, const std::string &permissionTag)
{
    return EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION;
}

ErrCode AllowedNotificationBundlesQuery::QueryPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    std::vector<AllowedNotificationBundlesType> policies;
    if (!AllowedNotificationBundlesSerializer::GetInstance()->Deserialize(policyData, policies)) {
        EDMLOGE("AllowedNotificationBundlesSerializer Deserialize error!");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    reply.WriteInt32(ERR_OK);
    int32_t accountId = data.ReadInt32();
    for (const auto& item : policies) {
        if (item.userId == accountId) {
            std::vector<std::string> bundleNames(item.trustList.begin(), item.trustList.end());
            reply.WriteStringVector(bundleNames);
            return ERR_OK;
        }
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS