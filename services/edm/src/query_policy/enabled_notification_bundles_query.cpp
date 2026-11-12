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

#include "enabled_notification_bundles_query.h"

#include <string>
#include <vector>

#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_log.h"
#include "notification_helper.h"

namespace OHOS {
namespace EDM {
std::string EnabledNotificationBundlesQuery::GetPolicyName()
{
    return PolicyName::POLICY_ENABLED_NOTIFICATION_BUNDLES;
}

std::string EnabledNotificationBundlesQuery::GetPermission(IPlugin::PermissionType, const std::string &permissionTag)
{
    return EdmPermission::PERMISSION_ENTERPRISE_MANAGE_NOTIFICATION;
}

ErrCode EnabledNotificationBundlesQuery::QueryPolicy(std::string &policyData, MessageParcel &data,
    MessageParcel &reply, int32_t userId)
{
    return QueryPolicy(policyData, data, reply, userId, false);
}

ErrCode EnabledNotificationBundlesQuery::QueryPolicy(std::string &policyData, MessageParcel &data,
    MessageParcel &reply, int32_t userId, bool isAdminNull)
{
    if (userId <= 0) {
        EDMLOGE("EnabledNotificationBundlesQuery invalid userId=%{public}d", userId);
        return EdmReturnErrCode::UID_INVALID;
    }
    if (!isAdminNull) {
        return GetArrayStringPolicy(policyData, reply);
    }
    std::vector<std::string> bundleList;
    int32_t ret = ReadEnabledBundles(userId, bundleList);
    if (ret != ERR_OK) {
        EDMLOGE("EnabledNotificationBundlesQuery ReadEnabledBundles failed, ret=%{public}d, "
            "userId=%{public}d", ret, userId);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    EDMLOGI("EnabledNotificationBundlesQuery all view, userId=%{public}d, size=%{public}zu",
        userId, bundleList.size());
    reply.WriteInt32(ERR_OK);
    reply.WriteStringVector(bundleList);
    return ERR_OK;
}

ErrCode EnabledNotificationBundlesQuery::ReadEnabledBundles(int32_t userId, std::vector<std::string> &bundleList)
{
    return Notification::NotificationHelper::GetSilentAuthNotificationBundles(userId, bundleList);
}
} // namespace EDM
} // namespace OHOS
