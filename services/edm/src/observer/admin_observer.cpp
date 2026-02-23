/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "admin_observer.h"

#include "ipc_skeleton.h"

#include "edm_bundle_manager_impl.h"
#include "edm_constants.h"
#include "edm_log.h"
#include "ext_info_manager.h"
#include "system_service_start_handler.h"

namespace OHOS {
namespace EDM {
constexpr float ICON_AXIS = 0.5;
void AdminObserver::OnAdminAdd(const std::string &bundleName, int32_t userId, bool isDebug)
{
    EDMLOGI("OnAdminAdd execute");
    SystemServiceStartHandler::GetInstance()->AddNetworkAccessPolicy({bundleName});
    if (isDebug) {
        ExtInfoManager extInfoManager;
        SendAdminNotification(EdmConstants::MANAGEMENT_NOTIFICATION_TIPS, extInfoManager.GetWantAgentInfo());
    }
}

void AdminObserver::OnAdminRemove(const std::string &bundleName, int32_t userId, AdminType adminType)
{
    EDMLOGI("OnAdminRemove execute");
    SystemServiceStartHandler::GetInstance()->RemoveNetworkAccessPolicy({bundleName});
    if (adminType == AdminType::BYOD) {
        SendByodDisableSelfNotification(bundleName);
    }
}

void AdminObserver::SendByodDisableSelfNotification(const std::string &bundleName)
{
    int32_t uid = IPCSkeleton::GetCallingUid();
    std::string callingBundleName;
    EdmBundleManagerImpl bundleManager;
    bundleManager.GetNameForUid(uid, callingBundleName);
    if (callingBundleName == bundleName) {
        WantAgentInfo wantAgentInfo;
        SendAdminNotification(EdmConstants::REMOVED_MANAGEMENT_NOTIFICATION_TIPS, wantAgentInfo);
    }
}

void AdminObserver::SendAdminNotification(const std::string &text, const WantAgentInfo &wantAgentInfo)
{
    NotificationInfo notificationInfo = {.title = EdmConstants::DEVICE_MANAGEMENT_TEXT, .body = text};
    ExtInfoManager extInfoManager;
    EdmBundleManagerImpl bundleManager;
    std::string icon = bundleManager.GetIconByBundleName(extInfoManager.GetAdminProvisioningInfo());
    IconInfo iconInfo = {.icon = icon, .xAxis = ICON_AXIS, .yAxis = ICON_AXIS};
    NotificationManager notificationManager;
    notificationManager.SendSystemNotification(notificationInfo, iconInfo, wantAgentInfo);
}
} // namespace EDM
} // namespace OHOS