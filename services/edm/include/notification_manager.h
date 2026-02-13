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

#ifndef SERVICES_EDM_INCLUDE_NOTIFICATION_MANAGER_H
#define SERVICES_EDM_INCLUDE_NOTIFICATION_MANAGER_H

#include <memory>
#include <string>

#include "notification_content.h"
#include "pixel_map.h"
#include "want_agent.h"

#include "notification_info.h"

namespace OHOS {
namespace EDM {
class NotificationManager {
public:
    bool SendSystemNotification(const NotificationInfo &notificationInfo, const IconInfo &iconInfo,
        const WantAgentInfo &wantAgentInfo);

private:
    std::shared_ptr<Notification::NotificationContent> CreateNotificationNormalContent(
        const NotificationInfo &notificationInfo);

    std::unique_ptr<Media::PixelMap> GetIconPixelMap(const IconInfo &iconInfo);

    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> GetWantAgent(const WantAgentInfo &wantAgentInfo);
};
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_INCLUDE_NOTIFICATION_MANAGER_H
