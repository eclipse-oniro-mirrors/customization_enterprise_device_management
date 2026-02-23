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

#ifndef SERVICES_EDM_INCLUDE_NOTIFICATION_INFO_H
#define SERVICES_EDM_INCLUDE_NOTIFICATION_INFO_H

#include <string>

namespace OHOS {
namespace EDM {
struct NotificationInfo {
    std::string title;
    std::string body;
};

struct IconInfo {
    std::string icon;
    float xAxis = 1.0;
    float yAxis = 1.0;
};

struct WantAgentInfo {
    std::string bundleName;
    std::string abilityName;
    std::string uri;
};
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_INCLUDE_NOTIFICATION_INFO_H
