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

#ifndef INTERFACES_INNER_API_APPLICATION_MANAGER_INCLUDE_MAIN_WINDOW_STATES_H
#define INTERFACES_INNER_API_APPLICATION_MANAGER_INCLUDE_MAIN_WINDOW_STATES_H

#include <string>
#include <vector>
#include "message_parcel.h"
#include "window_state_info.h"

namespace OHOS {
namespace EDM {
struct MainWindowStates {
    int32_t pid;
    std::string bundleName;
    WindowState state;
};

class MainWindowStatesHandle {
public:
    static bool ReadMainWindowStatesVector(MessageParcel &reply, std::vector<MainWindowStates> &mainWindowStates);
    static bool ReadMainWindowStates(MessageParcel &reply, MainWindowStates &mainWindowState);
    static bool WriteMainWindowStatesVector(MessageParcel &data, const std::vector<MainWindowStates> mainWindowStates);
    static bool WriteMainWindowStates(MessageParcel &data, const MainWindowStates mainWindowState);
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_APPLICATION_MANAGER_INCLUDE_MAIN_WINDOW_STATES_H
