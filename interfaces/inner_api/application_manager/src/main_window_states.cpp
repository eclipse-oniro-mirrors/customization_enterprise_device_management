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

#include "main_window_states.h"

#include "edm_constants.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
bool MainWindowStatesHandle::ReadMainWindowStatesVector(MessageParcel &data,
    std::vector<MainWindowStates> &mainWindowStates)
{
    mainWindowStates.clear();
    uint32_t size = data.ReadUint32();
    if (size > EdmConstants::DEFAULT_LOOP_MAX_SIZE) {
        return false;
    }
    mainWindowStates.reserve(size);

    for (uint32_t i = 0; i < size; i++) {
        MainWindowStates mainWindowState;
        if (!ReadMainWindowStates(data, mainWindowState)) {
            return false;
        }
        mainWindowStates.emplace_back(std::move(mainWindowState));
    }
    return true;
}

bool MainWindowStatesHandle::ReadMainWindowStates(MessageParcel &data, MainWindowStates &mainWindowState)
{
    if (!data.ReadInt32(mainWindowState.pid)) {
        return false;
    }
    if (!data.ReadString(mainWindowState.bundleName)) {
        return false;
    }
    uint32_t state = data.ReadUint32();
    if (state > static_cast<uint32_t>(WindowState::BACKGROUND)) {
        return false;
    }
    mainWindowState.state = WindowState(state);
    return true;
}

bool MainWindowStatesHandle::WriteMainWindowStatesVector(MessageParcel &data,
    const std::vector<MainWindowStates> mainWindowStates)
{
    if (!data.WriteUint32(mainWindowStates.size())) {
        return false;
    }

    for (const auto &mainWindowState : mainWindowStates) {
        if (!WriteMainWindowStates(data, mainWindowState)) {
            return false;
        }
    }
    return true;
}

bool MainWindowStatesHandle::WriteMainWindowStates(MessageParcel &data, const MainWindowStates mainWindowState)
{
    if (!data.WriteInt32(mainWindowState.pid)) {
        return false;
    }
    if (!data.WriteString(mainWindowState.bundleName)) {
        return false;
    }
    if (!data.WriteUint32(static_cast<uint32_t>(mainWindowState.state))) {
        return false;
    }
    return true;
}
} // namespace EDM
} // namespace OHOS
