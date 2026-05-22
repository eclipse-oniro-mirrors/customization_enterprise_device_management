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

#include "window_state_info.h"
#include "edm_log.h"
#include "edm_constants.h"

namespace OHOS {
namespace EDM {
bool WindowStateInfoHandle::ReadWindowStateInfoVector(MessageParcel &data,
    std::vector<WindowStateInfo> &windowStateInfos)
{
    uint32_t size = data.ReadUint32();
    if (size > EdmConstants::DEFAULT_LOOP_MAX_SIZE) {
        return false;
    }
    windowStateInfos.clear();
    windowStateInfos.reserve(size);

    for (uint32_t i = 0; i < size; i++) {
        WindowStateInfo info;
        if (!ReadWindowStateInfo(data, info)) {
            return false;
        }
        windowStateInfos.emplace_back(std::move(info));
    }
    return true;
}

bool WindowStateInfoHandle::ReadWindowStateInfo(MessageParcel &data, WindowStateInfo &windowStateInfo)
{
    if (!data.ReadInt32(windowStateInfo.windowId)) {
        return false;
    }
    uint32_t state = data.ReadUint32();
    if (state > static_cast<uint32_t>(WindowState::BACKGROUND)) {
        return false;
    }
    windowStateInfo.state = WindowState(state);
    if (!data.ReadBool(windowStateInfo.isOnDock)) {
        return false;
    }
    if (!data.ReadString(windowStateInfo.name)) {
        return false;
    }
    return true;
}

bool WindowStateInfoHandle::WriteWindowStateInfoVector(MessageParcel &data,
    const std::vector<WindowStateInfo> windowStateInfos)
{
    if (!data.WriteUint32(windowStateInfos.size())) {
        return false;
    }

    for (const auto &windowStateInfo : windowStateInfos) {
        if (!WriteWindowStateInfo(data, windowStateInfo)) {
            return false;
        }
    }
    return true;
}

bool WindowStateInfoHandle::WriteWindowStateInfo(MessageParcel &data, const WindowStateInfo windowStateInfo)
{
    if (!data.WriteInt32(windowStateInfo.windowId)) {
        return false;
    }
    if (!data.WriteUint32(static_cast<uint32_t>(windowStateInfo.state))) {
        return false;
    }
    if (!data.WriteBool(windowStateInfo.isOnDock)) {
        return false;
    }
    if (!data.WriteString(windowStateInfo.name)) {
        return false;
    }
    return true;
}
} // namespace EDM
} // namespace OHOS