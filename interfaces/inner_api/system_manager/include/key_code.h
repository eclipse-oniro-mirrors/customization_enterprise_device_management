/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNER_API_KEYEVENT_MANAGER_INCLUDE_KEY_CODE_H
#define INTERFACES_INNER_API_KEYEVENT_MANAGER_INCLUDE_KEY_CODE_H

#include <message_parcel.h>
#include <string>

namespace OHOS {
namespace EDM {
enum class KeyCode {
    POWER = 0,
    VOLUME_UP = 1,
    VOLUME_DOWN = 2,
    BACK = 3,
    HOME = 4,
    RECENT = 5,
    FN = 6,
    DPAD_UP = 7,
    DPAD_DOWN = 8,
    DPAD_LEFT = 9,
    DPAD_RIGHT = 10,
    DPAD_CENTER = 11,
    BRIGHTNESS_UP = 12,
    BRIGHTNESS_DOWN = 13,
    ESCAPE = 14,
    F1 = 15,
    F2 = 16,
    F3 = 17,
    F4 = 18,
    F5 = 19,
    F6 = 20,
    F7 = 21,
    F8 = 22,
    F9 = 23,
    F10 = 24,
    F11 = 25,
    F12 = 26
};

enum KeyPolicy {
    INTERCEPTION = 0,
    CUSTOM = 1
};

enum class KeyAction {
    UNKNOWN = -1,
    DOWN = 0,
    UP = 1
};

struct KeyCustomization {
    int32_t keyCode = 0;
    int32_t keyPolicy = 0;
};

class KeyEventHandle {
public:
    static bool WriteKeyCustomizationVector(MessageParcel &data,
        const std::vector<KeyCustomization> &keyCustomizations);
    static bool WriteKeyCustomization(MessageParcel &data, const KeyCustomization &keyCust);
    static bool ReadKeyCustomizationVector(MessageParcel &data,
        std::vector<KeyCustomization> &keyCustomizations);
    static bool ReadKeyCustomization(MessageParcel &data, KeyCustomization &keyCust);
};
} // namespace EDM
} // namespace OHOS
#endif // INTERFACES_INNER_API_KEYEVENT_MANAGER_INCLUDE_KEY_CODE_H