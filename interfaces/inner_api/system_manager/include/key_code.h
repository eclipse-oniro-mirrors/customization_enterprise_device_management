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

struct KeyCustomization {
    int32_t keyCode;
    int32_t keyPolicy;
};
class KeyEventHandle {
public:
    static bool WriteKeyCustomizationVector(MessageParcel &data,
        const std::vector<KeyCustomization> KeyCustomizations);
    static bool WriteKeyCustomization(MessageParcel &data, const KeyCustomization keyCust);
    static bool ReadKeyCustomizationVector(MessageParcel &data,
        std::vector<KeyCustomization> &KeyCustomizations);
    static bool ReadKeyCustomization(MessageParcel &data, KeyCustomization &keyCust);
};
} // namespace EDM
} // namespace OHOS
#endif // INTERFACES_INNER_API_KEYEVENT_MANAGER_INCLUDE_KEY_CODE_H