/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef COMMON_NATIVE_INCLUDE_POLICY_STRUCT_H
#define COMMON_NATIVE_INCLUDE_POLICY_STRUCT_H

#include <string>

namespace OHOS {
namespace EDM {
struct UpdateInfo {
    std::string version;
    int64_t firstReceivedTime;
    std::string packageType;
};

struct KeyEventItem {
    int32_t pressed;
    int32_t keyCode;
    int64_t downTime;
};

struct KeyEvent {
    int64_t actionTime;
    int32_t keyCode;
    int32_t keyAction;
    std::vector<KeyEventItem> keyItems;
};

} // namespace EDM
} // namespace OHOS

#endif // COMMON_NATIVE_INCLUDE_POLICY_STRUCT_H
