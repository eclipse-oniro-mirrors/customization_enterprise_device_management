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
 
#ifndef INTERFACES_INNER_API_DEVICE_SETTINGS_INCLUDE_SWITCH_PARAM_H
#define INTERFACES_INNER_API_DEVICE_SETTINGS_INCLUDE_SWITCH_PARAM_H
 
namespace OHOS {
namespace EDM {
 
enum class SwitchKey {
    UNKNOWN = -1,
    NEARLINK = 0,
    BLUETOOTH = 1,
    WIFI = 2,
    NFC = 3,
};
 
enum class SwitchStatus {
    UNKNOWN = -1,
    ON = 0,
    OFF = 1,
    FORCE_ON = 2,
};
 
struct SwitchParam {
    SwitchKey key = SwitchKey::UNKNOWN;
    SwitchStatus status = SwitchStatus::UNKNOWN;
};
} // namespace EDM
} // namespace OHOS
 
#endif // INTERFACES_INNER_API_DEVICE_SETTINGS_INCLUDE_SWITCH_PARAM_H