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

#ifndef INTERFACES_INNER_API_MANAGED_FEATURE_H
#define INTERFACES_INNER_API_MANAGED_FEATURE_H

namespace OHOS {
namespace EDM {
enum class ManagedFeature : int32_t {
    LOCAL_HOTA_DOMAIN = 0,
    USER_EXTEND_CREDENTIAL = 1,
    DEVICE_SECURITY_LEVEL = 2,
    PRINTER_IP_ADDRESS_POLICY = 3,
    OPTICAL_DISC_DRIVE_BURN = 4,
    EXACT_TIMER = 5,
    EXEMPTION_RESOURCE = 6,
    X_KEY = 7,
    SYSTEM_ROLLBACK = 8,
    SUPER_PRIVACY = 9,
};
} // namespace EDM
} // namespace OHOS
#endif // INTERFACES_INNER_API_MANAGED_FEATURE_H
