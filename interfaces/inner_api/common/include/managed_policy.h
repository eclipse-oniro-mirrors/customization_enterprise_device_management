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

#ifndef INTERFACES_INNER_API_MANAGED_POLICY_PROXY_H
#define INTERFACES_INNER_API_MANAGED_POLICY_PROXY_H

namespace OHOS {
namespace EDM {
enum class ManagedPolicy {
    DEFAULT = 0,
    DISALLOW = 1,
    FORCE_OPEN = 2,
};

enum class DeviceSecurityLevelPolicy {
    DEFAULT_ENFORCED = 0,
    ALLOW_BALANCED = 1,
    ALLOW_FLEXIBLE = 2,
};

enum class EnterpriseResetPolicy {
    DEFAULT = 0,
    ENTERPRISE_ACCOUNT_AUTH_ON = 1,
    ENTERPRISE_ACCOUNT_AUTH_OFF = 2,
};
} // namespace EDM
} // namespace OHOS
#endif // INTERFACES_INNER_API_MANAGED_POLICY_PROXY_H