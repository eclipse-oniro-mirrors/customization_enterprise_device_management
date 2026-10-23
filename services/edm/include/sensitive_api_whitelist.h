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

#ifndef SERVICES_EDM_INCLUDE_SENSITIVE_API_WHITELIST_H
#define SERVICES_EDM_INCLUDE_SENSITIVE_API_WHITELIST_H

#include <cstdint>
#include <string>

namespace OHOS {
namespace EDM {
// Sensitive operation whitelist (compile-time fixed, read-only).
// Sensitive operations are heterogeneous: policy FuncCode (SET/GET) routed via
// HandleDevicePolicyNew, and IDL/system-level ops like SubscribeManagedEvent
// (ipccode 10, sensitivity is in the events param, not the ipccode). A single
// ipccode cannot judge them; instead a canonical string id "POLICY:<code>" /
// "EVENT:<event>" merges type+identifier, avoiding numeric collision and
// keeping the table schema stable for future op types.
class SensitiveApiWhitelist {
public:
    // Lookup by canonical sensitive id (e.g. "POLICY:1002", "EVENT:27").
    static bool IsSensitive(const std::string &sensitiveId);
    // Get the notification body template resource name for a sensitive id.
    // Returns the default body template name if the id has no specific template.
    static std::string GetBodyTemplateName(const std::string &sensitiveId);
    // Build canonical id for a policy FuncCode's PolicyCode.
    static std::string MakePolicyId(uint32_t policyCode);
    // Build canonical id for a ManagedEvent value (SubscribeManagedEvent).
    static std::string MakeEventId(uint32_t managedEvent);
};
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_INCLUDE_SENSITIVE_API_WHITELIST_H
