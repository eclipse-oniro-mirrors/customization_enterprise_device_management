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

#include "sensitive_api_whitelist.h"

#include <string>
#include <unordered_map>

#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "managed_event.h"

namespace OHOS {
namespace EDM {
namespace {
constexpr const char *POLICY_PREFIX = "POLICY:";
constexpr const char *EVENT_PREFIX = "EVENT:";
} // namespace

std::string SensitiveApiWhitelist::MakePolicyId(uint32_t policyCode)
{
    return std::string(POLICY_PREFIX) + std::to_string(policyCode);
}

std::string SensitiveApiWhitelist::MakeEventId(uint32_t managedEvent)
{
    return std::string(EVENT_PREFIX) + std::to_string(managedEvent);
}

bool SensitiveApiWhitelist::IsSensitive(const std::string &sensitiveId)
{
    return !GetBodyTemplateName(sensitiveId).empty();
}

std::string SensitiveApiWhitelist::GetBodyTemplateName(const std::string &sensitiveId)
{
    static const std::unordered_map<std::string, std::string> sensitiveMap = {
        {MakePolicyId(static_cast<uint32_t>(EdmInterfaceCode::GET_CALL_LOGS)),
            "sensitive_call_notification_body_call_record"},
        {MakePolicyId(static_cast<uint32_t>(EdmInterfaceCode::GET_SMS_MESSAGES)),
            "sensitive_call_notification_body_sms_record"},
        {MakeEventId(static_cast<uint32_t>(ManagedEvent::SMS_RECEIVED)),
            "sensitive_call_notification_body_sms_broadcast"}
    };
    auto it = sensitiveMap.find(sensitiveId);
    return it != sensitiveMap.end() ? it->second : "";
}
} // namespace EDM
} // namespace OHOS
