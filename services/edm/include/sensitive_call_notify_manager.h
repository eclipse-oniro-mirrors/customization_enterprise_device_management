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

#ifndef SERVICES_EDM_INCLUDE_SENSITIVE_CALL_NOTIFY_MANAGER_H
#define SERVICES_EDM_INCLUDE_SENSITIVE_CALL_NOTIFY_MANAGER_H

#include <memory>
#include <mutex>
#include <string>

namespace OHOS {
namespace EDM {
// Cross-cutting observer (NOT an IPlugin) that, when an MDM admin app first
// calls a sensitive operation, sends a system notification to the device user
// and persists an "already notified" record for dedup + compliance evidence.
// Hook points decide sensitivity via SensitiveApiWhitelist and only call
// CheckAndNotify when the canonical sensitiveId is in the whitelist.
class SensitiveCallNotifyManager {
public:
    static std::shared_ptr<SensitiveCallNotifyManager> GetInstance();

    // Called by hook points after a sensitive op succeeded. sensitiveId is the
    // canonical string (e.g. "POLICY:1002" / "EVENT:27"). adminName is the
    // calling admin bundle name (available at both hook points). userId is the
    // OS account id. Records are keyed by (adminName, userId, appIndex,
    // sensitiveId); appIndex is resolved from the calling token.
    void CheckAndNotify(const std::string &sensitiveId, const std::string &adminName, int32_t userId);

    // Cleanup on admin deactivation (hooked in RemoveAdminAndAdminPolicy).
    void ClearByAdmin(const std::string &adminName, int32_t userId);
    // Cleanup on app uninstall (hooked in OnCommonEventPackageRemoved).
    void ClearByApp(const std::string &bundleName, int32_t appIndex);

    ~SensitiveCallNotifyManager() = default;
private:
    SensitiveCallNotifyManager() = default;
    static std::once_flag flag_;
    static std::shared_ptr<SensitiveCallNotifyManager> instance_;

    bool ResolveCallingIdentity(std::string &bundleName, int32_t &userId, int32_t &appIndex);
    bool IsAlreadyNotified(const std::string &adminName, int32_t userId, int32_t appIndex,
        const std::string &sensitiveId);
    void NotifyAndRecord(const std::string &adminName, int32_t userId, int32_t appIndex,
        const std::string &sensitiveId);
    std::mutex notifyMutex_;
};
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_INCLUDE_SENSITIVE_CALL_NOTIFY_MANAGER_H
