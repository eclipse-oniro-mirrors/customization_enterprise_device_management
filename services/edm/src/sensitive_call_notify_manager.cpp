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

#include "sensitive_call_notify_manager.h"

#include <chrono>
#include <thread>

#include "accesstoken_kit.h"
#include "edm_bundle_manager_impl.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_log.h"
#include "ext_info_manager.h"
#include "ipc_skeleton.h"
#include "language_manager.h"
#include "notification_info.h"
#include "notification_manager.h"
#include "sensitive_api_whitelist.h"
#include "sensitive_call_notify_rdb.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<SensitiveCallNotifyManager> SensitiveCallNotifyManager::instance_;
std::once_flag SensitiveCallNotifyManager::flag_;
constexpr float ICON_AXIS = 0.2;

std::shared_ptr<SensitiveCallNotifyManager> SensitiveCallNotifyManager::GetInstance()
{
    std::call_once(flag_, []() {
        if (instance_ == nullptr) {
            instance_.reset(new (std::nothrow) SensitiveCallNotifyManager());
        }
    });
    return instance_;
}

bool SensitiveCallNotifyManager::ResolveCallingIdentity(std::string &bundleName, int32_t &userId,
    int32_t &appIndex)
{
    Security::AccessToken::AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    Security::AccessToken::HapTokenInfo hapTokenInfo;
    if (FAILED(Security::AccessToken::AccessTokenKit::GetHapTokenInfo(tokenId, hapTokenInfo))) {
        EDMLOGE("SensitiveCallNotifyManager::ResolveCallingIdentity GetHapTokenInfo failed.");
        return false;
    }
    bundleName = hapTokenInfo.bundleName;
    userId = hapTokenInfo.userID;
    appIndex = hapTokenInfo.instIndex;
    return true;
}

bool SensitiveCallNotifyManager::IsAlreadyNotified(const std::string &adminName, int32_t userId,
    int32_t appIndex, const std::string &sensitiveId)
{
    auto rdb = SensitiveCallNotifyRdb::GetInstance();
    if (rdb == nullptr) {
        EDMLOGE("SensitiveCallNotifyManager::IsAlreadyNotified rdb null, treat as not notified.");
        return false;
    }
    return rdb->Query(adminName, userId, appIndex, sensitiveId);
}

void SensitiveCallNotifyManager::CheckAndNotify(const std::string &sensitiveId,
    const std::string &adminName, int32_t userId)
{
    if (sensitiveId.empty() || adminName.empty()) {
        EDMLOGW("SensitiveCallNotifyManager::CheckAndNotify invalid param, skip.");
        return;
    }
    std::lock_guard<std::mutex> lock(notifyMutex_);
    // appIndex is not available at the hook signature; resolve from calling token.
    std::string tokenBundleName;
    int32_t tokenUserId = userId;
    int32_t appIndex = 0;
    if (!ResolveCallingIdentity(tokenBundleName, tokenUserId, appIndex)) {
        EDMLOGE("SensitiveCallNotifyManager::CheckAndNotify resolve identity failed, skip. id=%{public}s",
            sensitiveId.c_str());
        return;
    }
    if (IsAlreadyNotified(adminName, userId, appIndex, sensitiveId)) {
        EDMLOGD("SensitiveCallNotifyManager::CheckAndNotify already notified, skip. id=%{public}s",
            sensitiveId.c_str());
        return;
    }
    NotifyAndRecord(adminName, userId, appIndex, sensitiveId);
}

void SensitiveCallNotifyManager::NotifyAndRecord(const std::string &adminName, int32_t userId,
    int32_t appIndex, const std::string &sensitiveId)
{
    // Resolve icon, app name, and body on the calling thread (BundleMgr available
    // here, not in detached thread). Body templates with %s placeholder are
    // resolved from system resources using the admin app's display name.
    EdmBundleManagerImpl bundleManager;
    std::string icon = bundleManager.GetIconByBundleName(adminName);
    IconInfo iconInfo = {.icon = icon, .xAxis = ICON_AXIS, .yAxis = ICON_AXIS};

    std::string appName = bundleManager.GetAppNameByBundleName(adminName);
    if (appName.empty()) {
        appName = adminName;
    }

    std::string bodyTemplate = SensitiveApiWhitelist::GetBodyTemplateName(sensitiveId);
    std::string resolvedBody = LanguageManager::GetSystemStringFormatByName(bodyTemplate, appName);
    if (resolvedBody.empty()) {
        resolvedBody = appName + " is performing a sensitive management operation.";
    }
    WantAgentInfo wantAgentInfo = ExtInfoManager::GetInstance()->GetWantAgentInfo();

    static std::atomic<int32_t> notifId{10000};
    int32_t notifIdVal = notifId.fetch_add(1);
    std::thread([adminName, iconInfo, wantAgentInfo, resolvedBody, notifIdVal, sensitiveId]() {
        NotificationInfo info = { .title = EdmConstants::SENSITIVE_CALL_NOTIFIED_TITLE,
                                  .body = resolvedBody,
                                  .notificationId = notifIdVal };
        NotificationManager notificationManager;
        if (!notificationManager.SendSystemNotification(info, iconInfo, wantAgentInfo)) {
            EDMLOGE("SensitiveCallNotifyManager notify failed, id=%{public}s", sensitiveId.c_str());
        }
    }).detach();

    // Write the record synchronously (local RDB is fast; safe under the lock).
    // Notification failure does not roll back the record (RISK-A2): the record
    // still counts as "notified" so we do not re-notify repeatedly.
    SensitiveCallRecord record;
    record.adminName = adminName;
    record.userId = userId;
    record.appIndex = appIndex;
    record.sensitiveId = sensitiveId;
    record.notifiedTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    auto rdb = SensitiveCallNotifyRdb::GetInstance();
    if (rdb == nullptr || !rdb->Insert(record)) {
        EDMLOGE("SensitiveCallNotifyManager insert record failed, id=%{public}s", sensitiveId.c_str());
    }
}

void SensitiveCallNotifyManager::ClearByAdmin(const std::string &adminName, int32_t userId)
{
    EDMLOGI("SensitiveCallNotifyManager::ClearByAdmin admin=%{public}s", adminName.c_str());
    auto rdb = SensitiveCallNotifyRdb::GetInstance();
    if (rdb == nullptr) {
        EDMLOGE("SensitiveCallNotifyManager::ClearByAdmin rdb null.");
        return;
    }
    rdb->DeleteByAdmin(adminName, userId);
}

void SensitiveCallNotifyManager::ClearByApp(const std::string &bundleName, int32_t appIndex)
{
    EDMLOGI("SensitiveCallNotifyManager::ClearByApp bundle=%{public}s appIndex=%{public}d",
        bundleName.c_str(), appIndex);
    auto rdb = SensitiveCallNotifyRdb::GetInstance();
    if (rdb == nullptr) {
        EDMLOGE("SensitiveCallNotifyManager::ClearByApp rdb null.");
        return;
    }
    rdb->DeleteByApp(bundleName, appIndex);
}
} // namespace EDM
} // namespace OHOS
