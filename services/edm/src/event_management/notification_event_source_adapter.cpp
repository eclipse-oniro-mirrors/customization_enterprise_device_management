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

#include "notification_event_source_adapter.h"

#include "edm_log.h"
#include "notification_helper.h"

namespace OHOS {
namespace EDM {
EdmNotificationSubscriber::EdmNotificationSubscriber(EventSubscriptionManager &manager) : manager_(manager)
{}

void EdmNotificationSubscriber::OnConsumed(const std::shared_ptr<OHOS::Notification::Notification> &request,
    const std::shared_ptr<OHOS::Notification::NotificationSortingMap> &sortingMap)
{
    if (request == nullptr) {
        EDMLOGE("EdmNotificationSubscriber::OnConsumed notification is null");
        return;
    }
    sptr<OHOS::Notification::NotificationRequest> notificationRequest = request->GetNotificationRequestPoint();
    if (notificationRequest == nullptr) {
        EDMLOGE("EdmNotificationSubscriber::OnConsumed notification request is null");
        return;
    }
    EdmEventData data;
    data.eventId = EventId{static_cast<uint32_t>(ManagedEvent::NOTIFICATION_RECEIVED)};
    data.notificationReceivedInfo.hashCode = request->GetKey();
    data.notificationReceivedInfo.bundleName = notificationRequest->GetOwnerBundleName();
    data.notificationReceivedInfo.appIndex = notificationRequest->GetAppIndex();
    data.notificationReceivedInfo.appName = notificationRequest->GetAppName();
    EDMLOGI("EdmNotificationSubscriber::OnConsumed bundleName=%{public}s",
        data.notificationReceivedInfo.bundleName.c_str());
    manager_.DispatchEvent(data);
}

void EdmNotificationSubscriber::OnCanceled(const std::shared_ptr<OHOS::Notification::Notification> &request,
    const std::shared_ptr<OHOS::Notification::NotificationSortingMap> &sortingMap, int32_t deleteReason)
{}

void EdmNotificationSubscriber::OnConnected()
{}

void EdmNotificationSubscriber::OnDisconnected()
{}

void EdmNotificationSubscriber::OnUpdate(const std::shared_ptr<OHOS::Notification::NotificationSortingMap> &sortingMap)
{}

void EdmNotificationSubscriber::OnDied()
{}

void EdmNotificationSubscriber::OnDoNotDisturbDateChange(
    const std::shared_ptr<OHOS::Notification::NotificationDoNotDisturbDate> &date)
{}

void EdmNotificationSubscriber::OnEnabledNotificationChanged(
    const std::shared_ptr<OHOS::Notification::EnabledNotificationCallbackData> &callbackData)
{}

void EdmNotificationSubscriber::OnBadgeChanged(
    const std::shared_ptr<OHOS::Notification::BadgeNumberCallbackData> &badgeData)
{}

void EdmNotificationSubscriber::OnBadgeEnabledChanged(
    const sptr<OHOS::Notification::EnabledNotificationCallbackData> &callbackData)
{}

void EdmNotificationSubscriber::OnBatchCanceled(
    const std::vector<std::shared_ptr<OHOS::Notification::Notification>> &requestList,
    const std::shared_ptr<OHOS::Notification::NotificationSortingMap> &sortingMap, int32_t deleteReason)
{}

NotificationEventSourceAdapter::NotificationEventSourceAdapter(EventSubscriptionManager &manager)
    : manager_(manager)
{}

NotificationEventSourceAdapter::~NotificationEventSourceAdapter()
{
    if (isSubscribed_) {
        UnsubscribeEvent();
    }
}

bool NotificationEventSourceAdapter::SubscribeEvent()
{
    if (isSubscribed_) {
        return true;
    }
    if (subscriber_ == nullptr) {
        subscriber_ = std::make_shared<EdmNotificationSubscriber>(manager_);
    }
    int32_t ret = DoSubscribeNotification();
    if (ret != ERR_OK) {
        EDMLOGE("NotificationEventSourceAdapter::SubscribeEvent failed ret=%{public}d", ret);
        return false;
    }
    isSubscribed_ = true;
    EDMLOGI("NotificationEventSourceAdapter::SubscribeEvent success");
    return true;
}

bool NotificationEventSourceAdapter::UnsubscribeEvent()
{
    if (subscriber_ == nullptr || !isSubscribed_) {
        isSubscribed_ = false;
        return true;
    }
    int32_t ret = DoUnsubscribeNotification();
    if (ret != ERR_OK) {
        EDMLOGE("NotificationEventSourceAdapter::UnsubscribeEvent failed ret=%{public}d", ret);
    }
    isSubscribed_ = false;
    EDMLOGI("NotificationEventSourceAdapter::UnsubscribeEvent success");
    return true;
}

int32_t NotificationEventSourceAdapter::DoSubscribeNotification()
{
    return OHOS::Notification::NotificationHelper::SubscribeNotification(subscriber_);
}

int32_t NotificationEventSourceAdapter::DoUnsubscribeNotification()
{
    return OHOS::Notification::NotificationHelper::UnSubscribeNotification(subscriber_);
}
} // namespace EDM
} // namespace OHOS
