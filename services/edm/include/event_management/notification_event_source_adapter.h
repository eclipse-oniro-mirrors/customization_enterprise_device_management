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

#ifndef SERVICES_EDM_INCLUDE_EVENT_MANAGEMENT_NOTIFICATION_EVENT_SOURCE_ADAPTER_H
#define SERVICES_EDM_INCLUDE_EVENT_MANAGEMENT_NOTIFICATION_EVENT_SOURCE_ADAPTER_H

#include <memory>

#include "event_subscription_manager.h"
#include "i_event_source_adapter.h"
#include "notification_subscriber.h"

namespace OHOS {
namespace EDM {
class EdmNotificationSubscriber : public OHOS::Notification::NotificationSubscriber {
public:
    explicit EdmNotificationSubscriber(EventSubscriptionManager &manager);
    ~EdmNotificationSubscriber() override = default;

    void OnCanceled(const std::shared_ptr<OHOS::Notification::Notification> &request,
        const std::shared_ptr<OHOS::Notification::NotificationSortingMap> &sortingMap,
        int32_t deleteReason) override;
    void OnConnected() override;
    void OnConsumed(const std::shared_ptr<OHOS::Notification::Notification> &request,
        const std::shared_ptr<OHOS::Notification::NotificationSortingMap> &sortingMap) override;
    void OnDisconnected() override;
    void OnUpdate(const std::shared_ptr<OHOS::Notification::NotificationSortingMap> &sortingMap) override;
    void OnDied() override;
    void OnDoNotDisturbDateChange(
        const std::shared_ptr<OHOS::Notification::NotificationDoNotDisturbDate> &date) override;
    void OnEnabledNotificationChanged(
        const std::shared_ptr<OHOS::Notification::EnabledNotificationCallbackData> &callbackData) override;
    void OnBadgeChanged(const std::shared_ptr<OHOS::Notification::BadgeNumberCallbackData> &badgeData) override;
    void OnBadgeEnabledChanged(
        const sptr<OHOS::Notification::EnabledNotificationCallbackData> &callbackData) override;
    void OnBatchCanceled(const std::vector<std::shared_ptr<OHOS::Notification::Notification>> &requestList,
        const std::shared_ptr<OHOS::Notification::NotificationSortingMap> &sortingMap,
        int32_t deleteReason) override;

private:
    EventSubscriptionManager &manager_;
};

class NotificationEventSourceAdapter : public IEventSourceAdapter {
public:
    explicit NotificationEventSourceAdapter(EventSubscriptionManager &manager);
    ~NotificationEventSourceAdapter() override;

    bool SubscribeEvent() override;
    bool UnsubscribeEvent() override;
    AdapterType GetAdapterType() const override
    {
        return AdapterType::ANS_SUBSCRIBER;
    }

protected:
    virtual int32_t DoSubscribeNotification();
    virtual int32_t DoUnsubscribeNotification();

private:
    EventSubscriptionManager &manager_;
    std::shared_ptr<EdmNotificationSubscriber> subscriber_;
    bool isSubscribed_ = false;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_EVENT_MANAGEMENT_NOTIFICATION_EVENT_SOURCE_ADAPTER_H
