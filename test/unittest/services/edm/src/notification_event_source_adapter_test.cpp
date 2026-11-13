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

#include <gtest/gtest.h>
#include <memory>

#include "adapter_factory.h"
#include "edm_event_data.h"
#include "event_subscription_manager.h"
#include "managed_event.h"
#include "notification_event_source_adapter.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
namespace {
constexpr int32_t SUBSCRIBE_OK_RET = 0;
constexpr int32_t SUBSCRIBE_FAIL_RET = 1300001;
}

class MockNotificationEventSourceAdapter : public NotificationEventSourceAdapter {
public:
    explicit MockNotificationEventSourceAdapter(EventSubscriptionManager &manager)
        : NotificationEventSourceAdapter(manager)
    {}

    int32_t DoSubscribeNotification() override
    {
        subscribeCalls_++;
        return subscribeResult_;
    }

    int32_t DoUnsubscribeNotification() override
    {
        unsubscribeCalls_++;
        return unsubscribeResult_;
    }

    int32_t subscribeResult_ = SUBSCRIBE_OK_RET;
    int32_t unsubscribeResult_ = SUBSCRIBE_OK_RET;
    int32_t subscribeCalls_ = 0;
    int32_t unsubscribeCalls_ = 0;
};

class NotificationEventSourceAdapterTest : public testing::Test {
protected:
    EventSubscriptionManager &manager_ = EventSubscriptionManager::GetInstance();
};

/**
 * @tc.name: SubscribeEvent_Success
 * @tc.desc: Test SubscribeEvent returns true and creates one ANS subscription.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationEventSourceAdapterTest, SubscribeEvent_Success, TestSize.Level1)
{
    MockNotificationEventSourceAdapter adapter(manager_);
    adapter.subscribeResult_ = SUBSCRIBE_OK_RET;
    EXPECT_TRUE(adapter.SubscribeEvent());
    EXPECT_EQ(adapter.subscribeCalls_, 1);
}

/**
 * @tc.name: SubscribeEvent_Failed
 * @tc.desc: Test SubscribeEvent returns false when ANS rejects the subscription.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationEventSourceAdapterTest, SubscribeEvent_Failed, TestSize.Level1)
{
    MockNotificationEventSourceAdapter adapter(manager_);
    adapter.subscribeResult_ = SUBSCRIBE_FAIL_RET;
    EXPECT_FALSE(adapter.SubscribeEvent());
    EXPECT_EQ(adapter.subscribeCalls_, 1);
}

/**
 * @tc.name: SubscribeEvent_Twice_SubscribesOnlyOnce
 * @tc.desc: Test repeated SubscribeEvent does not create a second ANS subscription.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationEventSourceAdapterTest, SubscribeEvent_Twice_SubscribesOnlyOnce, TestSize.Level1)
{
    MockNotificationEventSourceAdapter adapter(manager_);
    EXPECT_TRUE(adapter.SubscribeEvent());
    EXPECT_TRUE(adapter.SubscribeEvent());
    EXPECT_EQ(adapter.subscribeCalls_, 1);
}

/**
 * @tc.name: UnsubscribeEvent_NotSubscribed_ReturnsTrueWithoutCallingAns
 * @tc.desc: Test UnsubscribeEvent is idempotent when nothing was subscribed.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationEventSourceAdapterTest, UnsubscribeEvent_NotSubscribed_ReturnsTrueWithoutCallingAns,
    TestSize.Level1)
{
    MockNotificationEventSourceAdapter adapter(manager_);
    EXPECT_TRUE(adapter.UnsubscribeEvent());
    EXPECT_EQ(adapter.unsubscribeCalls_, 0);
}

/**
 * @tc.name: UnsubscribeEvent_Twice_UnsubscribesOnlyOnce
 * @tc.desc: Test repeated UnsubscribeEvent calls ANS only once.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationEventSourceAdapterTest, UnsubscribeEvent_Twice_UnsubscribesOnlyOnce, TestSize.Level1)
{
    MockNotificationEventSourceAdapter adapter(manager_);
    EXPECT_TRUE(adapter.SubscribeEvent());
    EXPECT_TRUE(adapter.UnsubscribeEvent());
    EXPECT_TRUE(adapter.UnsubscribeEvent());
    EXPECT_EQ(adapter.unsubscribeCalls_, 1);
}

/**
 * @tc.name: GetAdapterType_ReturnsAnsSubscriber
 * @tc.desc: Test the adapter reports ANS_SUBSCRIBER so CES restart retry does not touch it.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationEventSourceAdapterTest, GetAdapterType_ReturnsAnsSubscriber, TestSize.Level1)
{
    MockNotificationEventSourceAdapter adapter(manager_);
    EXPECT_EQ(adapter.GetAdapterType(), AdapterType::ANS_SUBSCRIBER);
    EXPECT_NE(adapter.GetAdapterType(), AdapterType::COMMON_EVENT);
}

/**
 * @tc.name: CreateAdapter_NotificationReceived_ReturnsAnsAdapter
 * @tc.desc: Test AdapterFactory maps event 10001 to a NotificationEventSourceAdapter instead of nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationEventSourceAdapterTest, CreateAdapter_NotificationReceived_ReturnsAnsAdapter, TestSize.Level1)
{
    EventId groupId {static_cast<uint32_t>(ManagedEvent::NOTIFICATION_RECEIVED)};
    auto adapter = AdapterFactory::CreateAdapter(manager_, groupId);
    ASSERT_NE(adapter, nullptr);
    EXPECT_EQ(adapter->GetAdapterType(), AdapterType::ANS_SUBSCRIBER);
}

/**
 * @tc.name: CreateAdapter_UnknownEvent_StillReturnsNull
 * @tc.desc: Test an event id with no adapter mapping still yields nullptr, so adding
 *   NOTIFICATION_RECEIVED did not make other ids resolvable. SMS_RECEIVED is not a valid
 *   probe here: the factory maps it to a CommonEventAdapter on both sides of the refactor.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationEventSourceAdapterTest, CreateAdapter_UnknownEvent_StillReturnsNull, TestSize.Level1)
{
    EventId groupId {9999};
    auto adapter = AdapterFactory::CreateAdapter(manager_, groupId);
    EXPECT_EQ(adapter, nullptr);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
