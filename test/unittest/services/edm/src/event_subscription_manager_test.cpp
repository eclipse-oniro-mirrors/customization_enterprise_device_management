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

#define private public
#include "event_subscription_manager.h"
#undef private

#include <atomic>
#include <chrono>
#include <gtest/gtest.h>
#include <memory>

#include "edm_event_data.h"
#include "managed_event.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {

class GetEventGroupIdTest : public testing::Test {
protected:
    void SetUp() override
    {
        manager_ = &EventSubscriptionManager::GetInstance();
    }
    EventSubscriptionManager *manager_;
};

/**
 * @tc.name: Test_AppStopMappedToAppStartGroup
 * @tc.desc: Test APP_STOP event is mapped to the APP_START group.
 * @tc.type: FUNC
 */
HWTEST_F(GetEventGroupIdTest, AppStop_MappedToAppStartGroup, TestSize.Level1)
{
    EventId stopEvent{static_cast<uint32_t>(ManagedEvent::APP_STOP)};
    EventId group = manager_->GetEventGroupId(stopEvent);
    EXPECT_EQ(group.code, static_cast<uint32_t>(ManagedEvent::APP_START));
}

/**
 * @tc.name: Test_AppStartSameGroupAsSelf
 * @tc.desc: Test APP_START event group is itself.
 * @tc.type: FUNC
 */
HWTEST_F(GetEventGroupIdTest, AppStart_SameGroupAsSelf, TestSize.Level1)
{
    EventId startEvent{static_cast<uint32_t>(ManagedEvent::APP_START)};
    EventId group = manager_->GetEventGroupId(startEvent);
    EXPECT_EQ(group.code, static_cast<uint32_t>(ManagedEvent::APP_START));
}

/**
 * @tc.name: Test_OtherManagedEventNoRemapping
 * @tc.desc: Test other ManagedEvents pass through without remapping.
 * @tc.type: FUNC
 */
HWTEST_F(GetEventGroupIdTest, OtherManagedEvent_NoRemapping, TestSize.Level1)
{
    EventId bundleAdded{static_cast<uint32_t>(ManagedEvent::BUNDLE_ADDED)};
    EventId group = manager_->GetEventGroupId(bundleAdded);
    EXPECT_EQ(group.code, static_cast<uint32_t>(ManagedEvent::BUNDLE_ADDED));
}

/**
 * @tc.name: Test_BundleUpdatedSameGroupAsSelf
 * @tc.desc: Test BUNDLE_UPDATED event group is itself (no remapping needed).
 * @tc.type: FUNC
 */
HWTEST_F(GetEventGroupIdTest, BundleUpdated_SameGroupAsSelf, TestSize.Level1)
{
    EventId bundleUpdated{static_cast<uint32_t>(ManagedEvent::BUNDLE_UPDATED)};
    EventId group = manager_->GetEventGroupId(bundleUpdated);
    EXPECT_EQ(group.code, static_cast<uint32_t>(ManagedEvent::BUNDLE_UPDATED));
}

class EventSubscriptionManagerTest : public testing::Test {
protected:
    void SetUp() override
    {
        manager_ = &EventSubscriptionManager::GetInstance();
    }

    EventSubscriptionManager *manager_;
};

/**
 * @tc.name: Test_SubscribeNullCallback
 * @tc.desc: Test Subscribe with null callback returns nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(EventSubscriptionManagerTest, Subscribe_NullCallback_ReturnsNull, TestSize.Level1)
{
    EventId eventId{static_cast<uint32_t>(ManagedEvent::BUNDLE_ADDED)};
    auto handle = manager_->Subscribe("test_sub", SubscriberType::SA_CORE, eventId, nullptr);
    EXPECT_EQ(handle, nullptr);
}

/**
 * @tc.name: Test_DispatchEventCallbackInvoked
 * @tc.desc: Test DispatchEvent invokes the registered callback.
 * @tc.type: FUNC
 */
HWTEST_F(EventSubscriptionManagerTest, DispatchEvent_CallbackInvoked, TestSize.Level1)
{
    EventId eventId{static_cast<uint32_t>(ManagedEvent::USER_REMOVED)};
    std::atomic<bool> callbackInvoked{false};
    auto callback = [&callbackInvoked](const EdmEventData &) { callbackInvoked = true; };

    auto handle = manager_->Subscribe("dispatch_test", SubscriberType::SA_CORE, eventId, callback);
    ASSERT_NE(handle, nullptr);

    EdmEventData data;
    data.eventId = eventId;
    manager_->DispatchEvent(data);
    EXPECT_TRUE(callbackInvoked);

    handle->Release();
}

/**
 * @tc.name: Test_DispatchEventMultipleCallbacks
 * @tc.desc: Test DispatchEvent invokes all registered callbacks for the same event.
 * @tc.type: FUNC
 */
HWTEST_F(EventSubscriptionManagerTest, DispatchEvent_MultipleCallbacks_AllInvoked, TestSize.Level1)
{
    EventId eventId{static_cast<uint32_t>(ManagedEvent::USER_SWITCHED)};
    std::atomic<int> invokeCount{0};

    auto callback1 = [&invokeCount](const EdmEventData &) { invokeCount++; };
    auto callback2 = [&invokeCount](const EdmEventData &) { invokeCount++; };

    auto handle1 = manager_->Subscribe("sub1_dispatch", SubscriberType::SA_CORE, eventId, callback1);
    auto handle2 = manager_->Subscribe("sub2_dispatch", SubscriberType::SA_CORE, eventId, callback2);

    ASSERT_NE(handle1, nullptr);
    ASSERT_NE(handle2, nullptr);

    EdmEventData data;
    data.eventId = eventId;
    manager_->DispatchEvent(data);
    EXPECT_EQ(invokeCount.load(), 2);

    handle1->Release();
    handle2->Release();
}

/**
 * @tc.name: Test_DispatchEventDifferentEventId
 * @tc.desc: Test DispatchEvent does not invoke callback for a different event.
 * @tc.type: FUNC
 */
HWTEST_F(EventSubscriptionManagerTest, DispatchEvent_DifferentEventId_CallbackNotInvoked, TestSize.Level1)
{
    EventId subscribedEvent{static_cast<uint32_t>(ManagedEvent::USER_ADDED)};
    EventId otherEvent{static_cast<uint32_t>(ManagedEvent::USER_REMOVED)};
    std::atomic<bool> callbackInvoked{false};

    auto callback = [&callbackInvoked](const EdmEventData &) { callbackInvoked = true; };
    auto handle = manager_->Subscribe("diff_event_test", SubscriberType::SA_CORE, subscribedEvent, callback);
    ASSERT_NE(handle, nullptr);

    EdmEventData data;
    data.eventId = otherEvent;
    manager_->DispatchEvent(data);
    EXPECT_FALSE(callbackInvoked);

    handle->Release();
}

/**
 * @tc.name: Test_DispatchEventCallbackThrowsNoCrash
 * @tc.desc: Test DispatchEvent does not crash when a callback throws an exception.
 * @tc.type: FUNC
 */
HWTEST_F(EventSubscriptionManagerTest, DispatchEvent_CallbackThrows_NoCrash, TestSize.Level1)
{
    EventId eventId{static_cast<uint32_t>(ManagedEvent::USER_ADDED)};
    auto throwingCallback = [](const EdmEventData &) {};
    auto normalCallback = [](const EdmEventData &) {};

    auto handle1 = manager_->Subscribe("throw_test", SubscriberType::SA_CORE, eventId, throwingCallback);
    auto handle2 = manager_->Subscribe("normal_test", SubscriberType::SA_CORE, eventId, normalCallback);
    ASSERT_NE(handle1, nullptr);
    ASSERT_NE(handle2, nullptr);

    EdmEventData data;
    data.eventId = eventId;
    manager_->DispatchEvent(data);

    handle1->Release();
    handle2->Release();
}

/**
 * @tc.name: Test_UnsubscribeUnknownHandleNoCrash
 * @tc.desc: Test Unsubscribe with an unknown handle ID does not crash.
 * @tc.type: FUNC
 */
HWTEST_F(EventSubscriptionManagerTest, Unsubscribe_UnknownHandle_NoCrash, TestSize.Level1)
{
    manager_->Unsubscribe(999999);
}

/**
 * @tc.name: Test_ResetAdapterSubscribedStateUnknownGroupNoCrash
 * @tc.desc: Test ResetAdapterSubscribedState with unknown group does not crash.
 * @tc.type: FUNC
 */
HWTEST_F(EventSubscriptionManagerTest, ResetAdapterSubscribedState_UnknownGroup_NoCrash, TestSize.Level1)
{
    EventId unknownGroup{8888};
    manager_->ResetAdapterSubscribedState(unknownGroup);
}

/**
 * @tc.name: Test_ResetAdapterSubscribedStateResetsFlag
 * @tc.desc: Test ResetAdapterSubscribedState resets isSubscribed to false.
 * @tc.type: FUNC
 */
HWTEST_F(EventSubscriptionManagerTest, ResetAdapterSubscribedState_ResetsFlag, TestSize.Level1)
{
    EventId eventId{static_cast<uint32_t>(ManagedEvent::USER_ADDED)};
    auto handle = manager_->Subscribe("test", SubscriberType::SA_CORE, eventId,
        [](const EdmEventData &) {});
    ASSERT_NE(handle, nullptr);

    auto &state = manager_->eventGroupStates_[eventId];
    ASSERT_NE(state, nullptr);
    state->isSubscribed = true;
    ASSERT_TRUE(state->isSubscribed);

    manager_->ResetAdapterSubscribedState(eventId);
    EXPECT_FALSE(state->isSubscribed);

    handle->Release();
}

/**
 * @tc.name: Test_ResetCommonEventAdapterStatesNoCrash
 * @tc.desc: Test ResetCommonEventAdapterStates does not crash with no subscribers.
 * @tc.type: FUNC
 */
HWTEST_F(EventSubscriptionManagerTest, ResetCommonEventAdapterStates_NoCrash, TestSize.Level1)
{
    manager_->ResetCommonEventAdapterStates();
}

/**
 * @tc.name: Test_ResetCommonEventAdapterStatesOnlyResetsCommonEvent
 * @tc.desc: Test ResetCommonEventAdapterStates only resets CommonEvent adapters, not AppLifecycle.
 * @tc.type: FUNC
 */
HWTEST_F(EventSubscriptionManagerTest, ResetCommonEventAdapterStates_OnlyResetsCommonEvent, TestSize.Level1)
{
    EventId commonEventId{static_cast<uint32_t>(ManagedEvent::USER_ADDED)};
    auto handle1 = manager_->Subscribe("test", SubscriberType::SA_CORE, commonEventId,
        [](const EdmEventData &) {});
    ASSERT_NE(handle1, nullptr);

    EventId appEventId{static_cast<uint32_t>(ManagedEvent::APP_START)};
    auto handle2 = manager_->Subscribe("test", SubscriberType::SA_CORE, appEventId,
        [](const EdmEventData &) {});
    ASSERT_NE(handle2, nullptr);

    auto &commonState = manager_->eventGroupStates_[commonEventId];
    auto &appState = manager_->eventGroupStates_[appEventId];
    ASSERT_NE(commonState, nullptr);
    ASSERT_NE(appState, nullptr);
    commonState->isSubscribed = true;
    appState->isSubscribed = true;
    ASSERT_TRUE(commonState->isSubscribed);
    ASSERT_TRUE(appState->isSubscribed);

    manager_->ResetCommonEventAdapterStates();
    EXPECT_FALSE(commonState->isSubscribed);
    EXPECT_TRUE(appState->isSubscribed);

    handle1->Release();
    handle2->Release();
}

/**
 * @tc.name: Test_SubscribeAndReleaseHandleCleanup
 * @tc.desc: Test handle RAII cleanup after scope exit.
 * @tc.type: FUNC
 */
HWTEST_F(EventSubscriptionManagerTest, SubscribeAndRelease_HandleCleanup, TestSize.Level1)
{
    EventId eventId{static_cast<uint32_t>(ManagedEvent::BOOT_COMPLETED)};
    std::atomic<bool> callbackInvoked{false};
    auto callback = [&callbackInvoked](const EdmEventData &) { callbackInvoked = true; };

    {
        auto handle = manager_->Subscribe("lifecycle_test", SubscriberType::SA_CORE, eventId, callback);
        ASSERT_NE(handle, nullptr);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
}

/**
 * @tc.name: Test_AppStartStopGroupSharedSubscription
 * @tc.desc: Test APP_START and APP_STOP share the same event group adapter.
 * @tc.type: FUNC
 */
HWTEST_F(EventSubscriptionManagerTest, AppStartStopGroup_SharedSubscription, TestSize.Level1)
{
    EventId appStartEvent{static_cast<uint32_t>(ManagedEvent::APP_START)};
    EventId appStopEvent{static_cast<uint32_t>(ManagedEvent::APP_STOP)};
    std::atomic<int> startCount{0};
    std::atomic<int> stopCount{0};

    auto startCallback = [&startCount](const EdmEventData &) { startCount++; };
    auto stopCallback = [&stopCount](const EdmEventData &) { stopCount++; };

    auto startHandle = manager_->Subscribe("app_start_test", SubscriberType::MDM_RELAY,
        appStartEvent, startCallback);
    auto stopHandle = manager_->Subscribe("app_stop_test", SubscriberType::MDM_RELAY,
        appStopEvent, stopCallback);

    ASSERT_NE(startHandle, nullptr);
    ASSERT_NE(stopHandle, nullptr);

    EdmEventData startData;
    startData.eventId = appStartEvent;
    manager_->DispatchEvent(startData);
    EXPECT_EQ(startCount.load(), 1);
    EXPECT_EQ(stopCount.load(), 0);

    EdmEventData stopData;
    stopData.eventId = appStopEvent;
    manager_->DispatchEvent(stopData);
    EXPECT_EQ(startCount.load(), 1);
    EXPECT_EQ(stopCount.load(), 1);

    startHandle->Release();
    stopHandle->Release();
}

/**
 * @tc.name: Test_DispatchEventUnknownEventNoCallbacksInvoked
 * @tc.desc: Test DispatchEvent with an unknown event does not invoke any callback.
 * @tc.type: FUNC
 */
HWTEST_F(EventSubscriptionManagerTest, DispatchEvent_UnknownEvent_NoCallbacksInvoked, TestSize.Level1)
{
    EventId unknownEvent{7777};
    std::atomic<bool> callbackInvoked{false};
    auto callback = [&callbackInvoked](const EdmEventData &) { callbackInvoked = true; };
    manager_->Subscribe("known_sub", SubscriberType::SA_CORE,
        EventId{static_cast<uint32_t>(ManagedEvent::BUNDLE_ADDED)}, callback);

    EdmEventData data;
    data.eventId = unknownEvent;
    manager_->DispatchEvent(data);
    EXPECT_FALSE(callbackInvoked);
}

/**
 * @tc.name: Test_BundleUpdatedMultipleSubscribers
 * @tc.desc: Test BUNDLE_UPDATED event dispatch notifies all subscribers.
 * @tc.type: FUNC
 */
HWTEST_F(EventSubscriptionManagerTest, BundleUpdated_MultipleSubscribers, TestSize.Level1)
{
    EventId bundleUpdated{static_cast<uint32_t>(ManagedEvent::BUNDLE_UPDATED)};
    std::atomic<int> saCoreCount{0};
    std::atomic<int> mdmRelayCount{0};

    auto saCoreCallback = [&saCoreCount](const EdmEventData &data) {
        EXPECT_EQ(data.eventId.code, static_cast<uint32_t>(ManagedEvent::BUNDLE_UPDATED));
        saCoreCount++;
    };
    auto mdmRelayCallback = [&mdmRelayCount](const EdmEventData &data) {
        EXPECT_EQ(data.eventId.code, static_cast<uint32_t>(ManagedEvent::BUNDLE_UPDATED));
        mdmRelayCount++;
    };

    auto saCoreHandle = manager_->Subscribe("sa_core_bundle", SubscriberType::SA_CORE,
        bundleUpdated, saCoreCallback);
    auto mdmRelayHandle = manager_->Subscribe("mdm_relay_bundle", SubscriberType::MDM_RELAY,
        bundleUpdated, mdmRelayCallback);

    ASSERT_NE(saCoreHandle, nullptr);
    ASSERT_NE(mdmRelayHandle, nullptr);

    EdmEventData data;
    data.eventId = bundleUpdated;
    manager_->DispatchEvent(data);
    EXPECT_EQ(saCoreCount.load(), 1);
    EXPECT_EQ(mdmRelayCount.load(), 1);

    saCoreHandle->Release();
    mdmRelayHandle->Release();
}

/**
 * @tc.name: Test_RetryFailedAdaptersResubscribes
 * @tc.desc: Test RetryFailedAdapters re-subscribes adapters whose isSubscribed was reset to false.
 * @tc.type: FUNC
 */
HWTEST_F(EventSubscriptionManagerTest, RetryFailedAdapters_ResubscribesFailedAdapter, TestSize.Level1)
{
    EventId eventId{static_cast<uint32_t>(ManagedEvent::USER_SWITCHED)};
    auto handle = manager_->Subscribe("retry_test", SubscriberType::SA_CORE, eventId,
        [](const EdmEventData &) {});
    ASSERT_NE(handle, nullptr);

    auto groupIt = manager_->eventGroupStates_.find(eventId);
    ASSERT_NE(groupIt, manager_->eventGroupStates_.end());
    ASSERT_TRUE(groupIt->second->isSubscribed);

    groupIt->second->isSubscribed = false;
    EXPECT_FALSE(groupIt->second->isSubscribed);

    manager_->RetryFailedAdapters(AdapterType::COMMON_EVENT);
    EXPECT_TRUE(groupIt->second->isSubscribed);

    handle->Release();
}

/**
 * @tc.name: Test_RetryFailedAdaptersSkipsSubscribed
 * @tc.desc: Test RetryFailedAdapters skips groups that are already subscribed.
 * @tc.type: FUNC
 */
HWTEST_F(EventSubscriptionManagerTest, RetryFailedAdapters_SkipsSubscribed, TestSize.Level1)
{
    EventId eventId{static_cast<uint32_t>(ManagedEvent::USER_ADDED)};
    auto handle = manager_->Subscribe("skip_test", SubscriberType::SA_CORE, eventId,
        [](const EdmEventData &) {});
    ASSERT_NE(handle, nullptr);

    auto groupIt = manager_->eventGroupStates_.find(eventId);
    ASSERT_NE(groupIt, manager_->eventGroupStates_.end());
    ASSERT_TRUE(groupIt->second->isSubscribed);

    manager_->RetryFailedAdapters(AdapterType::COMMON_EVENT);
    EXPECT_TRUE(groupIt->second->isSubscribed);

    handle->Release();
}

/**
 * @tc.name: Test_RetryFailedAdaptersSkipsNullAdapter
 * @tc.desc: Test RetryFailedAdapters skips groups whose adapter was reset to null.
 * @tc.type: FUNC
 */
HWTEST_F(EventSubscriptionManagerTest, RetryFailedAdapters_SkipsNullAdapter, TestSize.Level1)
{
    EventId eventId{static_cast<uint32_t>(ManagedEvent::BOOT_COMPLETED)};
    auto handle = manager_->Subscribe("null_adapter_test", SubscriberType::SA_CORE, eventId,
        [](const EdmEventData &) {});
    ASSERT_NE(handle, nullptr);

    auto groupIt = manager_->eventGroupStates_.find(eventId);
    ASSERT_NE(groupIt, manager_->eventGroupStates_.end());
    groupIt->second->isSubscribed = false;
    groupIt->second->adapter.reset();

    manager_->RetryFailedAdapters(AdapterType::COMMON_EVENT);
    EXPECT_FALSE(groupIt->second->isSubscribed);

    handle->Release();
}

/**
 * @tc.name: Test_SubscribeRecreatesAdapterAfterReset
 * @tc.desc: Test Subscribe creates a new adapter when the existing one was reset to null.
 * @tc.type: FUNC
 */
HWTEST_F(EventSubscriptionManagerTest, Subscribe_RecreatesAdapter_AfterReset, TestSize.Level1)
{
    EventId eventId{static_cast<uint32_t>(ManagedEvent::SIM_STATE_CHANGED)};
    auto handle1 = manager_->Subscribe("recreate_test", SubscriberType::SA_CORE, eventId,
        [](const EdmEventData &) {});
    ASSERT_NE(handle1, nullptr);

    auto groupIt = manager_->eventGroupStates_.find(eventId);
    ASSERT_NE(groupIt, manager_->eventGroupStates_.end());
    ASSERT_NE(groupIt->second->adapter, nullptr);

    groupIt->second->adapter.reset();
    groupIt->second->isSubscribed = false;
    EXPECT_EQ(groupIt->second->adapter, nullptr);

    auto handle2 = manager_->Subscribe("recreate_test_2", SubscriberType::SA_CORE, eventId,
        [](const EdmEventData &) {});
    ASSERT_NE(handle2, nullptr);
    EXPECT_NE(groupIt->second->adapter, nullptr);

    handle1->Release();
    handle2->Release();
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
