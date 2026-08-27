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
#include "adapter_factory.h"
#include "app_lifecycle_adapter.h"
#include "common_event_adapter.h"
#include "event_subscription_manager.h"
#undef private

#include <gtest/gtest.h>
#include <memory>
#include <string>

#include "managed_event.h"
#include "managed_event.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {

class ConvertToCommonEventTest : public testing::Test {};

/**
 * @tc.name: Test_BundleAddedMappedCorrectly
 * @tc.desc: Test BUNDLE_ADDED maps to COMMON_EVENT_PACKAGE_ADDED.
 * @tc.type: FUNC
 */
HWTEST_F(ConvertToCommonEventTest, BundleAdded_MappedCorrectly, TestSize.Level1)
{
    EventId eventId{static_cast<uint32_t>(ManagedEvent::BUNDLE_ADDED)};
    std::string commonEvent;
    bool result = AdapterFactory::ConvertToCommonEvent(eventId, commonEvent);
    EXPECT_TRUE(result);
    EXPECT_EQ(commonEvent, EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
}

/**
 * @tc.name: Test_BundleRemovedMappedCorrectly
 * @tc.desc: Test BUNDLE_REMOVED maps to COMMON_EVENT_PACKAGE_REMOVED.
 * @tc.type: FUNC
 */
HWTEST_F(ConvertToCommonEventTest, BundleRemoved_MappedCorrectly, TestSize.Level1)
{
    EventId eventId{static_cast<uint32_t>(ManagedEvent::BUNDLE_REMOVED)};
    std::string commonEvent;
    bool result = AdapterFactory::ConvertToCommonEvent(eventId, commonEvent);
    EXPECT_TRUE(result);
    EXPECT_EQ(commonEvent, EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
}

/**
 * @tc.name: Test_UserAddedMappedCorrectly
 * @tc.desc: Test USER_ADDED maps to COMMON_EVENT_USER_ADDED.
 * @tc.type: FUNC
 */
HWTEST_F(ConvertToCommonEventTest, UserAdded_MappedCorrectly, TestSize.Level1)
{
    EventId eventId{static_cast<uint32_t>(ManagedEvent::USER_ADDED)};
    std::string commonEvent;
    bool result = AdapterFactory::ConvertToCommonEvent(eventId, commonEvent);
    EXPECT_TRUE(result);
    EXPECT_EQ(commonEvent, EventFwk::CommonEventSupport::COMMON_EVENT_USER_ADDED);
}

/**
 * @tc.name: Test_UserSwitchedMappedCorrectly
 * @tc.desc: Test USER_SWITCHED maps to COMMON_EVENT_USER_SWITCHED.
 * @tc.type: FUNC
 */
HWTEST_F(ConvertToCommonEventTest, UserSwitched_MappedCorrectly, TestSize.Level1)
{
    EventId eventId{static_cast<uint32_t>(ManagedEvent::USER_SWITCHED)};
    std::string commonEvent;
    bool result = AdapterFactory::ConvertToCommonEvent(eventId, commonEvent);
    EXPECT_TRUE(result);
    EXPECT_EQ(commonEvent, EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
}

/**
 * @tc.name: Test_UserRemovedMappedCorrectly
 * @tc.desc: Test USER_REMOVED maps to COMMON_EVENT_USER_REMOVED.
 * @tc.type: FUNC
 */
HWTEST_F(ConvertToCommonEventTest, UserRemoved_MappedCorrectly, TestSize.Level1)
{
    EventId eventId{static_cast<uint32_t>(ManagedEvent::USER_REMOVED)};
    std::string commonEvent;
    bool result = AdapterFactory::ConvertToCommonEvent(eventId, commonEvent);
    EXPECT_TRUE(result);
    EXPECT_EQ(commonEvent, EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED);
}

/**
 * @tc.name: Test_BootCompletedMappedCorrectly
 * @tc.desc: Test BOOT_COMPLETED maps to COMMON_EVENT_BOOT_COMPLETED.
 * @tc.type: FUNC
 */
HWTEST_F(ConvertToCommonEventTest, BootCompleted_MappedCorrectly, TestSize.Level1)
{
    EventId eventId{static_cast<uint32_t>(ManagedEvent::BOOT_COMPLETED)};
    std::string commonEvent;
    bool result = AdapterFactory::ConvertToCommonEvent(eventId, commonEvent);
    EXPECT_TRUE(result);
    EXPECT_EQ(commonEvent, EventFwk::CommonEventSupport::COMMON_EVENT_BOOT_COMPLETED);
}

/**
 * @tc.name: Test_BundleUpdatedMappedCorrectly
 * @tc.desc: Test BUNDLE_UPDATED maps to COMMON_EVENT_PACKAGE_CHANGED.
 * @tc.type: FUNC
 */
HWTEST_F(ConvertToCommonEventTest, BundleUpdated_MappedCorrectly, TestSize.Level1)
{
    EventId eventId{static_cast<uint32_t>(ManagedEvent::BUNDLE_UPDATED)};
    std::string commonEvent;
    bool result = AdapterFactory::ConvertToCommonEvent(eventId, commonEvent);
    EXPECT_TRUE(result);
    EXPECT_EQ(commonEvent, EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED);
}

/**
 * @tc.name: Test_UnknownManagedEventReturnsFalse
 * @tc.desc: Test unknown managed event code returns false.
 * @tc.type: FUNC
 */
HWTEST_F(ConvertToCommonEventTest, UnknownManagedEvent_ReturnsFalse, TestSize.Level1)
{
    EventId eventId{9999};
    std::string commonEvent;
    bool result = AdapterFactory::ConvertToCommonEvent(eventId, commonEvent);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: Test_EdmInternalBmsReadyMappedCorrectly
 * @tc.desc: Test ManagedEvent BMS_READY maps to COMMON_EVENT_BUNDLE_SCAN_FINISHED.
 * @tc.type: FUNC
 */
HWTEST_F(ConvertToCommonEventTest, EdmInternalBmsReady_MappedCorrectly, TestSize.Level1)
{
    EventId eventId{static_cast<uint32_t>(ManagedEvent::BMS_READY)};
    std::string commonEvent;
    bool result = AdapterFactory::ConvertToCommonEvent(eventId, commonEvent);
    EXPECT_TRUE(result);
    EXPECT_EQ(commonEvent, EventFwk::CommonEventSupport::COMMON_EVENT_BUNDLE_SCAN_FINISHED);
}

/**
 * @tc.name: Test_EdmInternalKioskModeOnMappedCorrectly
 * @tc.desc: Test ManagedEvent KIOSK_MODE_ON maps correctly.
 * @tc.type: FUNC
 */
HWTEST_F(ConvertToCommonEventTest, EdmInternalKioskModeOn_MappedCorrectly, TestSize.Level1)
{
    EventId eventId{static_cast<uint32_t>(ManagedEvent::KIOSK_MODE_ON)};
    std::string commonEvent;
    bool result = AdapterFactory::ConvertToCommonEvent(eventId, commonEvent);
    EXPECT_TRUE(result);
    EXPECT_EQ(commonEvent, EventFwk::CommonEventSupport::COMMON_EVENT_KIOSK_MODE_ON);
}

/**
 * @tc.name: Test_EdmInternalKioskModeOffMappedCorrectly
 * @tc.desc: Test ManagedEvent KIOSK_MODE_OFF maps correctly.
 * @tc.type: FUNC
 */
HWTEST_F(ConvertToCommonEventTest, EdmInternalKioskModeOff_MappedCorrectly, TestSize.Level1)
{
    EventId eventId{static_cast<uint32_t>(ManagedEvent::KIOSK_MODE_OFF)};
    std::string commonEvent;
    bool result = AdapterFactory::ConvertToCommonEvent(eventId, commonEvent);
    EXPECT_TRUE(result);
    EXPECT_EQ(commonEvent, EventFwk::CommonEventSupport::COMMON_EVENT_KIOSK_MODE_OFF);
}

/**
 * @tc.name: Test_EdmInternalSimStateChangedMappedCorrectly
 * @tc.desc: Test ManagedEvent SIM_STATE_CHANGED maps correctly.
 * @tc.type: FUNC
 */
HWTEST_F(ConvertToCommonEventTest, EdmInternalSimStateChanged_MappedCorrectly, TestSize.Level1)
{
    EventId eventId{static_cast<uint32_t>(ManagedEvent::SIM_STATE_CHANGED)};
    std::string commonEvent;
    bool result = AdapterFactory::ConvertToCommonEvent(eventId, commonEvent);
    EXPECT_TRUE(result);
    EXPECT_EQ(commonEvent, EventFwk::CommonEventSupport::COMMON_EVENT_SIM_STATE_CHANGED);
}


class AdapterFactoryCreateAdapterTest : public testing::Test {
protected:
    void SetUp() override
    {
        manager_ = &EventSubscriptionManager::GetInstance();
    }

    EventSubscriptionManager *manager_;
};

/**
 * @tc.name: Test_AppStartReturnsAppLifecycleAdapter
 * @tc.desc: Test APP_START event creates an AppLifecycleAdapter.
 * @tc.type: FUNC
 */
HWTEST_F(AdapterFactoryCreateAdapterTest, AppStart_ReturnsAppLifecycleAdapter, TestSize.Level1)
{
    EventId groupId{static_cast<uint32_t>(ManagedEvent::APP_START)};
    auto adapter = AdapterFactory::CreateAdapter(*manager_, groupId);
    ASSERT_NE(adapter, nullptr);
    auto appLifecycleAdapter = std::static_pointer_cast<AppLifecycleAdapter>(adapter);
    EXPECT_NE(appLifecycleAdapter, nullptr);
}

/**
 * @tc.name: Test_BundleAddedReturnsCommonEventAdapter
 * @tc.desc: Test BUNDLE_ADDED event creates a CommonEventAdapter.
 * @tc.type: FUNC
 */
HWTEST_F(AdapterFactoryCreateAdapterTest, BundleAdded_ReturnsCommonEventAdapter, TestSize.Level1)
{
    EventId groupId{static_cast<uint32_t>(ManagedEvent::BUNDLE_ADDED)};
    auto adapter = AdapterFactory::CreateAdapter(*manager_, groupId);
    ASSERT_NE(adapter, nullptr);
    auto commonEventAdapter = std::static_pointer_cast<CommonEventAdapter>(adapter);
    EXPECT_NE(commonEventAdapter, nullptr);
}

/**
 * @tc.name: Test_UserAddedReturnsAdapter
 * @tc.desc: Test USER_ADDED event creates a valid adapter.
 * @tc.type: FUNC
 */
HWTEST_F(AdapterFactoryCreateAdapterTest, UserAdded_ReturnsCommonEventAdapter, TestSize.Level1)
{
    EventId groupId{static_cast<uint32_t>(ManagedEvent::USER_ADDED)};
    auto adapter = AdapterFactory::CreateAdapter(*manager_, groupId);
    ASSERT_NE(adapter, nullptr);
}

/**
 * @tc.name: Test_SystemUpdateWithCustomEventReturnsAdapter
 * @tc.desc: Test SYSTEM_UPDATE event with custom CES name creates an adapter.
 * @tc.type: FUNC
 */
HWTEST_F(AdapterFactoryCreateAdapterTest, SystemUpdate_WithCustomEvent_ReturnsAdapter, TestSize.Level1)
{
    EventId groupId{static_cast<uint32_t>(ManagedEvent::SYSTEM_UPDATE)};
    auto adapter = AdapterFactory::CreateAdapter(*manager_, groupId);
    ASSERT_NE(adapter, nullptr);
}

/**
 * @tc.name: Test_StartupGuideCompletedWithCustomEventReturnsAdapter
 * @tc.desc: Test STARTUP_GUIDE_COMPLETED event with custom CES name creates an adapter.
 * @tc.type: FUNC
 */
HWTEST_F(AdapterFactoryCreateAdapterTest, StartupGuideCompleted_WithCustomEvent_ReturnsAdapter, TestSize.Level1)
{
    EventId groupId{static_cast<uint32_t>(ManagedEvent::STARTUP_GUIDE_COMPLETED)};
    auto adapter = AdapterFactory::CreateAdapter(*manager_, groupId);
    ASSERT_NE(adapter, nullptr);
}

/**
 * @tc.name: Test_EdmInternalKioskModeOnReturnsAdapter
 * @tc.desc: Test ManagedEvent KIOSK_MODE_ON creates a CommonEventAdapter.
 * @tc.type: FUNC
 */
HWTEST_F(AdapterFactoryCreateAdapterTest, EdmInternalKioskModeOn_ReturnsAdapter, TestSize.Level1)
{
    EventId groupId{static_cast<uint32_t>(ManagedEvent::KIOSK_MODE_ON)};
    auto adapter = AdapterFactory::CreateAdapter(*manager_, groupId);
    ASSERT_NE(adapter, nullptr);
}

/**
 * @tc.name: Test_CustomEventNameReturnsAdapter
 * @tc.desc: Test unknown event with a custom event name creates a CommonEventAdapter.
 * @tc.type: FUNC
 */
HWTEST_F(AdapterFactoryCreateAdapterTest, CustomEventName_ReturnsAdapter, TestSize.Level1)
{
    EventId groupId{9999};
    auto adapter = AdapterFactory::CreateAdapter(*manager_, groupId, "custom.event.TEST", "");
    ASSERT_NE(adapter, nullptr);
}

/**
 * @tc.name: Test_UnknownEventNoNameReturnsNull
 * @tc.desc: Test unknown event without a custom name returns nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(AdapterFactoryCreateAdapterTest, UnknownEventNoName_ReturnsNull, TestSize.Level1)
{
    EventId groupId{9999};
    auto adapter = AdapterFactory::CreateAdapter(*manager_, groupId);
    EXPECT_EQ(adapter, nullptr);
}

class ManagedEventTest : public testing::Test {};

/**
 * @tc.name: Test_ManagedEventEnumValues
 * @tc.desc: Test ManagedEvent enum values start at 100.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedEventTest, EnumValues_StartAt100, TestSize.Level1)
{
    EXPECT_EQ(static_cast<uint32_t>(ManagedEvent::BMS_READY), 101u);
    EXPECT_EQ(static_cast<uint32_t>(ManagedEvent::KIOSK_MODE_ON), 102u);
    EXPECT_EQ(static_cast<uint32_t>(ManagedEvent::KIOSK_MODE_OFF), 103u);
    EXPECT_EQ(static_cast<uint32_t>(ManagedEvent::SIM_STATE_CHANGED), 104u);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
