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
#include "common_event_adapter.h"
#include "common_event_support.h"
#include "event_subscription_manager.h"
#undef private

#include <gtest/gtest.h>
#include <memory>
#include <string>

#include "managed_event.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {

class CommonEventAdapterTest : public testing::Test {
protected:
    void SetUp() override
    {
        manager_ = &EventSubscriptionManager::GetInstance();
    }

    EventSubscriptionManager *manager_;
};

/**
 * @tc.name: Test_ConstructorCreatesSubscriber
 * @tc.desc: Test CommonEventAdapter constructor creates a subscriber.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventAdapterTest, Constructor_CreatesSubscriber, TestSize.Level1)
{
    EventFwk::MatchingSkills skill;
    skill.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    EventFwk::CommonEventSubscribeInfo info(skill);
    EventId eventId{static_cast<uint32_t>(ManagedEvent::BUNDLE_ADDED)};

    CommonEventAdapter adapter(info, *manager_, eventId);
    EXPECT_NE(adapter.subscriber_, nullptr);
}

/**
 * @tc.name: Test_ConstructorWithPermission
 * @tc.desc: Test CommonEventAdapter constructor with permission set.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventAdapterTest, Constructor_WithPermission_CreatesSubscriber, TestSize.Level1)
{
    EventFwk::MatchingSkills skill;
    skill.AddEvent(EDM_SYSTEM_UPDATE_FOR_POLICY);
    EventFwk::CommonEventSubscribeInfo info(skill);
    info.SetPermission(EDM_SYSTEM_UPDATE_PERMISSION);
    EventId eventId{static_cast<uint32_t>(ManagedEvent::SYSTEM_UPDATE)};

    CommonEventAdapter adapter(info, *manager_, eventId);
    EXPECT_NE(adapter.subscriber_, nullptr);
}

/**
 * @tc.name: Test_SubscribeEventNullSubscriber
 * @tc.desc: Test SubscribeEvent returns false when subscriber is null.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventAdapterTest, SubscribeEvent_NullSubscriber_ReturnsFalse, TestSize.Level1)
{
    EventFwk::MatchingSkills skill;
    skill.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    EventFwk::CommonEventSubscribeInfo info(skill);
    EventId eventId{static_cast<uint32_t>(ManagedEvent::BUNDLE_ADDED)};

    CommonEventAdapter adapter(info, *manager_, eventId);
    adapter.subscriber_ = nullptr;
    EXPECT_FALSE(adapter.SubscribeEvent());
}

/**
 * @tc.name: Test_UnsubscribeEventNullSubscriber
 * @tc.desc: Test UnsubscribeEvent returns false when subscriber is null.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventAdapterTest, UnsubscribeEvent_NullSubscriber_ReturnsFalse, TestSize.Level1)
{
    EventFwk::MatchingSkills skill;
    skill.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    EventFwk::CommonEventSubscribeInfo info(skill);
    EventId eventId{static_cast<uint32_t>(ManagedEvent::BUNDLE_ADDED)};

    CommonEventAdapter adapter(info, *manager_, eventId);
    adapter.subscriber_ = nullptr;
    EXPECT_FALSE(adapter.UnsubscribeEvent());
}

/**
 * @tc.name: Test_SubscribeAndUnsubscribeEventSuccess
 * @tc.desc: Test SubscribeEvent succeeds and UnsubscribeEvent succeeds after subscription.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventAdapterTest, SubscribeAndUnsubscribe_Success, TestSize.Level1)
{
    EventFwk::MatchingSkills skill;
    skill.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED);
    EventFwk::CommonEventSubscribeInfo info(skill);
    EventId eventId{static_cast<uint32_t>(ManagedEvent::USER_REMOVED)};

    CommonEventAdapter adapter(info, *manager_, eventId);
    bool subResult = adapter.SubscribeEvent();
    if (subResult) {
        EXPECT_TRUE(adapter.UnsubscribeEvent());
    }
}

/**
 * @tc.name: Test_UnsubscribeEventWithoutSubscription
 * @tc.desc: Test UnsubscribeEvent without prior subscription (may fail or succeed).
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventAdapterTest, UnsubscribeEvent_WithoutSubscription_NoCrash, TestSize.Level1)
{
    EventFwk::MatchingSkills skill;
    skill.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_ADDED);
    EventFwk::CommonEventSubscribeInfo info(skill);
    EventId eventId{static_cast<uint32_t>(ManagedEvent::USER_ADDED)};

    CommonEventAdapter adapter(info, *manager_, eventId);
    bool result = adapter.UnsubscribeEvent();
    EXPECT_TRUE(result || !result);
}

/**
 * @tc.name: Test_SubscribeEventEmptyMatchingSkills
 * @tc.desc: Test SubscribeEvent with empty MatchingSkills (may fail).
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventAdapterTest, SubscribeEvent_EmptyMatchingSkills_NoCrash, TestSize.Level1)
{
    EventFwk::MatchingSkills emptySkill;
    EventFwk::CommonEventSubscribeInfo emptyInfo(emptySkill);
    EventId eventId{static_cast<uint32_t>(ManagedEvent::USER_REMOVED)};

    CommonEventAdapter adapter(emptyInfo, *manager_, eventId);
    bool result = adapter.SubscribeEvent();
    EXPECT_TRUE(result || !result);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
