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
#include "ipolicy_manager.h"
#include "plugin_event_router.h"
#include "iplugin_event_subscribe_manager.h"
#undef private

#include <gtest/gtest.h>
#include <string>

#include "edm_event_data.h"
#include "event_subscription_manager.h"
#include "managed_event.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {

class PluginEventRouterTest : public testing::Test {};

/**
 * @tc.name: Test_MakeKeyCorrectFormat
 * @tc.desc: Test MakeKey produces "policyName:isManagedEvent:code" format.
 * @tc.type: FUNC
 */
HWTEST_F(PluginEventRouterTest, MakeKey_CorrectFormat, TestSize.Level1)
{
    PluginEventRouter &router = PluginEventRouter::GetInstance();
    EventId eventId{100};
    std::string key = router.MakeKey("POLICY_TEST", eventId);
    EXPECT_EQ(key, "POLICY_TEST:100");
}

/**
 * @tc.name: Test_MakeKeyNonManagedEvent
 * @tc.desc: Test MakeKey with non-managed event produces correct format.
 * @tc.type: FUNC
 */
HWTEST_F(PluginEventRouterTest, MakeKey_NonManagedEvent, TestSize.Level1)
{
    PluginEventRouter &router = PluginEventRouter::GetInstance();
    EventId eventId{200};
    std::string key = router.MakeKey("POLICY_TEST", eventId);
    EXPECT_EQ(key, "POLICY_TEST:200");
}

/**
 * @tc.name: Test_MakeKeyDifferentPolicyDifferentKey
 * @tc.desc: Test MakeKey produces different keys for different policy names.
 * @tc.type: FUNC
 */
HWTEST_F(PluginEventRouterTest, MakeKey_DifferentPolicy_DifferentKey, TestSize.Level1)
{
    PluginEventRouter &router = PluginEventRouter::GetInstance();
    EventId eventId{100};
    std::string key1 = router.MakeKey("POLICY_A", eventId);
    std::string key2 = router.MakeKey("POLICY_B", eventId);
    EXPECT_NE(key1, key2);
}

/**
 * @tc.name: Test_MakeKeyDifferentEventDifferentKey
 * @tc.desc: Test MakeKey produces different keys for different event codes.
 * @tc.type: FUNC
 */
HWTEST_F(PluginEventRouterTest, MakeKey_DifferentEvent_DifferentKey, TestSize.Level1)
{
    PluginEventRouter &router = PluginEventRouter::GetInstance();
    EventId event1{100};
    EventId event2{200};
    std::string key1 = router.MakeKey("POLICY_TEST", event1);
    std::string key2 = router.MakeKey("POLICY_TEST", event2);
    EXPECT_NE(key1, key2);
}

/**
 * @tc.name: Test_SubscribeEventStoresPolicyCode
 * @tc.desc: Test SubscribeEvent stores policyCode in PluginEntry.
 * @tc.type: FUNC
 */
HWTEST_F(PluginEventRouterTest, SubscribeEvent_StoresPolicyCode, TestSize.Level1)
{
    PluginEventRouter &router = PluginEventRouter::GetInstance();
    std::string policyName = "POLICY_UT_" + std::to_string(std::rand());
    uint32_t eventCode = static_cast<uint32_t>(ManagedEvent::BOOT_COMPLETED);
    bool result = router.SubscribeEvent(policyName, eventCode, 999, false, false);
    EXPECT_TRUE(result);
    EventId eventId{eventCode};
    std::string key = router.MakeKey(policyName, eventId);
    auto it = router.entries_.find(key);
    ASSERT_NE(it, router.entries_.end());
    EXPECT_EQ(it->second.policyCode, static_cast<uint32_t>(999));
    router.UnsubscribeEvent(policyName, eventCode);
}

/**
 * @tc.name: Test_SubscribeEventDuplicateReturnsTrue
 * @tc.desc: Test SubscribeEvent returns true for duplicate subscription.
 * @tc.type: FUNC
 */
HWTEST_F(PluginEventRouterTest, SubscribeEvent_Duplicate_ReturnsTrue, TestSize.Level1)
{
    PluginEventRouter &router = PluginEventRouter::GetInstance();
    std::string policyName = "POLICY_UT_DUP_" + std::to_string(std::rand());
    uint32_t eventCode = static_cast<uint32_t>(ManagedEvent::USER_ADDED);
    bool result1 = router.SubscribeEvent(policyName, eventCode, 1001, false, false);
    EXPECT_TRUE(result1);
    bool result2 = router.SubscribeEvent(policyName, eventCode, 1001, false, false);
    EXPECT_TRUE(result2);
    router.UnsubscribeEvent(policyName, eventCode);
}

class IPluginEventSubscribeManagerTest : public testing::Test {};

/**
 * @tc.name: Test_GetInstanceSetInstance
 * @tc.desc: Test GetInstance/SetInstance roundtrip updates the singleton.
 * @tc.type: FUNC
 */
HWTEST_F(IPluginEventSubscribeManagerTest, GetInstance_SetInstance_Roundtrip, TestSize.Level1)
{
    IPluginEventSubscribeManager *saved = IPluginEventSubscribeManager::GetInstance();
    IPluginEventSubscribeManager::SetInstance(nullptr);
    EXPECT_EQ(IPluginEventSubscribeManager::GetInstance(), nullptr);
    IPluginEventSubscribeManager::SetInstance(saved);
    EXPECT_EQ(IPluginEventSubscribeManager::GetInstance(), saved);
}

/**
 * @tc.name: Test_UnsubscribeEventReleasesHandleOutsideLock
 * @tc.desc: Test UnsubscribeEvent removes entry and group state correctly.
 * @tc.type: FUNC
 */
HWTEST_F(PluginEventRouterTest, UnsubscribeEvent_RemovesEntryAndGroupState, TestSize.Level1)
{
    PluginEventRouter &router = PluginEventRouter::GetInstance();
    std::string policyName = "POLICY_UT_UNSUB_" + std::to_string(std::rand());
    uint32_t eventCode = static_cast<uint32_t>(ManagedEvent::USER_REMOVED);
    bool result = router.SubscribeEvent(policyName, eventCode, 5001, false, false);
    EXPECT_TRUE(result);

    EventId eventId{eventCode};
    EXPECT_EQ(router.eventGroupStates_.count(eventId), 1u);
    std::string key = router.MakeKey(policyName, eventId);
    EXPECT_EQ(router.entries_.count(key), 1u);

    router.UnsubscribeEvent(policyName, eventCode);
    EXPECT_EQ(router.entries_.count(key), 0u);
    EXPECT_EQ(router.eventGroupStates_.count(eventId), 0u);
}

/**
 * @tc.name: Test_AppStartAndAppStopSeparateEntries
 * @tc.desc: Test APP_START and APP_STOP create separate entries and group states (exact eventId matching).
 * @tc.type: FUNC
 */
HWTEST_F(PluginEventRouterTest, AppStartAndAppStop_SeparateEntries, TestSize.Level1)
{
    PluginEventRouter &router = PluginEventRouter::GetInstance();
    std::string policyName = "POLICY_UT_GROUP_" + std::to_string(std::rand());
    uint32_t startCode = static_cast<uint32_t>(ManagedEvent::APP_START);
    uint32_t stopCode = static_cast<uint32_t>(ManagedEvent::APP_STOP);

    bool r1 = router.SubscribeEvent(policyName, startCode, 6001, false, false);
    bool r2 = router.SubscribeEvent(policyName, stopCode, 6002, false, false);
    EXPECT_TRUE(r1);
    EXPECT_TRUE(r2);

    EventId startId{startCode};
    EventId stopId{stopCode};
    EXPECT_EQ(router.eventGroupStates_.count(startId), 1u);
    EXPECT_EQ(router.eventGroupStates_.count(stopId), 1u);
    EXPECT_NE(startId, stopId);

    std::string startKey = router.MakeKey(policyName, startId);
    std::string stopKey = router.MakeKey(policyName, stopId);
    EXPECT_NE(startKey, stopKey);
    EXPECT_EQ(router.entries_[startKey].policyCode, 6001u);
    EXPECT_EQ(router.entries_[stopKey].policyCode, 6002u);

    router.UnsubscribeEvent(policyName, startCode);
    router.UnsubscribeEvent(policyName, stopCode);
    EXPECT_EQ(router.entries_.count(startKey), 0u);
    EXPECT_EQ(router.entries_.count(stopKey), 0u);
}

/**
 * @tc.name: Test_RestorePluginSubscriptionsPolicyManagerNull
 * @tc.desc: Test RestorePluginSubscriptions returns early when policyManager is null.
 * @tc.type: FUNC
 */
HWTEST_F(PluginEventRouterTest, RestorePluginSubscriptions_PolicyManagerNull_Returns, TestSize.Level1)
{
    PluginEventRouter &router = PluginEventRouter::GetInstance();
    auto saved = IPolicyManager::policyManagerInstance_;
    IPolicyManager::policyManagerInstance_ = nullptr;
    size_t beforeSize = router.entries_.size();
    router.RestorePluginSubscriptions();
    EXPECT_EQ(router.entries_.size(), beforeSize);
    IPolicyManager::policyManagerInstance_ = saved;
}

/**
 * @tc.name: Test_RestorePluginSubscriptionsAllPoliciesEmpty
 * @tc.desc: Test RestorePluginSubscriptions skips all plugins when policies are empty.
 * @tc.type: FUNC
 */
HWTEST_F(PluginEventRouterTest, RestorePluginSubscriptions_AllPoliciesEmpty_SkipsSubscribe, TestSize.Level1)
{
    PluginEventRouter &router = PluginEventRouter::GetInstance();
    auto saved = IPolicyManager::policyManagerInstance_;
    IPolicyManager emptyManager;
    IPolicyManager::policyManagerInstance_ = &emptyManager;
    size_t beforeSize = router.entries_.size();
    router.RestorePluginSubscriptions();
    EXPECT_EQ(router.entries_.size(), beforeSize);
    IPolicyManager::policyManagerInstance_ = saved;
}

/**
 * @tc.name: Test_SubscribeEventSecondPolicySameEvent
 * @tc.desc: Test second policy subscribing to same event reuses group state.
 * @tc.type: FUNC
 */
HWTEST_F(PluginEventRouterTest, SubscribeEvent_SecondPolicySameEvent, TestSize.Level1)
{
    PluginEventRouter &router = PluginEventRouter::GetInstance();
    std::string policyName1 = "POLICY_UT_SECOND1_" + std::to_string(std::rand());
    std::string policyName2 = "POLICY_UT_SECOND2_" + std::to_string(std::rand());
    uint32_t eventCode = static_cast<uint32_t>(ManagedEvent::BOOT_COMPLETED);

    bool r1 = router.SubscribeEvent(policyName1, eventCode, 1001, false, false);
    EXPECT_TRUE(r1);
    bool r2 = router.SubscribeEvent(policyName2, eventCode, 1002, false, false);
    EXPECT_TRUE(r2);

    router.UnsubscribeEvent(policyName1, eventCode);
    router.UnsubscribeEvent(policyName2, eventCode);
}

/**
 * @tc.name: Test_SubscribeEventInvalidEventCode
 * @tc.desc: Test SubscribeEvent with invalid event code returns false.
 * @tc.type: FUNC
 */
HWTEST_F(PluginEventRouterTest, SubscribeEvent_InvalidEventCode_ReturnsFalse, TestSize.Level1)
{
    PluginEventRouter &router = PluginEventRouter::GetInstance();
    std::string policyName = "POLICY_UT_INVALID_" + std::to_string(std::rand());
    uint32_t invalidEventCode = 9999;

    bool result = router.SubscribeEvent(policyName, invalidEventCode, 999, false, false);
    EXPECT_FALSE(result);

    EventId eventId{invalidEventCode};
    std::string key = router.MakeKey(policyName, eventId);
    EXPECT_EQ(router.entries_.count(key), 0u);
    EXPECT_EQ(router.eventGroupStates_.count(eventId), 0u);
}

/**
 * @tc.name: Test_UnsubscribeEventNotFound
 * @tc.desc: Test UnsubscribeEvent for non-existent policy returns true.
 * @tc.type: FUNC
 */
HWTEST_F(PluginEventRouterTest, UnsubscribeEvent_NotFound_ReturnsTrue, TestSize.Level1)
{
    PluginEventRouter &router = PluginEventRouter::GetInstance();
    bool result = router.UnsubscribeEvent("NONEXISTENT_POLICY",
        static_cast<uint32_t>(ManagedEvent::BOOT_COMPLETED));
    EXPECT_TRUE(result);
}

/**
 * @tc.name: Test_UnsubscribeEventRemainingKeys
 * @tc.desc: Test UnsubscribeEvent when other keys remain keeps group state.
 * @tc.type: FUNC
 */
HWTEST_F(PluginEventRouterTest, UnsubscribeEvent_RemainingKeys_KeepsGroup, TestSize.Level1)
{
    PluginEventRouter &router = PluginEventRouter::GetInstance();
    std::string policyName1 = "POLICY_UT_REM1_" + std::to_string(std::rand());
    std::string policyName2 = "POLICY_UT_REM2_" + std::to_string(std::rand());
    uint32_t eventCode = static_cast<uint32_t>(ManagedEvent::USER_ADDED);

    router.SubscribeEvent(policyName1, eventCode, 8001, false, false);
    router.SubscribeEvent(policyName2, eventCode, 8002, false, false);

    EventId eventId{eventCode};
    EXPECT_EQ(router.eventGroupStates_.count(eventId), 1u);

    router.UnsubscribeEvent(policyName1, eventCode);
    EXPECT_EQ(router.eventGroupStates_.count(eventId), 1u);

    router.UnsubscribeEvent(policyName2, eventCode);
    EXPECT_EQ(router.eventGroupStates_.count(eventId), 0u);
}

/**
 * @tc.name: Test_UnsubscribeEventGroupNotFound
 * @tc.desc: Test UnsubscribeEvent when group state was already removed.
 * @tc.type: FUNC
 */
HWTEST_F(PluginEventRouterTest, UnsubscribeEvent_GroupNotFound, TestSize.Level1)
{
    PluginEventRouter &router = PluginEventRouter::GetInstance();
    std::string policyName = "POLICY_UT_NOGROUP_" + std::to_string(std::rand());
    uint32_t eventCode = static_cast<uint32_t>(ManagedEvent::USER_SWITCHED);

    router.SubscribeEvent(policyName, eventCode, 900, false, false);

    EventId eventId{eventCode};
    auto groupIt = router.eventGroupStates_.find(eventId);
    ASSERT_NE(groupIt, router.eventGroupStates_.end());
    auto handle = groupIt->second->handle;
    router.eventGroupStates_.erase(eventId);

    bool result = router.UnsubscribeEvent(policyName, eventCode);
    EXPECT_TRUE(result);
    EXPECT_EQ(router.entries_.count(router.MakeKey(policyName, eventId)), 0u);
}

/**
 * @tc.name: Test_OnEventDispatchTriggersCollect
 * @tc.desc: Test OnEventDispatch is triggered when event is dispatched.
 * @tc.type: FUNC
 */
HWTEST_F(PluginEventRouterTest, OnEventDispatch_TriggersCollect, TestSize.Level1)
{
    PluginEventRouter &router = PluginEventRouter::GetInstance();
    std::string policyName = "POLICY_UT_DISPATCH_" + std::to_string(std::rand());
    uint32_t eventCode = static_cast<uint32_t>(ManagedEvent::BUNDLE_ADDED);

    bool result = router.SubscribeEvent(policyName, eventCode, 777, false, false);
    EXPECT_TRUE(result);

    EdmEventData data;
    data.eventId = EventId{eventCode};
    EventSubscriptionManager::GetInstance().DispatchEvent(data);

    router.UnsubscribeEvent(policyName, eventCode);
}

/**
 * @tc.name: Test_CollectDispatchEntriesEntryNotFound
 * @tc.desc: Test CollectDispatchEntries skips when entry not found.
 * @tc.type: FUNC
 */
HWTEST_F(PluginEventRouterTest, CollectDispatchEntries_EntryNotFound_Skips, TestSize.Level1)
{
    PluginEventRouter &router = PluginEventRouter::GetInstance();
    std::string policyName = "POLICY_UT_ENTRYNF_" + std::to_string(std::rand());
    uint32_t eventCode = static_cast<uint32_t>(ManagedEvent::USER_REMOVED);

    router.SubscribeEvent(policyName, eventCode, 888, false, false);

    EventId eventId{eventCode};
    std::string key = router.MakeKey(policyName, eventId);
    router.entries_.erase(key);
    EXPECT_EQ(router.entries_.count(key), 0u);

    EdmEventData data;
    data.eventId = eventId;
    EventSubscriptionManager::GetInstance().DispatchEvent(data);

    EXPECT_EQ(router.entries_.count(key), 0u);
    router.eventGroupStates_.erase(eventId);
}

/**
 * @tc.name: Test_CollectDispatchEntriesDifferentEvent
 * @tc.desc: Test CollectDispatchEntries skips group with different event.
 * @tc.type: FUNC
 */
HWTEST_F(PluginEventRouterTest, CollectDispatchEntries_DifferentEvent_Skips, TestSize.Level1)
{
    PluginEventRouter &router = PluginEventRouter::GetInstance();
    std::string policyNameA = "POLICY_UT_DIFFA_" + std::to_string(std::rand());
    std::string policyNameB = "POLICY_UT_DIFFB_" + std::to_string(std::rand());
    uint32_t eventCodeA = static_cast<uint32_t>(ManagedEvent::BUNDLE_ADDED);
    uint32_t eventCodeB = static_cast<uint32_t>(ManagedEvent::BUNDLE_REMOVED);

    router.SubscribeEvent(policyNameA, eventCodeA, 1100, false, false);
    router.SubscribeEvent(policyNameB, eventCodeB, 1101, false, false);
    EXPECT_EQ(router.entries_.size() >= 2, true);

    EdmEventData data;
    data.eventId = EventId{eventCodeA};
    EventSubscriptionManager::GetInstance().DispatchEvent(data);

    router.UnsubscribeEvent(policyNameA, eventCodeA);
    router.UnsubscribeEvent(policyNameB, eventCodeB);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
