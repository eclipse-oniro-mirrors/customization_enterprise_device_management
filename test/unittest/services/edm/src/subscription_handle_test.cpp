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
#include "subscription_handle.h"
#include "event_subscription_manager.h"
#undef private

#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <unordered_map>

#include "managed_event.h"
#include "managed_event.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {

class EventIdTest : public testing::Test {};

/**
 * @tc.name: Test_EventIdOperatorEqualSameValues
 * @tc.desc: Test EventId operator== returns true for identical values.
 * @tc.type: FUNC
 */
HWTEST_F(EventIdTest, OperatorEqual_SameValues_ReturnsTrue, TestSize.Level1)
{
    EventId a{100};
    EventId b{100};
    EXPECT_TRUE(a == b);
}

/**
 * @tc.name: Test_EventIdOperatorEqualDifferentCode
 * @tc.desc: Test EventId operator== returns false when codes differ.
 * @tc.type: FUNC
 */
HWTEST_F(EventIdTest, OperatorEqual_DifferentCode_ReturnsFalse, TestSize.Level1)
{
    EventId a{100};
    EventId b{200};
    EXPECT_FALSE(a == b);
}

/**
 * @tc.name: Test_EventIdOperatorEqualSameCode
 * @tc.desc: Test EventId operator== returns true when code is the same.
 * @tc.type: FUNC
 */
HWTEST_F(EventIdTest, OperatorEqual_SameCode_ReturnsTrue, TestSize.Level1)
{
    EventId a{100};
    EventId b{100};
    EXPECT_TRUE(a == b);
}

class EventIdHashTest : public testing::Test {};

/**
 * @tc.name: Test_EventIdHashSameEventIdSameHash
 * @tc.desc: Test EventIdHash produces the same hash for identical EventIds.
 * @tc.type: FUNC
 */
HWTEST_F(EventIdHashTest, SameEventId_SameHash, TestSize.Level1)
{
    EventIdHash hasher;
    EventId a{100};
    EventId b{100};
    EXPECT_EQ(hasher(a), hasher(b));
}

/**
 * @tc.name: Test_EventIdHashDifferentCode
 * @tc.desc: Test EventIdHash produces different hashes for different codes.
 * @tc.type: FUNC
 */
HWTEST_F(EventIdHashTest, DifferentEventId_DifferentHash, TestSize.Level1)
{
    EventIdHash hasher;
    EventId a{100};
    EventId b{200};
    EXPECT_NE(hasher(a), hasher(b));
}

/**
 * @tc.name: Test_EventIdHashDifferentCode
 * @tc.desc: Test EventIdHash produces different hashes for different codes.
 * @tc.type: FUNC
 */
HWTEST_F(EventIdHashTest, DifferentCode_DifferentHash, TestSize.Level1)
{
    EventIdHash hasher;
    EventId a{100};
    EventId b{200};
    EXPECT_NE(hasher(a), hasher(b));
}

/**
 * @tc.name: Test_EventIdHashConsistent
 * @tc.desc: Test EventIdHash returns consistent value across multiple calls.
 * @tc.type: FUNC
 */
HWTEST_F(EventIdHashTest, HashConsistent_MultipleCalls, TestSize.Level1)
{
    EventIdHash hasher;
    EventId id{104};
    size_t h1 = hasher(id);
    size_t h2 = hasher(id);
    EXPECT_EQ(h1, h2);
}

/**
 * @tc.name: Test_EventIdUsedAsUnorderedMapKey
 * @tc.desc: Test EventId can be used as a key in unordered_map with EventIdHash.
 * @tc.type: FUNC
 */
HWTEST_F(EventIdHashTest, EventId_UsedAsUnorderedMapKey, TestSize.Level1)
{
    std::unordered_map<EventId, int, EventIdHash> map;
    EventId a{100};
    EventId b{200};
    EventId c{300};

    map[a] = 1;
    map[b] = 2;
    map[c] = 3;

    EXPECT_EQ(map.size(), 3u);
    EXPECT_EQ(map[a], 1);
    EXPECT_EQ(map[b], 2);
    EXPECT_EQ(map[c], 3);
}

/**
 * @tc.name: Test_EventIdOverwriteExistingKey
 * @tc.desc: Test overwriting an existing EventId key in unordered_map.
 * @tc.type: FUNC
 */
HWTEST_F(EventIdHashTest, EventId_OverwriteExistingKey, TestSize.Level1)
{
    std::unordered_map<EventId, std::string, EventIdHash> map;
    EventId id{100};
    map[id] = "first";
    map[id] = "second";
    EXPECT_EQ(map.size(), 1u);
    EXPECT_EQ(map[id], "second");
}

/**
 * @tc.name: Test_EventIdFindExistingKey
 * @tc.desc: Test finding an existing EventId key in unordered_map.
 * @tc.type: FUNC
 */
HWTEST_F(EventIdHashTest, EventId_FindExistingKey, TestSize.Level1)
{
    std::unordered_map<EventId, int, EventIdHash> map;
    EventId id{static_cast<uint32_t>(ManagedEvent::APP_START)};
    map[id] = 42;
    auto it = map.find(id);
    ASSERT_NE(it, map.end());
    EXPECT_EQ(it->second, 42);
}

class SubscriberTypeTest : public testing::Test {};

/**
 * @tc.name: Test_SubscriberTypeEnumValues
 * @tc.desc: Test SubscriberType enum values match expected constants.
 * @tc.type: FUNC
 */
HWTEST_F(SubscriberTypeTest, EnumValues_Correct, TestSize.Level1)
{
    EXPECT_EQ(static_cast<uint32_t>(SubscriberType::SA_CORE), 0u);
    EXPECT_EQ(static_cast<uint32_t>(SubscriberType::MDM_RELAY), 1u);
    EXPECT_EQ(static_cast<uint32_t>(SubscriberType::POLICY_BOUND), 2u);
}

class SubscriptionHandleTest : public testing::Test {};

/**
 * @tc.name: Test_GetHandleId
 * @tc.desc: Test GetHandleId returns the handle ID passed at construction.
 * @tc.type: FUNC
 */
HWTEST_F(SubscriptionHandleTest, GetHandleId_ReturnsCorrectId, TestSize.Level1)
{
    EventSubscriptionManager &manager = EventSubscriptionManager::GetInstance();
    EventId eventId{static_cast<uint32_t>(ManagedEvent::BUNDLE_ADDED)};
    SubscriptionHandle handle(manager, 42, eventId, "test_sub", SubscriberType::SA_CORE);
    EXPECT_EQ(handle.GetHandleId(), 42u);
}

/**
 * @tc.name: Test_GetEventId
 * @tc.desc: Test GetEventId returns the EventId passed at construction.
 * @tc.type: FUNC
 */
HWTEST_F(SubscriptionHandleTest, GetEventId_ReturnsCorrectEventId, TestSize.Level1)
{
    EventSubscriptionManager &manager = EventSubscriptionManager::GetInstance();
    EventId eventId{static_cast<uint32_t>(ManagedEvent::BUNDLE_ADDED)};
    SubscriptionHandle handle(manager, 1, eventId, "test_sub", SubscriberType::SA_CORE);
    EXPECT_EQ(handle.GetEventId(), eventId);
}

/**
 * @tc.name: Test_GetSubscriberId
 * @tc.desc: Test GetSubscriberId returns the subscriber ID passed at construction.
 * @tc.type: FUNC
 */
HWTEST_F(SubscriptionHandleTest, GetSubscriberId_ReturnsCorrectId, TestSize.Level1)
{
    EventSubscriptionManager &manager = EventSubscriptionManager::GetInstance();
    EventId eventId{static_cast<uint32_t>(ManagedEvent::BUNDLE_ADDED)};
    SubscriptionHandle handle(manager, 1, eventId, "my_subscriber", SubscriberType::SA_CORE);
    EXPECT_EQ(handle.GetSubscriberId(), "my_subscriber");
}

/**
 * @tc.name: Test_GetSubscriberType
 * @tc.desc: Test GetSubscriberType returns the type passed at construction.
 * @tc.type: FUNC
 */
HWTEST_F(SubscriptionHandleTest, GetSubscriberType_ReturnsCorrectType, TestSize.Level1)
{
    EventSubscriptionManager &manager = EventSubscriptionManager::GetInstance();
    EventId eventId{static_cast<uint32_t>(ManagedEvent::BUNDLE_ADDED)};
    SubscriptionHandle handle(manager, 1, eventId, "test_sub", SubscriberType::MDM_RELAY);
    EXPECT_EQ(handle.GetSubscriberType(), SubscriberType::MDM_RELAY);
}

/**
 * @tc.name: Test_ReleaseIdempotent
 * @tc.desc: Test Release called twice does not cause double-unsubscribe.
 * @tc.type: FUNC
 */
HWTEST_F(SubscriptionHandleTest, Release_CalledOnlyOnce, TestSize.Level1)
{
    EventSubscriptionManager &manager = EventSubscriptionManager::GetInstance();
    EventId eventId{static_cast<uint32_t>(ManagedEvent::USER_ADDED)};
    SubscriptionHandle handle(manager, 0, eventId, "test_sub", SubscriberType::SA_CORE);
    handle.Release();
    handle.Release();
}

/**
 * @tc.name: Test_MoveConstructorTransfersOwnership
 * @tc.desc: Test move constructor transfers ownership and nullifies the source.
 * @tc.type: FUNC
 */
HWTEST_F(SubscriptionHandleTest, MoveConstructor_TransfersOwnership, TestSize.Level1)
{
    EventSubscriptionManager &manager = EventSubscriptionManager::GetInstance();
    EventId eventId{static_cast<uint32_t>(ManagedEvent::USER_ADDED)};
    SubscriptionHandle handle1(manager, 100, eventId, "sub1", SubscriberType::SA_CORE);
    uint32_t origId = handle1.GetHandleId();

    SubscriptionHandle handle2(std::move(handle1));
    EXPECT_EQ(handle2.GetHandleId(), origId);
    EXPECT_EQ(handle2.GetSubscriberId(), "sub1");
    EXPECT_EQ(handle1.GetHandleId(), 0u);
}

/**
 * @tc.name: Test_MoveAssignmentTransfersOwnership
 * @tc.desc: Test move assignment transfers ownership and releases the old handle.
 * @tc.type: FUNC
 */
HWTEST_F(SubscriptionHandleTest, MoveAssignment_TransfersOwnership, TestSize.Level1)
{
    EventSubscriptionManager &manager = EventSubscriptionManager::GetInstance();
    EventId eventId1{static_cast<uint32_t>(ManagedEvent::USER_ADDED)};
    EventId eventId2{static_cast<uint32_t>(ManagedEvent::USER_REMOVED)};
    SubscriptionHandle handle1(manager, 100, eventId1, "sub1", SubscriberType::SA_CORE);
    SubscriptionHandle handle2(manager, 200, eventId2, "sub2", SubscriberType::MDM_RELAY);

    handle2 = std::move(handle1);
    EXPECT_EQ(handle2.GetHandleId(), 100u);
    EXPECT_EQ(handle2.GetSubscriberId(), "sub1");
    EXPECT_EQ(handle1.GetHandleId(), 0u);
}

/**
 * @tc.name: Test_DestructorCallsRelease
 * @tc.desc: Test destructor calls Release automatically (RAII).
 * @tc.type: FUNC
 */
HWTEST_F(SubscriptionHandleTest, Destructor_CallsRelease, TestSize.Level1)
{
    EventSubscriptionManager &manager = EventSubscriptionManager::GetInstance();
    EventId eventId{static_cast<uint32_t>(ManagedEvent::USER_ADDED)};
    {
        SubscriptionHandle handle(manager, 0, eventId, "test_sub", SubscriberType::SA_CORE);
    }
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
