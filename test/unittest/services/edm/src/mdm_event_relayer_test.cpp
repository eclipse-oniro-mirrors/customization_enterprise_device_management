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
#include "mdm_event_relayer.h"
#include "callback_strategies.h"
#undef private

#include <gtest/gtest.h>
#include <memory>
#include <string>

#include "edm_event_data.h"
#include "event_subscription_manager.h"
#include "icallback_strategy.h"
#include "managed_event.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {

class MdmEventRelayerTest : public testing::Test {
protected:
    void SetUp() override
    {
        relayer_ = &MdmEventRelayer::GetInstance();
    }

    MdmEventRelayer *relayer_;
};

/**
 * @tc.name: Test_MakeAdminKeyCorrectFormat
 * @tc.desc: Test MakeAdminKey produces "adminName_userId" format.
 * @tc.type: FUNC
 */
HWTEST_F(MdmEventRelayerTest, MakeAdminKey_CorrectFormat, TestSize.Level1)
{
    std::string key = relayer_->MakeAdminKey("com.test.admin", 100);
    EXPECT_EQ(key, "com.test.admin_100");
}

/**
 * @tc.name: Test_MakeAdminKeyDifferentUserIdDifferentKey
 * @tc.desc: Test MakeAdminKey produces different keys for different user IDs.
 * @tc.type: FUNC
 */
HWTEST_F(MdmEventRelayerTest, MakeAdminKey_DifferentUserId_DifferentKey, TestSize.Level1)
{
    std::string key1 = relayer_->MakeAdminKey("com.test.admin", 100);
    std::string key2 = relayer_->MakeAdminKey("com.test.admin", 200);
    EXPECT_NE(key1, key2);
}

/**
 * @tc.name: Test_MakeAdminKeyDifferentAdminDifferentKey
 * @tc.desc: Test MakeAdminKey produces different keys for different admin names.
 * @tc.type: FUNC
 */
HWTEST_F(MdmEventRelayerTest, MakeAdminKey_DifferentAdmin_DifferentKey, TestSize.Level1)
{
    std::string key1 = relayer_->MakeAdminKey("com.test.admin1", 100);
    std::string key2 = relayer_->MakeAdminKey("com.test.admin2", 100);
    EXPECT_NE(key1, key2);
}

/**
 * @tc.name: Test_OnAdminSubscribeCreatesHandle
 * @tc.desc: Test OnAdminSubscribe stores a subscription handle in the map.
 * @tc.type: FUNC
 */
HWTEST_F(MdmEventRelayerTest, OnAdminSubscribe_CreatesHandle, TestSize.Level1)
{
    std::string admin = "com.test.sub_admin_" + std::to_string(std::rand());
    int32_t userId = 100;
    relayer_->OnAdminSubscribe(admin, userId, ManagedEvent::BUNDLE_ADDED);

    std::string key = relayer_->MakeAdminKey(admin, userId);
    auto adminIt = relayer_->adminSubscriptionHandles_.find(key);
    ASSERT_NE(adminIt, relayer_->adminSubscriptionHandles_.end());
    EXPECT_EQ(adminIt->second.count(ManagedEvent::BUNDLE_ADDED), 1u);
    EXPECT_NE(adminIt->second[ManagedEvent::BUNDLE_ADDED], nullptr);

    relayer_->OnAdminUnsubscribe(admin, userId, ManagedEvent::BUNDLE_ADDED);
}

/**
 * @tc.name: Test_OnAdminSubscribeDuplicateSkips
 * @tc.desc: Test OnAdminSubscribe skips when already subscribed to the same event.
 * @tc.type: FUNC
 */
HWTEST_F(MdmEventRelayerTest, OnAdminSubscribe_Duplicate_Skips, TestSize.Level1)
{
    std::string admin = "com.test.dup_admin_" + std::to_string(std::rand());
    int32_t userId = 100;
    relayer_->OnAdminSubscribe(admin, userId, ManagedEvent::USER_SWITCHED);
    relayer_->OnAdminSubscribe(admin, userId, ManagedEvent::USER_SWITCHED);

    std::string key = relayer_->MakeAdminKey(admin, userId);
    EXPECT_EQ(relayer_->adminSubscriptionHandles_[key].count(ManagedEvent::USER_SWITCHED), 1u);

    relayer_->OnAdminUnsubscribe(admin, userId, ManagedEvent::USER_SWITCHED);
}

/**
 * @tc.name: Test_OnAdminUnsubscribeRemovesHandle
 * @tc.desc: Test OnAdminUnsubscribe removes the handle from the map.
 * @tc.type: FUNC
 */
HWTEST_F(MdmEventRelayerTest, OnAdminUnsubscribe_RemovesHandle, TestSize.Level1)
{
    std::string admin = "com.test.unsub_admin_" + std::to_string(std::rand());
    int32_t userId = 100;
    relayer_->OnAdminSubscribe(admin, userId, ManagedEvent::BUNDLE_REMOVED);
    relayer_->OnAdminUnsubscribe(admin, userId, ManagedEvent::BUNDLE_REMOVED);

    std::string key = relayer_->MakeAdminKey(admin, userId);
    auto adminIt = relayer_->adminSubscriptionHandles_.find(key);
    if (adminIt != relayer_->adminSubscriptionHandles_.end()) {
        EXPECT_EQ(adminIt->second.count(ManagedEvent::BUNDLE_REMOVED), 0u);
    }
}

/**
 * @tc.name: Test_OnAdminRemovedClearsAllEvents
 * @tc.desc: Test OnAdminRemoved removes all subscription handles for an admin.
 * @tc.type: FUNC
 */
HWTEST_F(MdmEventRelayerTest, OnAdminRemoved_ClearsAllEvents, TestSize.Level1)
{
    std::string admin = "com.test.removed_admin_" + std::to_string(std::rand());
    int32_t userId = 100;
    relayer_->OnAdminSubscribe(admin, userId, ManagedEvent::BUNDLE_ADDED);
    relayer_->OnAdminSubscribe(admin, userId, ManagedEvent::USER_SWITCHED);

    std::string key = relayer_->MakeAdminKey(admin, userId);
    ASSERT_EQ(relayer_->adminSubscriptionHandles_.count(key), 1u);
    EXPECT_EQ(relayer_->adminSubscriptionHandles_[key].size(), 2u);

    relayer_->OnAdminRemoved(admin, userId);

    EXPECT_EQ(relayer_->adminSubscriptionHandles_.count(key), 0u);
}

/**
 * @tc.name: Test_FactoryReturnsStrategyForBootCompleted
 * @tc.desc: Test BOOT_COMPLETED factory returns a non-null strategy (not dispatches to admins).
 * @tc.type: FUNC
 */
HWTEST_F(MdmEventRelayerTest, Factory_ReturnsStrategy_BootCompleted, TestSize.Level1)
{
    auto it = relayer_->strategyFactories_.find(ManagedEvent::BOOT_COMPLETED);
    ASSERT_NE(it, relayer_->strategyFactories_.end());
    EdmEventData data;
    data.eventId = EventId{static_cast<uint32_t>(ManagedEvent::BOOT_COMPLETED)};
    auto strategy = it->second(data);
    EXPECT_NE(strategy, nullptr);
}

/**
 * @tc.name: Test_FactoryReturnsNullptrForBundleUpdatedWrongType
 * @tc.desc: Test BUNDLE_UPDATED factory returns nullptr when type is not BUNDLE_UPDATE_EVENT.
 * @tc.type: FUNC
 */
HWTEST_F(MdmEventRelayerTest, Factory_ReturnsNullptr_BundleUpdatedWrongType, TestSize.Level1)
{
    auto it = relayer_->strategyFactories_.find(ManagedEvent::BUNDLE_UPDATED);
    ASSERT_NE(it, relayer_->strategyFactories_.end());
    EdmEventData data;
    data.eventId = EventId{static_cast<uint32_t>(ManagedEvent::BUNDLE_UPDATED)};
    auto strategy = it->second(data);
    EXPECT_EQ(strategy, nullptr);
}

/**
 * @tc.name: Test_FactoryReturnsNullptrForStartupGuideNoFlags
 * @tc.desc: Test STARTUP_GUIDE_COMPLETED factory returns nullptr when no startup flags are set.
 * @tc.type: FUNC
 */
HWTEST_F(MdmEventRelayerTest, Factory_ReturnsNullptr_StartupGuideNoFlags, TestSize.Level1)
{
    auto it = relayer_->strategyFactories_.find(ManagedEvent::STARTUP_GUIDE_COMPLETED);
    ASSERT_NE(it, relayer_->strategyFactories_.end());
    EdmEventData data;
    data.eventId = EventId{static_cast<uint32_t>(ManagedEvent::STARTUP_GUIDE_COMPLETED)};
    auto strategy = it->second(data);
    EXPECT_EQ(strategy, nullptr);
}

/**
 * @tc.name: Test_FactoryReturnsStrategyForSystemUpdate
 * @tc.desc: Test SYSTEM_UPDATE factory returns a non-null strategy.
 * @tc.type: FUNC
 */
HWTEST_F(MdmEventRelayerTest, Factory_ReturnsStrategy_SystemUpdate, TestSize.Level1)
{
    auto it = relayer_->strategyFactories_.find(ManagedEvent::SYSTEM_UPDATE);
    ASSERT_NE(it, relayer_->strategyFactories_.end());
    EdmEventData data;
    data.eventId = EventId{static_cast<uint32_t>(ManagedEvent::SYSTEM_UPDATE)};
    auto strategy = it->second(data);
    EXPECT_NE(strategy, nullptr);
}

/**
 * @tc.name: Test_FactoryReturnsStrategyForPasswordFailed
 * @tc.desc: Test PASSWORD_FAILED factory returns a non-null strategy when count is valid.
 * @tc.type: FUNC
 */
HWTEST_F(MdmEventRelayerTest, Factory_ReturnsStrategy_PasswordFailed, TestSize.Level1)
{
    auto it = relayer_->strategyFactories_.find(ManagedEvent::PASSWORD_FAILED);
    ASSERT_NE(it, relayer_->strategyFactories_.end());
    EdmEventData data;
    data.eventId = EventId{static_cast<uint32_t>(ManagedEvent::PASSWORD_FAILED)};
    data.passwordFailedCount = 3;
    data.userId = 100;
    auto strategy = it->second(data);
    EXPECT_NE(strategy, nullptr);
}

/**
 * @tc.name: Test_FactoryReturnsNullptrForPasswordFailedInvalidCount
 * @tc.desc: Test PASSWORD_FAILED factory returns nullptr when count is negative.
 * @tc.type: FUNC
 */
HWTEST_F(MdmEventRelayerTest, Factory_ReturnsNullptr_PasswordFailedInvalidCount, TestSize.Level1)
{
    auto it = relayer_->strategyFactories_.find(ManagedEvent::PASSWORD_FAILED);
    ASSERT_NE(it, relayer_->strategyFactories_.end());
    EdmEventData data;
    data.eventId = EventId{static_cast<uint32_t>(ManagedEvent::PASSWORD_FAILED)};
    data.passwordFailedCount = -1;
    data.userId = 100;
    auto strategy = it->second(data);
    EXPECT_EQ(strategy, nullptr);
}

/**
 * @tc.name: Test_FactoryReturnsNullptrForPasswordFailedInvalidUserId
 * @tc.desc: Test PASSWORD_FAILED factory returns nullptr when userId is negative.
 * @tc.type: FUNC
 */
HWTEST_F(MdmEventRelayerTest, Factory_ReturnsNullptr_PasswordFailedInvalidUserId, TestSize.Level1)
{
    auto it = relayer_->strategyFactories_.find(ManagedEvent::PASSWORD_FAILED);
    ASSERT_NE(it, relayer_->strategyFactories_.end());
    EdmEventData data;
    data.eventId = EventId{static_cast<uint32_t>(ManagedEvent::PASSWORD_FAILED)};
    data.passwordFailedCount = 1;
    data.userId = -1;
    auto strategy = it->second(data);
    EXPECT_EQ(strategy, nullptr);
}

#ifdef USERIAM_EDM_ENABLE
/**
 * @tc.name: Test_PasswordFailedEventBroadcastToAllSubscribers
 * @tc.desc: Test PASSWORD_FAILED event is broadcast to all subscribed admins
 *           (userId distinguishes the failed user in callback params).
 * @tc.type: FUNC
 */
HWTEST_F(MdmEventRelayerTest, PasswordFailedEvent_BroadcastToAllSubscribers, TestSize.Level1)
{
    auto originalFactory = relayer_->strategyFactories_[ManagedEvent::PASSWORD_FAILED];
    int dispatched = 0;
    relayer_->strategyFactories_[ManagedEvent::PASSWORD_FAILED] =
        [&dispatched](const EdmEventData &) -> std::shared_ptr<ICallbackStrategy> {
        dispatched++;
        return nullptr;
    };

    std::string adminA = "com.test.bcastA_" + std::to_string(std::rand());
    std::string adminB = "com.test.bcastB_" + std::to_string(std::rand());
    constexpr int32_t userIdA = 100;
    constexpr int32_t userIdB = 101;

    relayer_->OnAdminSubscribe(adminA, userIdA, ManagedEvent::PASSWORD_FAILED);
    relayer_->OnAdminSubscribe(adminB, userIdB, ManagedEvent::PASSWORD_FAILED);

    EdmEventData data;
    data.eventId = EventId{static_cast<uint32_t>(ManagedEvent::PASSWORD_FAILED)};
    data.userId = userIdB;
    data.passwordFailedCount = 2;
    EventSubscriptionManager::GetInstance().DispatchEvent(data);
    EXPECT_EQ(dispatched, 2);

    relayer_->OnAdminUnsubscribe(adminA, userIdA, ManagedEvent::PASSWORD_FAILED);
    relayer_->OnAdminUnsubscribe(adminB, userIdB, ManagedEvent::PASSWORD_FAILED);
    relayer_->strategyFactories_[ManagedEvent::PASSWORD_FAILED] = originalFactory;
}
#endif

/**
 * @tc.name: Test_MultipleAdminsEachDispatchedOnce
 * @tc.desc: Test that when N admins subscribe to the same event, the factory is invoked
 *           exactly N times (once per admin), not N*N. This verifies the direct-dispatch
 *           fix: each subscription callback dispatches to only its own admin.
 * @tc.type: FUNC
 */
HWTEST_F(MdmEventRelayerTest, MultipleAdmins_EachDispatchedOnce, TestSize.Level1)
{
    auto originalFactory = relayer_->strategyFactories_[ManagedEvent::BUNDLE_ADDED];
    int strategyCreated = 0;
    relayer_->strategyFactories_[ManagedEvent::BUNDLE_ADDED] =
        [&strategyCreated](const EdmEventData &) -> std::shared_ptr<ICallbackStrategy> {
            strategyCreated++;
            return nullptr;
        };

    std::string adminA = "com.test.directA_" + std::to_string(std::rand());
    std::string adminB = "com.test.directB_" + std::to_string(std::rand());
    int32_t userId = 100;

    relayer_->OnAdminSubscribe(adminA, userId, ManagedEvent::BUNDLE_ADDED);
    relayer_->OnAdminSubscribe(adminB, userId, ManagedEvent::BUNDLE_ADDED);

    EdmEventData data;
    data.eventId = EventId{static_cast<uint32_t>(ManagedEvent::BUNDLE_ADDED)};
    EventSubscriptionManager::GetInstance().DispatchEvent(data);

    EXPECT_EQ(strategyCreated, 2);

    relayer_->OnAdminUnsubscribe(adminA, userId, ManagedEvent::BUNDLE_ADDED);
    relayer_->OnAdminUnsubscribe(adminB, userId, ManagedEvent::BUNDLE_ADDED);
    relayer_->strategyFactories_[ManagedEvent::BUNDLE_ADDED] = originalFactory;
}

namespace {
constexpr int32_t TEST_SWITCHED_IN_ACCOUNT_ID = 102;
constexpr int32_t TEST_SWITCHED_OUT_ACCOUNT_ID = 100;
/* 账号切换事件 Want 的切出账号ID参数名（生产侧同名常量定义于 mdm_event_relayer.cpp） */
constexpr const char *TEST_OLD_ACCOUNT_ID_PARAM = "oldId";

/* 构造账号事件数据：CommonEventData.code 承载账号ID，Want 的 oldId 参数承载切出账号ID */
EdmEventData BuildAccountEventData(ManagedEvent event, int32_t accountId, const std::string &oldId)
{
    AAFwk::Want want;
    if (!oldId.empty()) {
        want.SetParam(TEST_OLD_ACCOUNT_ID_PARAM, oldId);
    }
    EventFwk::CommonEventData commonEventData;
    commonEventData.SetCode(accountId);
    commonEventData.SetWant(want);

    EdmEventData data;
    data.eventId = EventId{static_cast<uint32_t>(event)};
    data.commonEventData = commonEventData;
    return data;
}

/* 通过账号事件工厂构造 AccountStrategy，工厂未注册或返回类型不符时返回 nullptr */
std::shared_ptr<AccountStrategy> CreateAccountStrategyForTest(
    MdmEventRelayer *relayer, ManagedEvent event, int32_t accountId, const std::string &oldId)
{
    auto factoryIt = relayer->strategyFactories_.find(event);
    if (factoryIt == relayer->strategyFactories_.end()) {
        return nullptr;
    }
    // 注：OpenHarmony 全局 -fno-rtti，dynamic_pointer_cast 不可用，只能静态向下转换；
    // 类型正确性由三个账号事件工厂的实现保证，用例通过字段值断言间接校验类型行为
    return std::static_pointer_cast<AccountStrategy>(factoryIt->second(
        BuildAccountEventData(event, accountId, oldId)));
}

/* 断言切出账号被判定为不可用：切出账号回退为 INVALID_ACCOUNT_ID，切入账号不受影响 */
void ExpectInvalidOldAccountId(const std::shared_ptr<AccountStrategy> &strategy, const std::string &oldId)
{
    ASSERT_NE(strategy, nullptr) << "oldId=" << oldId;
    EXPECT_EQ(strategy->oldAccountId_, INVALID_ACCOUNT_ID) << "oldId=" << oldId;
    EXPECT_EQ(strategy->accountId_, TEST_SWITCHED_IN_ACCOUNT_ID) << "oldId=" << oldId;
}
} // namespace

/**
 * @tc.name: Test_AccountSwitchFactory_ValidOldId_CarriesBothAccountIds
 * @tc.desc: Test USER_SWITCHED factory parses oldId from Want and builds AccountStrategy
 *           carrying both the switched-in accountId and switched-out oldAccountId.
 * @tc.type: FUNC
 */
HWTEST_F(MdmEventRelayerTest, AccountSwitchFactory_ValidOldId_CarriesBothAccountIds, TestSize.Level1)
{
    auto strategy = CreateAccountStrategyForTest(relayer_, ManagedEvent::USER_SWITCHED,
        TEST_SWITCHED_IN_ACCOUNT_ID, std::to_string(TEST_SWITCHED_OUT_ACCOUNT_ID));
    ASSERT_NE(strategy, nullptr);
    EXPECT_EQ(strategy->GetCode(), static_cast<uint32_t>(IEnterpriseAdmin::COMMAND_ON_ACCOUNT_SWITCHED));
    EXPECT_EQ(strategy->accountId_, TEST_SWITCHED_IN_ACCOUNT_ID);
    EXPECT_EQ(strategy->oldAccountId_, TEST_SWITCHED_OUT_ACCOUNT_ID);
}

/**
 * @tc.name: Test_AccountSwitchFactory_ZeroOldId_KeepsZero
 * @tc.desc: Test USER_SWITCHED with oldId "0" keeps 0 as a valid account ID instead of
 *           being mistaken for unavailable, since 0 is a legal OS account ID.
 * @tc.type: FUNC
 */
HWTEST_F(MdmEventRelayerTest, AccountSwitchFactory_ZeroOldId_KeepsZero, TestSize.Level1)
{
    auto strategy = CreateAccountStrategyForTest(relayer_, ManagedEvent::USER_SWITCHED,
        TEST_SWITCHED_IN_ACCOUNT_ID, "0");
    ASSERT_NE(strategy, nullptr);
    EXPECT_EQ(strategy->oldAccountId_, 0);
    EXPECT_NE(strategy->oldAccountId_, INVALID_ACCOUNT_ID);
}

/**
 * @tc.name: Test_AccountSwitchFactory_MaxOldId_KeepsMax
 * @tc.desc: Test USER_SWITCHED with oldId taking the maximum int32 value is still accepted,
 *           covering the upper boundary of the accepted range.
 * @tc.type: FUNC
 */
HWTEST_F(MdmEventRelayerTest, AccountSwitchFactory_MaxOldId_KeepsMax, TestSize.Level1)
{
    auto strategy = CreateAccountStrategyForTest(relayer_, ManagedEvent::USER_SWITCHED,
        TEST_SWITCHED_IN_ACCOUNT_ID, "2147483647");
    ASSERT_NE(strategy, nullptr);
    EXPECT_EQ(strategy->oldAccountId_, 2147483647);
}

/**
 * @tc.name: Test_AccountSwitchFactory_MissingOldId_FallsBackToInvalid
 * @tc.desc: Test USER_SWITCHED without the oldId param falls back to INVALID_ACCOUNT_ID
 *           while the switched-in accountId is still delivered.
 * @tc.type: FUNC
 */
HWTEST_F(MdmEventRelayerTest, AccountSwitchFactory_MissingOldId_FallsBackToInvalid, TestSize.Level1)
{
    auto strategy = CreateAccountStrategyForTest(relayer_, ManagedEvent::USER_SWITCHED,
        TEST_SWITCHED_IN_ACCOUNT_ID, "");
    ExpectInvalidOldAccountId(strategy, "");
}

/**
 * @tc.name: Test_AccountSwitchFactory_NonNumericOldId_FallsBackToInvalid
 * @tc.desc: Test USER_SWITCHED with a non-numeric oldId falls back to INVALID_ACCOUNT_ID.
 * @tc.type: FUNC
 */
HWTEST_F(MdmEventRelayerTest, AccountSwitchFactory_NonNumericOldId_FallsBackToInvalid, TestSize.Level1)
{
    auto strategy = CreateAccountStrategyForTest(relayer_, ManagedEvent::USER_SWITCHED,
        TEST_SWITCHED_IN_ACCOUNT_ID, "abc");
    ExpectInvalidOldAccountId(strategy, "abc");
}

/**
 * @tc.name: Test_AccountSwitchFactory_TrailingGarbageOldId_FallsBackToInvalid
 * @tc.desc: Test USER_SWITCHED with a partially numeric oldId keeps no leading digits,
 *           falling back to INVALID_ACCOUNT_ID rather than truncating to 100.
 * @tc.type: FUNC
 */
HWTEST_F(MdmEventRelayerTest, AccountSwitchFactory_TrailingGarbageOldId_FallsBackToInvalid, TestSize.Level1)
{
    auto strategy = CreateAccountStrategyForTest(relayer_, ManagedEvent::USER_SWITCHED,
        TEST_SWITCHED_IN_ACCOUNT_ID, "100abc");
    ExpectInvalidOldAccountId(strategy, "100abc");
}

/**
 * @tc.name: Test_AccountSwitchFactory_NegativeOldId_ParsedAsNegative
 * @tc.desc: Test USER_SWITCHED with a negative oldId: OHOS::StrToInt accepts the minus sign,
 *           so the parsed negative value is passed through as-is.
 * @tc.type: FUNC
 */
HWTEST_F(MdmEventRelayerTest, AccountSwitchFactory_NegativeOldId_ParsedAsNegative, TestSize.Level1)
{
    auto strategy = CreateAccountStrategyForTest(relayer_, ManagedEvent::USER_SWITCHED,
        TEST_SWITCHED_IN_ACCOUNT_ID, "-5");
    ASSERT_NE(strategy, nullptr);
    EXPECT_EQ(strategy->oldAccountId_, -5);
}

/**
 * @tc.name: Test_AccountSwitchFactory_OutOfRangeOldId_FallsBackToInvalid
 * @tc.desc: Test USER_SWITCHED with oldId beyond int32 range falls back to INVALID_ACCOUNT_ID
 *           instead of being truncated into a wrong account ID.
 * @tc.type: FUNC
 */
HWTEST_F(MdmEventRelayerTest, AccountSwitchFactory_OutOfRangeOldId_FallsBackToInvalid, TestSize.Level1)
{
    // 前导空白与正号同样拒绝：strtol 会宽松接受，ParseOldAccountId 要求纯数字开头
    for (const char *oldId : {"2147483648", "99999999999999", " 100", "+100"}) {
        SCOPED_TRACE(std::string("oldId=") + oldId);
        auto strategy = CreateAccountStrategyForTest(relayer_, ManagedEvent::USER_SWITCHED,
            TEST_SWITCHED_IN_ACCOUNT_ID, oldId);
        ExpectInvalidOldAccountId(strategy, oldId);
    }
}

/**
 * @tc.name: Test_AccountAddedFactory_IgnoresOldId
 * @tc.desc: Test USER_ADDED factory does not parse oldId, keeping single-account semantics
 *           so account-added callbacks never report a switched-out account.
 * @tc.type: FUNC
 */
HWTEST_F(MdmEventRelayerTest, AccountAddedFactory_IgnoresOldId, TestSize.Level1)
{
    auto strategy = CreateAccountStrategyForTest(relayer_, ManagedEvent::USER_ADDED,
        TEST_SWITCHED_IN_ACCOUNT_ID, std::to_string(TEST_SWITCHED_OUT_ACCOUNT_ID));
    ASSERT_NE(strategy, nullptr);
    EXPECT_EQ(strategy->GetCode(), static_cast<uint32_t>(IEnterpriseAdmin::COMMAND_ON_ACCOUNT_ADDED));
    EXPECT_EQ(strategy->accountId_, TEST_SWITCHED_IN_ACCOUNT_ID);
    EXPECT_EQ(strategy->oldAccountId_, INVALID_ACCOUNT_ID);
}

/**
 * @tc.name: Test_AccountRemovedFactory_IgnoresOldId
 * @tc.desc: Test USER_REMOVED factory does not parse oldId, keeping single-account semantics
 *           so account-removed callbacks never report a switched-out account.
 * @tc.type: FUNC
 */
HWTEST_F(MdmEventRelayerTest, AccountRemovedFactory_IgnoresOldId, TestSize.Level1)
{
    auto strategy = CreateAccountStrategyForTest(relayer_, ManagedEvent::USER_REMOVED,
        TEST_SWITCHED_IN_ACCOUNT_ID, std::to_string(TEST_SWITCHED_OUT_ACCOUNT_ID));
    ASSERT_NE(strategy, nullptr);
    EXPECT_EQ(strategy->GetCode(), static_cast<uint32_t>(IEnterpriseAdmin::COMMAND_ON_ACCOUNT_REMOVED));
    EXPECT_EQ(strategy->accountId_, TEST_SWITCHED_IN_ACCOUNT_ID);
    EXPECT_EQ(strategy->oldAccountId_, INVALID_ACCOUNT_ID);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
