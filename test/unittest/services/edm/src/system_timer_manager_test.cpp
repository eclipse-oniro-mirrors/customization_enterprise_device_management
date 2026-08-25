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

#include <atomic>
#include <map>
#include <mutex>
#include <string>

#define private public
#define protected public
#include "edm_timer_info_sa.h"
#include "system_timer_manager.h"
#include "timer_death_recipient.h"
#undef protected
#undef private

#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "func_code.h"
#include "i_timer_callback.h"
#include "iremote_stub.h"
#include "message_parcel.h"
#include "time_service_client.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
namespace {
const std::string ADMIN_A = "com.example.admin_a";
const std::string ADMIN_B = "com.example.admin_b";
const std::string TIMER_NAME = "test_timer";
const uint64_t TEST_TIMER_ID = 10001;
const uint64_t TEST_TIMER_ID_2 = 10002;
const uint64_t TEST_TRIGGER_TIME = 5000;
constexpr uint32_t COMMAND_ON_TIMER_TRIGGERED = 1;

uint32_t MakeTimerFuncCode()
{
    return POLICY_FUNC_CODE(static_cast<uint32_t>(FuncOperateType::SET),
        EdmInterfaceCode::SYSTEM_TIMER_OPERATION);
}
} // namespace

class TestTimerCallbackStub : public IRemoteStub<ITimerCallback> {
public:
    TestTimerCallbackStub() = default;
    ~TestTimerCallbackStub() override = default;
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        if (code == COMMAND_ON_TIMER_TRIGGERED) {
            data.ReadInterfaceToken();
            uint64_t timerId = data.ReadUint64();
            OnTimerTriggered(timerId);
            return ERR_OK;
        }
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    void OnTimerTriggered(uint64_t timerId) override
    {
        triggeredTimerId_.store(timerId);
        triggerCount_.fetch_add(1);
    }
    std::atomic<uint64_t> triggeredTimerId_{0};
    std::atomic<int32_t> triggerCount_{0};
};

class SystemTimerManagerTest : public testing::Test {
public:
    void SetUp() override
    {
        instance_ = SystemTimerManager::GetInstance();
        ASSERT_TRUE(instance_ != nullptr);
        CleanupAllTimers();
    }

    void TearDown() override
    {
        CleanupAllTimers();
    }

protected:
    SystemTimerManager* instance_ = nullptr;

    void CleanupAllTimers()
    {
        std::lock_guard<std::mutex> lock(instance_->mutex_);
        auto timer = MiscServices::TimeServiceClient::GetInstance();
        for (auto &[timerId, entry] : instance_->timerMap_) {
            if (timer != nullptr) {
                timer->DestroyTimer(timerId);
            }
        }
        instance_->timerMap_.clear();
        instance_->recipientMap_.clear();
    }

    void InjectTimerEntry(uint64_t timerId, const std::string &admin, const sptr<IRemoteObject> &callback)
    {
        std::lock_guard<std::mutex> lock(instance_->mutex_);
        TimerEntry entry;
        entry.adminBundleName = admin;
        entry.clientCallback = callback;
        instance_->timerMap_[timerId] = entry;
    }

    size_t GetTimerMapSize()
    {
        std::lock_guard<std::mutex> lock(instance_->mutex_);
        return instance_->timerMap_.size();
    }

    bool TimerExists(uint64_t timerId)
    {
        std::lock_guard<std::mutex> lock(instance_->mutex_);
        return instance_->timerMap_.find(timerId) != instance_->timerMap_.end();
    }
};

/**
 * @tc.name: GetInstance_Singleton
 * @tc.desc: Test GetInstance returns a non-null singleton that is stable across calls.
 * @tc.type: FUNC
 */
HWTEST_F(SystemTimerManagerTest, GetInstance_Singleton, TestSize.Level1)
{
    auto* inst1 = SystemTimerManager::GetInstance();
    auto* inst2 = SystemTimerManager::GetInstance();
    ASSERT_TRUE(inst1 != nullptr);
    ASSERT_TRUE(inst2 != nullptr);
    EXPECT_EQ(inst1, inst2);
}

/**
 * @tc.name: IsTimerOwner_MatchesAdminOnly
 * @tc.desc: Test IsTimerOwner returns true only for the owning admin, false for a
 *           different admin or a non-existent timer.
 * @tc.type: FUNC
 */
HWTEST_F(SystemTimerManagerTest, IsTimerOwner_MatchesAdminOnly, TestSize.Level1)
{
    auto callback = new TestTimerCallbackStub();
    InjectTimerEntry(TEST_TIMER_ID, ADMIN_A, callback);
    EXPECT_TRUE(instance_->IsTimerOwner(TEST_TIMER_ID, ADMIN_A));
    EXPECT_FALSE(instance_->IsTimerOwner(TEST_TIMER_ID, ADMIN_B));
    EXPECT_FALSE(instance_->IsTimerOwner(TEST_TIMER_ID_2, ADMIN_A));
}

/**
 * @tc.name: StartTimer_NonOwnerOrNonExistent_ReturnNotFound
 * @tc.desc: Test StartTimer returns SYSTEM_TIMER_NOT_FOUND for a non-owner admin or a
 *           non-existent timer, leaving the owned entry intact.
 * @tc.type: FUNC
 */
HWTEST_F(SystemTimerManagerTest, StartTimer_NonOwnerOrNonExistent_ReturnNotFound, TestSize.Level1)
{
    auto callback = new TestTimerCallbackStub();
    InjectTimerEntry(TEST_TIMER_ID, ADMIN_A, callback);
    ASSERT_EQ(GetTimerMapSize(), 1u);

    EXPECT_EQ(instance_->StartTimer(TEST_TIMER_ID, TEST_TRIGGER_TIME, ADMIN_B),
        EdmReturnErrCode::SYSTEM_TIMER_NOT_FOUND);
    EXPECT_EQ(instance_->StartTimer(TEST_TIMER_ID_2, TEST_TRIGGER_TIME, ADMIN_A),
        EdmReturnErrCode::SYSTEM_TIMER_NOT_FOUND);
    EXPECT_TRUE(TimerExists(TEST_TIMER_ID));
}

/**
 * @tc.name: StopTimer_NonOwnerOrNonExistent_ReturnNotFound
 * @tc.desc: Test StopTimer returns SYSTEM_TIMER_NOT_FOUND for a non-owner admin or a
 *           non-existent timer, leaving the owned entry intact.
 * @tc.type: FUNC
 */
HWTEST_F(SystemTimerManagerTest, StopTimer_NonOwnerOrNonExistent_ReturnNotFound, TestSize.Level1)
{
    auto callback = new TestTimerCallbackStub();
    InjectTimerEntry(TEST_TIMER_ID, ADMIN_A, callback);
    ASSERT_EQ(GetTimerMapSize(), 1u);

    EXPECT_EQ(instance_->StopTimer(TEST_TIMER_ID, ADMIN_B), EdmReturnErrCode::SYSTEM_TIMER_NOT_FOUND);
    EXPECT_EQ(instance_->StopTimer(TEST_TIMER_ID_2, ADMIN_A), EdmReturnErrCode::SYSTEM_TIMER_NOT_FOUND);
    EXPECT_TRUE(TimerExists(TEST_TIMER_ID));
}

/**
 * @tc.name: DestroyTimer_NonOwnerOrNonExistent_PreservesEntry
 * @tc.desc: Test DestroyTimer returns SYSTEM_TIMER_NOT_FOUND for a non-owner or
 *           non-existent timer and preserves the owned entry.
 * @tc.type: FUNC
 */
HWTEST_F(SystemTimerManagerTest, DestroyTimer_NonOwnerOrNonExistent_PreservesEntry, TestSize.Level1)
{
    auto callback = new TestTimerCallbackStub();
    InjectTimerEntry(TEST_TIMER_ID, ADMIN_A, callback);
    ASSERT_TRUE(TimerExists(TEST_TIMER_ID));

    EXPECT_EQ(instance_->DestroyTimer(TEST_TIMER_ID, ADMIN_B), EdmReturnErrCode::SYSTEM_TIMER_NOT_FOUND);
    EXPECT_TRUE(TimerExists(TEST_TIMER_ID));
    EXPECT_EQ(instance_->DestroyTimer(TEST_TIMER_ID_2, ADMIN_A), EdmReturnErrCode::SYSTEM_TIMER_NOT_FOUND);
    EXPECT_TRUE(TimerExists(TEST_TIMER_ID));
}

/**
 * @tc.name: DestroyTimer_Owner_RemovesFromMap
 * @tc.desc: Test DestroyTimer removes the entry for the owning admin and a subsequent
 *           destroy is not found.
 * @tc.type: FUNC
 */
HWTEST_F(SystemTimerManagerTest, DestroyTimer_Owner_RemovesFromMap, TestSize.Level1)
{
    auto callback = new TestTimerCallbackStub();
    InjectTimerEntry(TEST_TIMER_ID, ADMIN_A, callback);
    ASSERT_TRUE(TimerExists(TEST_TIMER_ID));

    EXPECT_EQ(instance_->DestroyTimer(TEST_TIMER_ID, ADMIN_A), ERR_OK);
    EXPECT_FALSE(TimerExists(TEST_TIMER_ID));
    EXPECT_EQ(instance_->DestroyTimer(TEST_TIMER_ID, ADMIN_A), EdmReturnErrCode::SYSTEM_TIMER_NOT_FOUND);
}

/**
 * @tc.name: OnTimerTriggered_NotExist_NoOp
 * @tc.desc: Test OnTimerTriggered is a safe no-op (and idempotent) for an absent timer.
 * @tc.type: FUNC
 */
HWTEST_F(SystemTimerManagerTest, OnTimerTriggered_NotExist_NoOp, TestSize.Level1)
{
    EXPECT_EQ(GetTimerMapSize(), 0u);
    instance_->OnTimerTriggered(TEST_TIMER_ID);
    EXPECT_FALSE(TimerExists(TEST_TIMER_ID));
    instance_->OnTimerTriggered(TEST_TIMER_ID);
    EXPECT_EQ(GetTimerMapSize(), 0u);
}

/**
 * @tc.name: OnTimerTriggered_ClientAlive_SendRequest
 * @tc.desc: Test OnTimerTriggered sends the reverse IPC to the client callback when it
 *           is alive, and does not consume the entry.
 * @tc.type: FUNC
 */
HWTEST_F(SystemTimerManagerTest, OnTimerTriggered_ClientAlive_SendRequest, TestSize.Level1)
{
    auto callback = new TestTimerCallbackStub();
    InjectTimerEntry(TEST_TIMER_ID, ADMIN_A, callback);
    instance_->OnTimerTriggered(TEST_TIMER_ID);
    EXPECT_EQ(callback->triggerCount_.load(), 1);
    EXPECT_EQ(callback->triggeredTimerId_.load(), TEST_TIMER_ID);
    EXPECT_TRUE(TimerExists(TEST_TIMER_ID));
}

/**
 * @tc.name: OnRemoteDied_RemovesMatchingTimers
 * @tc.desc: Test OnRemoteDied is a no-op on an empty map and removes all timers sharing
 *           the died callback.
 * @tc.type: FUNC
 */
HWTEST_F(SystemTimerManagerTest, OnRemoteDied_RemovesMatchingTimers, TestSize.Level1)
{
    auto orphan = new TestTimerCallbackStub();
    wptr<IRemoteObject> wpOrphan(orphan);
    instance_->OnRemoteDied(wpOrphan);
    EXPECT_EQ(GetTimerMapSize(), 0u);

    auto callback = new TestTimerCallbackStub();
    InjectTimerEntry(TEST_TIMER_ID, ADMIN_A, callback);
    InjectTimerEntry(TEST_TIMER_ID_2, ADMIN_A, callback);
    ASSERT_EQ(GetTimerMapSize(), 2u);
    wptr<IRemoteObject> wp(callback);
    instance_->OnRemoteDied(wp);
    EXPECT_FALSE(TimerExists(TEST_TIMER_ID));
    EXPECT_FALSE(TimerExists(TEST_TIMER_ID_2));
}

/**
 * @tc.name: OnRemoteDied_LeavesNonMatchingTimer
 * @tc.desc: Test OnRemoteDied removes only the timers bound to the died callback and
 *           leaves timers bound to other callbacks intact.
 * @tc.type: FUNC
 */
HWTEST_F(SystemTimerManagerTest, OnRemoteDied_LeavesNonMatchingTimer, TestSize.Level1)
{
    auto callbackA = new TestTimerCallbackStub();
    auto callbackB = new TestTimerCallbackStub();
    InjectTimerEntry(TEST_TIMER_ID, ADMIN_A, callbackA);
    InjectTimerEntry(TEST_TIMER_ID_2, ADMIN_B, callbackB);
    ASSERT_EQ(GetTimerMapSize(), 2u);

    wptr<IRemoteObject> wpA(callbackA);
    instance_->OnRemoteDied(wpA);
    EXPECT_FALSE(TimerExists(TEST_TIMER_ID));
    EXPECT_TRUE(TimerExists(TEST_TIMER_ID_2));
}

/**
 * @tc.name: OnAdminRemove_RemovesOwnTimers
 * @tc.desc: Test OnAdminRemove removes all timers belonging to the named admin.
 * @tc.type: FUNC
 */
HWTEST_F(SystemTimerManagerTest, OnAdminRemove_RemovesOwnTimers, TestSize.Level1)
{
    auto callback = new TestTimerCallbackStub();
    InjectTimerEntry(TEST_TIMER_ID, ADMIN_A, callback);
    InjectTimerEntry(TEST_TIMER_ID_2, ADMIN_A, callback);
    ASSERT_EQ(GetTimerMapSize(), 2u);

    instance_->OnAdminRemove(ADMIN_A);
    EXPECT_FALSE(TimerExists(TEST_TIMER_ID));
    EXPECT_FALSE(TimerExists(TEST_TIMER_ID_2));
}

/**
 * @tc.name: OnAdminRemove_LeavesOtherAdmins
 * @tc.desc: Test OnAdminRemove is a no-op for an admin with no timers and only removes
 *           the named admin's timers, leaving other admins' timers intact.
 * @tc.type: FUNC
 */
HWTEST_F(SystemTimerManagerTest, OnAdminRemove_LeavesOtherAdmins, TestSize.Level1)
{
    auto callback = new TestTimerCallbackStub();
    InjectTimerEntry(TEST_TIMER_ID, ADMIN_A, callback);
    instance_->OnAdminRemove(ADMIN_B);
    EXPECT_TRUE(TimerExists(TEST_TIMER_ID));

    auto callbackB = new TestTimerCallbackStub();
    InjectTimerEntry(TEST_TIMER_ID_2, ADMIN_B, callbackB);
    instance_->OnAdminRemove(ADMIN_A);
    EXPECT_FALSE(TimerExists(TEST_TIMER_ID));
    EXPECT_TRUE(TimerExists(TEST_TIMER_ID_2));
}

/**
 * @tc.name: HandleTimerOperation_OperationType_Invalid
 * @tc.desc: Test HandleTimerOperation returns an error when the operationType cannot be
 *           read or is an unknown value.
 * @tc.type: FUNC
 */
HWTEST_F(SystemTimerManagerTest, HandleTimerOperation_OperationType_Invalid, TestSize.Level1)
{
    uint32_t funcCode = MakeTimerFuncCode();
    MessageParcel reply;
    {
        MessageParcel data;
        EXPECT_EQ(instance_->HandleTimerOperation(funcCode, ADMIN_A, data, reply, 0),
            EdmReturnErrCode::PARAM_ERROR);
    }
    {
        MessageParcel data;
        data.WriteInt32(999);
        EXPECT_EQ(instance_->HandleTimerOperation(funcCode, ADMIN_A, data, reply, 0),
            EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    }
}

/**
 * @tc.name: HandleTimerOperation_Create_NameTooLong
 * @tc.desc: Test HandleTimerOperation CREATE with a name exceeding TIMER_NAME_MAX_LEN
 *           is rejected and does not create state.
 * @tc.type: FUNC
 */
HWTEST_F(SystemTimerManagerTest, HandleTimerOperation_Create_NameTooLong, TestSize.Level1)
{
    MessageParcel data;
    data.WriteInt32(static_cast<int32_t>(TimerOperationType::CREATE));
    data.WriteBool(false);
    data.WriteUint64(0);
    data.WriteString(std::string(EdmConstants::SystemTimer::TIMER_NAME_MAX_LEN + 1, 'x'));
    MessageParcel reply;
    EXPECT_EQ(instance_->HandleTimerOperation(MakeTimerFuncCode(), ADMIN_A, data, reply, 0),
        EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    EXPECT_EQ(GetTimerMapSize(), 0u);
}

/**
 * @tc.name: HandleTimerOperation_Create_IntervalOutOfRange
 * @tc.desc: Test HandleTimerOperation CREATE with a repeating timer rejects intervals
 *           below the minimum and above the maximum.
 * @tc.type: FUNC
 */
HWTEST_F(SystemTimerManagerTest, HandleTimerOperation_Create_IntervalOutOfRange, TestSize.Level1)
{
    uint32_t funcCode = MakeTimerFuncCode();
    MessageParcel reply;
    {
        MessageParcel data;
        data.WriteInt32(static_cast<int32_t>(TimerOperationType::CREATE));
        data.WriteBool(true);
        data.WriteUint64(EdmConstants::SystemTimer::TIMER_INTERVAL_MIN_MS - 1);
        data.WriteString(TIMER_NAME);
        EXPECT_EQ(instance_->HandleTimerOperation(funcCode, ADMIN_A, data, reply, 0),
            EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    }
    {
        MessageParcel data;
        data.WriteInt32(static_cast<int32_t>(TimerOperationType::CREATE));
        data.WriteBool(true);
        data.WriteUint64(EdmConstants::SystemTimer::TIMER_INTERVAL_MAX_MS + 1);
        data.WriteString(TIMER_NAME);
        EXPECT_EQ(instance_->HandleTimerOperation(funcCode, ADMIN_A, data, reply, 0),
            EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    }
}

/**
 * @tc.name: HandleTimerOperation_Create_NullClientCallback
 * @tc.desc: Test HandleTimerOperation CREATE without a client callback remote object is
 *           rejected with PARAM_ERROR and creates no state.
 * @tc.type: FUNC
 */
HWTEST_F(SystemTimerManagerTest, HandleTimerOperation_Create_NullClientCallback, TestSize.Level1)
{
    MessageParcel data;
    data.WriteInt32(static_cast<int32_t>(TimerOperationType::CREATE));
    data.WriteBool(false);
    data.WriteUint64(0);
    data.WriteString(TIMER_NAME);
    MessageParcel reply;
    EXPECT_EQ(instance_->HandleTimerOperation(MakeTimerFuncCode(), ADMIN_A, data, reply, 0),
        EdmReturnErrCode::PARAM_ERROR);
    EXPECT_EQ(GetTimerMapSize(), 0u);
}

/**
 * @tc.name: HandleTimerOperation_Start_TriggerTimeZero
 * @tc.desc: Test HandleTimerOperation START with triggerTime == 0 is rejected.
 * @tc.type: FUNC
 */
HWTEST_F(SystemTimerManagerTest, HandleTimerOperation_Start_TriggerTimeZero, TestSize.Level1)
{
    MessageParcel data;
    data.WriteInt32(static_cast<int32_t>(TimerOperationType::START));
    data.WriteUint64(TEST_TIMER_ID);
    data.WriteUint64(0);
    MessageParcel reply;
    EXPECT_EQ(instance_->HandleTimerOperation(MakeTimerFuncCode(), ADMIN_A, data, reply, 0),
        EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: HandleTimerOperation_Destroy_Owner_Ok
 * @tc.desc: Test HandleTimerOperation DESTROY by the owning admin succeeds and removes
 *           the entry.
 * @tc.type: FUNC
 */
HWTEST_F(SystemTimerManagerTest, HandleTimerOperation_Destroy_Owner_Ok, TestSize.Level1)
{
    auto callback = new TestTimerCallbackStub();
    InjectTimerEntry(TEST_TIMER_ID, ADMIN_A, callback);
    ASSERT_TRUE(TimerExists(TEST_TIMER_ID));

    MessageParcel data;
    data.WriteInt32(static_cast<int32_t>(TimerOperationType::DESTROY));
    data.WriteUint64(TEST_TIMER_ID);
    MessageParcel reply;
    EXPECT_EQ(instance_->HandleTimerOperation(MakeTimerFuncCode(), ADMIN_A, data, reply, 0), ERR_OK);
    EXPECT_FALSE(TimerExists(TEST_TIMER_ID));
}

/**
 * @tc.name: CreateTimer_PerAdminCountLimit
 * @tc.desc: Test CreateTimer enforces TIMER_MAX_COUNT_PER_ADMIN per admin: rejects at the
 *           limit, allows below the limit, and counts admins independently.
 * @tc.type: FUNC
 */
HWTEST_F(SystemTimerManagerTest, CreateTimer_PerAdminCountLimit, TestSize.Level1)
{
    auto callback = new TestTimerCallbackStub();
    uint64_t timerId = 0;
    TimerOptions options{false, 0, TIMER_NAME, callback};

    for (uint32_t i = 0; i < EdmConstants::SystemTimer::TIMER_MAX_COUNT_PER_ADMIN; ++i) {
        InjectTimerEntry(TEST_TIMER_ID + i, ADMIN_A, callback);
    }
    EXPECT_EQ(instance_->CreateTimer(options, ADMIN_A, 0, timerId),
        EdmReturnErrCode::SYSTEM_TIMER_MAX_COUNT_REACHED);
    EXPECT_EQ(timerId, 0u);
    CleanupAllTimers();

    for (uint32_t i = 0; i < EdmConstants::SystemTimer::TIMER_MAX_COUNT_PER_ADMIN - 1; ++i) {
        InjectTimerEntry(TEST_TIMER_ID + i, ADMIN_A, callback);
    }
    EXPECT_NE(instance_->CreateTimer(options, ADMIN_A, 0, timerId),
        EdmReturnErrCode::SYSTEM_TIMER_MAX_COUNT_REACHED);
    CleanupAllTimers();

    for (uint32_t i = 0; i < EdmConstants::SystemTimer::TIMER_MAX_COUNT_PER_ADMIN; ++i) {
        InjectTimerEntry(TEST_TIMER_ID + i, ADMIN_A, callback);
    }
    EXPECT_NE(instance_->CreateTimer(options, ADMIN_B, 0, timerId),
        EdmReturnErrCode::SYSTEM_TIMER_MAX_COUNT_REACHED);
}

/**
 * @tc.name: EdmTimerInfoSa_Setters
 * @tc.desc: Test EdmTimerInfoSa setters store the provided values.
 * @tc.type: FUNC
 */
HWTEST_F(SystemTimerManagerTest, EdmTimerInfoSa_Setters, TestSize.Level1)
{
    EdmTimerInfoSa timerInfo(0);
    timerInfo.SetType(EdmConstants::SystemTimer::DEFAULT_TIMER_TYPE);
    EXPECT_EQ(timerInfo.type, EdmConstants::SystemTimer::DEFAULT_TIMER_TYPE);
    timerInfo.SetRepeat(true);
    EXPECT_TRUE(timerInfo.repeat);
    uint64_t interval = 5000;
    timerInfo.SetInterval(interval);
    EXPECT_EQ(timerInfo.interval, interval);
    std::string name = "test_name";
    timerInfo.SetName(name);
    EXPECT_EQ(timerInfo.name, name);
    timerInfo.SetTimerId(TEST_TIMER_ID);
    EXPECT_EQ(timerInfo.timerId_, TEST_TIMER_ID);
}

/**
 * @tc.name: EdmTimerInfoSa_OnTrigger_NullAndRegistered
 * @tc.desc: Test EdmTimerInfoSa::OnTrigger is a safe no-op with no callback set, and
 *           invokes a registered callback with the stored timerId.
 * @tc.type: FUNC
 */
HWTEST_F(SystemTimerManagerTest, EdmTimerInfoSa_OnTrigger_NullAndRegistered, TestSize.Level1)
{
    EdmTimerInfoSa timerInfo(0);
    timerInfo.SetTimerId(TEST_TIMER_ID);
    timerInfo.OnTrigger();

    std::atomic<bool> called{false};
    uint64_t captured = 0;
    timerInfo.SetTriggerCallback([&called, &captured](uint64_t id) {
        called.store(true);
        captured = id;
    });
    timerInfo.OnTrigger();
    EXPECT_TRUE(called.load());
    EXPECT_EQ(captured, TEST_TIMER_ID);
}

/**
 * @tc.name: TimerDeathRecipient_DelegatesToManager
 * @tc.desc: Test TimerDeathRecipient::OnRemoteDied delegates to SystemTimerManager and
 *           removes the timer bound to the died remote object.
 * @tc.type: FUNC
 */
HWTEST_F(SystemTimerManagerTest, TimerDeathRecipient_DelegatesToManager, TestSize.Level1)
{
    auto callback = new TestTimerCallbackStub();
    InjectTimerEntry(TEST_TIMER_ID, ADMIN_A, callback);
    ASSERT_TRUE(TimerExists(TEST_TIMER_ID));

    auto deathRecipient = new TimerDeathRecipient();
    wptr<IRemoteObject> wp(callback);
    deathRecipient->OnRemoteDied(wp);
    EXPECT_FALSE(TimerExists(TEST_TIMER_ID));
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
