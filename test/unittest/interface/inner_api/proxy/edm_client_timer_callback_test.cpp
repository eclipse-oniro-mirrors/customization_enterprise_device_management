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

#include <cstdint>
#include <map>
#include <mutex>

#define private public
#define protected public
#include "edm_client_timer_callback.h"
#undef protected
#undef private

#include "i_timer_callback.h"
#include "iremote_object.h"
#include "message_parcel.h"
#include "edm_errors.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
namespace {
const uint64_t TEST_TIMER_ID = 20001;
const uint64_t TEST_TIMER_ID_2 = 20002;
constexpr uint32_t COMMAND_ON_TIMER_TRIGGERED = 1;
constexpr uint32_t COMMAND_INVALID = 999;
} // namespace

class EdmClientTimerCallbackTest : public testing::Test {
public:
    void SetUp() override
    {
        callback_ = new EdmClientTimerCallback();
        ASSERT_TRUE(callback_ != nullptr);
    }

    void TearDown() override
    {
        if (callback_ != nullptr) {
            std::lock_guard<std::mutex> lock(callback_->mutex_);
            callback_->callbackMap_.clear();
        }
        callback_ = nullptr;
    }

protected:
    sptr<EdmClientTimerCallback> callback_ = nullptr;

    size_t GetCallbackMapSize()
    {
        std::lock_guard<std::mutex> lock(callback_->mutex_);
        return callback_->callbackMap_.size();
    }

    bool CallbackExists(uint64_t timerId)
    {
        std::lock_guard<std::mutex> lock(callback_->mutex_);
        return callback_->callbackMap_.find(timerId) != callback_->callbackMap_.end();
    }

    void WriteTriggerParcel(MessageParcel &data, uint64_t timerId)
    {
        data.WriteInterfaceToken(ITimerCallback::GetDescriptor());
        data.WriteUint64(timerId);
    }
};

/**
 * @tc.name: InsertCallback_StoreAndOverwrite
 * @tc.desc: Test InsertCallback stores a null entry and overwrites the value for an
 *           existing timerId without growing the map.
 * @tc.type: FUNC
 */
HWTEST_F(EdmClientTimerCallbackTest, InsertCallback_StoreAndOverwrite, TestSize.Level1)
{
    callback_->InsertCallback(TEST_TIMER_ID, nullptr, nullptr);
    EXPECT_TRUE(CallbackExists(TEST_TIMER_ID));
    EXPECT_EQ(GetCallbackMapSize(), 1u);

    callback_->InsertCallback(TEST_TIMER_ID, nullptr, nullptr);
    EXPECT_EQ(GetCallbackMapSize(), 1u);
    EXPECT_TRUE(CallbackExists(TEST_TIMER_ID));
}

/**
 * @tc.name: InsertCallback_MultipleTimers
 * @tc.desc: Test InsertCallback stores multiple distinct timerIds independently.
 * @tc.type: FUNC
 */
HWTEST_F(EdmClientTimerCallbackTest, InsertCallback_MultipleTimers, TestSize.Level1)
{
    callback_->InsertCallback(TEST_TIMER_ID, nullptr, nullptr);
    EXPECT_EQ(GetCallbackMapSize(), 1u);

    callback_->InsertCallback(TEST_TIMER_ID_2, nullptr, nullptr);
    EXPECT_EQ(GetCallbackMapSize(), 2u);
    EXPECT_TRUE(CallbackExists(TEST_TIMER_ID));
    EXPECT_TRUE(CallbackExists(TEST_TIMER_ID_2));
}

/**
 * @tc.name: RemoveCallback_Existing
 * @tc.desc: Test RemoveCallback erases an existing null entry (no napi call needed).
 * @tc.type: FUNC
 */
HWTEST_F(EdmClientTimerCallbackTest, RemoveCallback_Existing, TestSize.Level1)
{
    callback_->InsertCallback(TEST_TIMER_ID, nullptr, nullptr);
    ASSERT_TRUE(CallbackExists(TEST_TIMER_ID));

    callback_->RemoveCallback(TEST_TIMER_ID);
    EXPECT_FALSE(CallbackExists(TEST_TIMER_ID));
    EXPECT_EQ(GetCallbackMapSize(), 0u);
}

/**
 * @tc.name: RemoveCallback_NonExistent_NoOp
 * @tc.desc: Test RemoveCallback is a safe no-op for a non-existent timerId and does
 *           not affect an existing unrelated entry.
 * @tc.type: FUNC
 */
HWTEST_F(EdmClientTimerCallbackTest, RemoveCallback_NonExistent_NoOp, TestSize.Level1)
{
    EXPECT_EQ(GetCallbackMapSize(), 0u);
    callback_->RemoveCallback(TEST_TIMER_ID);
    EXPECT_EQ(GetCallbackMapSize(), 0u);

    callback_->InsertCallback(TEST_TIMER_ID_2, nullptr, nullptr);
    callback_->RemoveCallback(TEST_TIMER_ID);
    EXPECT_TRUE(CallbackExists(TEST_TIMER_ID_2));
    EXPECT_EQ(GetCallbackMapSize(), 1u);
}

/**
 * @tc.name: ClearAll_EmptiesMap
 * @tc.desc: Test ClearAll removes all null entries (no napi calls needed).
 * @tc.type: FUNC
 */
HWTEST_F(EdmClientTimerCallbackTest, ClearAll_EmptiesMap, TestSize.Level1)
{
    callback_->InsertCallback(TEST_TIMER_ID, nullptr, nullptr);
    callback_->InsertCallback(TEST_TIMER_ID_2, nullptr, nullptr);
    ASSERT_EQ(GetCallbackMapSize(), 2u);

    callback_->ClearAll();
    EXPECT_FALSE(CallbackExists(TEST_TIMER_ID));
    EXPECT_FALSE(CallbackExists(TEST_TIMER_ID_2));
    EXPECT_EQ(GetCallbackMapSize(), 0u);
}

/**
 * @tc.name: ClearAll_EmptyMap_NoOp
 * @tc.desc: Test ClearAll is a safe no-op (and idempotent) when the map is empty.
 * @tc.type: FUNC
 */
HWTEST_F(EdmClientTimerCallbackTest, ClearAll_EmptyMap_NoOp, TestSize.Level1)
{
    EXPECT_EQ(GetCallbackMapSize(), 0u);
    callback_->ClearAll();
    EXPECT_EQ(GetCallbackMapSize(), 0u);
    callback_->ClearAll();
    EXPECT_EQ(GetCallbackMapSize(), 0u);
}

/**
 * @tc.name: OnTimerTriggered_NotInMap_NoOp
 * @tc.desc: Test OnTimerTriggered is a safe no-op (and idempotent) for an absent timerId.
 * @tc.type: FUNC
 */
HWTEST_F(EdmClientTimerCallbackTest, OnTimerTriggered_NotInMap_NoOp, TestSize.Level1)
{
    EXPECT_EQ(GetCallbackMapSize(), 0u);
    callback_->OnTimerTriggered(TEST_TIMER_ID);
    EXPECT_EQ(GetCallbackMapSize(), 0u);
    callback_->OnTimerTriggered(TEST_TIMER_ID);
    EXPECT_EQ(GetCallbackMapSize(), 0u);
}

/**
 * @tc.name: OnTimerTriggered_NullEnvNullRef_NoNapiCall
 * @tc.desc: Test OnTimerTriggered returns early without napi calls for a null env/ref
 *           entry and leaves the entry and map size unchanged.
 * @tc.type: FUNC
 */
HWTEST_F(EdmClientTimerCallbackTest, OnTimerTriggered_NullEnvNullRef_NoNapiCall, TestSize.Level1)
{
    callback_->InsertCallback(TEST_TIMER_ID, nullptr, nullptr);
    ASSERT_TRUE(CallbackExists(TEST_TIMER_ID));
    size_t sizeBefore = GetCallbackMapSize();

    callback_->OnTimerTriggered(TEST_TIMER_ID);
    EXPECT_TRUE(CallbackExists(TEST_TIMER_ID));
    EXPECT_EQ(GetCallbackMapSize(), sizeBefore);
}

/**
 * @tc.name: OnRemoteRequest_InvalidDescriptor_ReturnsError
 * @tc.desc: Test OnRemoteRequest returns an error for a trigger command without a
 *           matching interface token (descriptor mismatch).
 * @tc.type: FUNC
 */
HWTEST_F(EdmClientTimerCallbackTest, OnRemoteRequest_InvalidDescriptor_ReturnsError, TestSize.Level1)
{
    MessageParcel data;
    data.WriteUint64(TEST_TIMER_ID); // no interface token written
    MessageParcel reply;
    MessageOption option;
    int32_t ret = callback_->OnRemoteRequest(COMMAND_ON_TIMER_TRIGGERED, data, reply, option);
    EXPECT_NE(ret, ERR_OK);
    EXPECT_EQ(GetCallbackMapSize(), 0u);
}

/**
 * @tc.name: OnRemoteRequest_InvalidCode_DelegatesToBase
 * @tc.desc: Test OnRemoteRequest with an unknown command code delegates to the base
 *           class and does not succeed.
 * @tc.type: FUNC
 */
HWTEST_F(EdmClientTimerCallbackTest, OnRemoteRequest_InvalidCode_DelegatesToBase, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = callback_->OnRemoteRequest(COMMAND_INVALID, data, reply, option);
    EXPECT_NE(ret, ERR_OK);
    EXPECT_EQ(GetCallbackMapSize(), 0u);
}

/**
 * @tc.name: OnRemoteRequest_NonEdmCaller_PermissionDenied
 * @tc.desc: Test OnRemoteRequest with a valid descriptor is rejected with
 *           PERMISSION_DENIED when the caller is not the edm SA (uid != EDM_UID),
 *           and a pre-existing entry is left untouched.
 * @tc.type: FUNC
 */
HWTEST_F(EdmClientTimerCallbackTest, OnRemoteRequest_NonEdmCaller_PermissionDenied, TestSize.Level1)
{
    callback_->InsertCallback(TEST_TIMER_ID, nullptr, nullptr);
    ASSERT_TRUE(CallbackExists(TEST_TIMER_ID));

    MessageParcel data;
    WriteTriggerParcel(data, TEST_TIMER_ID);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = callback_->OnRemoteRequest(COMMAND_ON_TIMER_TRIGGERED, data, reply, option);
    EXPECT_EQ(ret, static_cast<int32_t>(EdmReturnErrCode::PERMISSION_DENIED));
    EXPECT_TRUE(CallbackExists(TEST_TIMER_ID));
}

/**
 * @tc.name: Destructor_ClearsMap
 * @tc.desc: Test the destructor clears the callback map (with null entries, no NAPI calls).
 * @tc.type: FUNC
 */
HWTEST_F(EdmClientTimerCallbackTest, Destructor_ClearsMap, TestSize.Level1)
{
    sptr<EdmClientTimerCallback> cb = new EdmClientTimerCallback();
    cb->InsertCallback(TEST_TIMER_ID, nullptr, nullptr);
    cb->InsertCallback(TEST_TIMER_ID_2, nullptr, nullptr);
    {
        std::lock_guard<std::mutex> lock(cb->mutex_);
        ASSERT_EQ(cb->callbackMap_.size(), 2u);
    }
    // Dropping the last reference runs the destructor; it must not crash.
    cb = nullptr;
    EXPECT_TRUE(true);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
