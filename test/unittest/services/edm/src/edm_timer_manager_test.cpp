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
#include <chrono>
#include <thread>

#define private public
#define protected public
#include "edm_timer_info.h"
#include "edm_timer_manager.h"
#undef protected
#undef private
#include "iedm_timer_manager.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {

class EdmTimerManagerTest : public testing::Test {
public:
    void SetUp() override
    {
        instance_ = EdmTimerManager::GetInstance();
        CleanupAllTimers();
    }

    void TearDown() override
    {
        CleanupAllTimers();
    }

protected:
    std::shared_ptr<EdmTimerManager> instance_ = nullptr;

    void CleanupAllTimers()
    {
        std::lock_guard<std::mutex> lock(instance_->mutex_);
        auto timer = MiscServices::TimeServiceClient::GetInstance();
        for (auto &[timerTask, task] : instance_->timerTaskMap_) {
            if (timer != nullptr && task.timerId != 0) {
                timer->DestroyTimer(task.timerId);
            }
        }
        instance_->timerTaskMap_.clear();
    }
};

HWTEST_F(EdmTimerManagerTest, GetInstance_ReturnNotNull_Success, TestSize.Level1)
{
    auto inst = EdmTimerManager::GetInstance();
    ASSERT_TRUE(inst != nullptr);
}

HWTEST_F(EdmTimerManagerTest, GetInstance_MultipleCalls_SameInstance, TestSize.Level1)
{
    auto inst1 = EdmTimerManager::GetInstance();
    auto inst2 = EdmTimerManager::GetInstance();
    EXPECT_EQ(inst1.get(), inst2.get());
}

HWTEST_F(EdmTimerManagerTest, GetInstance_SetBasePointer_Success, TestSize.Level1)
{
    auto inst = EdmTimerManager::GetInstance();
    EXPECT_EQ(IEdmTimerManager::edmTimerManagerInstance_, inst.get());
}

HWTEST_F(EdmTimerManagerTest, SetTimer_NewTaskId_ReturnTrue, TestSize.Level1)
{
    std::atomic<bool> callbackExecuted{false};
    bool ret = instance_->SetTimer(EdmTimerTask::INSTALLED_BUNDLE_TIMER, 5000, [&callbackExecuted]() {
        callbackExecuted.store(true);
    });
    EXPECT_TRUE(ret);
    EXPECT_TRUE(instance_->IsTimerRunning(EdmTimerTask::INSTALLED_BUNDLE_TIMER));
}

HWTEST_F(EdmTimerManagerTest, SetTimer_DuplicateRunningTaskId_ReturnTrue, TestSize.Level1)
{
    std::atomic<bool> callbackExecuted{false};
    bool ret1 = instance_->SetTimer(EdmTimerTask::INSTALLED_BUNDLE_TIMER, 5000, [&callbackExecuted]() {
        callbackExecuted.store(true);
    });
    EXPECT_TRUE(ret1);

    bool ret2 = instance_->SetTimer(EdmTimerTask::INSTALLED_BUNDLE_TIMER, 5000, [&callbackExecuted]() {
        callbackExecuted.store(true);
    });
    EXPECT_TRUE(ret2);
}

HWTEST_F(EdmTimerManagerTest, CancelTimer_RunningTimer_IsTimerRunningFalse, TestSize.Level1)
{
    std::atomic<bool> callbackExecuted{false};
    bool ret = instance_->SetTimer(EdmTimerTask::INSTALLED_BUNDLE_TIMER, 5000, [&callbackExecuted]() {
        callbackExecuted.store(true);
    });
    EXPECT_TRUE(ret);
    EXPECT_TRUE(instance_->IsTimerRunning(EdmTimerTask::INSTALLED_BUNDLE_TIMER));

    instance_->CancelTimer(EdmTimerTask::INSTALLED_BUNDLE_TIMER);
    EXPECT_FALSE(instance_->IsTimerRunning(EdmTimerTask::INSTALLED_BUNDLE_TIMER));
}

HWTEST_F(EdmTimerManagerTest, CancelTimer_NonExistentTaskId_NoCrash, TestSize.Level1)
{
    instance_->CancelTimer(EdmTimerTask::INSTALLED_BUNDLE_TIMER);
    EXPECT_TRUE(true);
}

HWTEST_F(EdmTimerManagerTest, IsTimerRunning_TimerRunning_ReturnTrue, TestSize.Level1)
{
    std::atomic<bool> callbackExecuted{false};
    instance_->SetTimer(EdmTimerTask::INSTALLED_BUNDLE_TIMER, 5000, [&callbackExecuted]() {
        callbackExecuted.store(true);
    });
    EXPECT_TRUE(instance_->IsTimerRunning(EdmTimerTask::INSTALLED_BUNDLE_TIMER));
}

HWTEST_F(EdmTimerManagerTest, IsTimerRunning_NonExistentTaskId_ReturnFalse, TestSize.Level1)
{
    EXPECT_FALSE(instance_->IsTimerRunning(EdmTimerTask::INSTALLED_BUNDLE_TIMER));
}

/**
 * @tc.name: EdmTimerManager_SetTimer_TimerInfoTypeSet_CorrectTypeValue
 * @tc.desc: Test SetTimer sets timerInfo type to the correct combined value of REALTIME|WAKEUP|EXACT.
 * @tc.type: FUNC
 */
HWTEST_F(EdmTimerManagerTest, SetTimer_TimerInfoTypeSet_CorrectTypeValue, TestSize.Level1)
{
    std::atomic<bool> callbackExecuted{false};
    bool ret = instance_->SetTimer(EdmTimerTask::INSTALLED_BUNDLE_TIMER, 5000, [&callbackExecuted]() {
        callbackExecuted.store(true);
    });
    EXPECT_TRUE(ret);

    std::lock_guard<std::mutex> lock(instance_->mutex_);
    auto it = instance_->timerTaskMap_.find(EdmTimerTask::INSTALLED_BUNDLE_TIMER);
    ASSERT_TRUE(it != instance_->timerTaskMap_.end());
    auto &timerInfo = it->second.timerInfo;
    ASSERT_TRUE(timerInfo != nullptr);
    int32_t expectedType = static_cast<int32_t>(
        static_cast<uint8_t>(timerInfo->TIMER_TYPE_REALTIME) |
        static_cast<uint8_t>(timerInfo->TIMER_TYPE_WAKEUP) |
        static_cast<uint8_t>(timerInfo->TIMER_TYPE_EXACT));
    EXPECT_EQ(timerInfo->type, expectedType);
    EXPECT_FALSE(timerInfo->repeat);
    EXPECT_EQ(timerInfo->interval, 0);
    EXPECT_TRUE(timerInfo->callback_ != nullptr);
    EXPECT_TRUE(timerInfo->cleanupCallback_ != nullptr);
    EXPECT_NE(it->second.timerId, 0);
}

/**
 * @tc.name: EdmTimerManager_CancelTimer_ThenSetSameTimer_ReturnTrue
 * @tc.desc: Test cancelling a timer then setting the same timer again returns true.
 * @tc.type: FUNC
 */
HWTEST_F(EdmTimerManagerTest, CancelTimer_ThenSetSameTimer_ReturnTrue, TestSize.Level1)
{
    std::atomic<bool> callbackExecuted{false};
    bool ret1 = instance_->SetTimer(EdmTimerTask::INSTALLED_BUNDLE_TIMER, 5000, [&callbackExecuted]() {
        callbackExecuted.store(true);
    });
    EXPECT_TRUE(ret1);
    EXPECT_TRUE(instance_->IsTimerRunning(EdmTimerTask::INSTALLED_BUNDLE_TIMER));

    instance_->CancelTimer(EdmTimerTask::INSTALLED_BUNDLE_TIMER);
    EXPECT_FALSE(instance_->IsTimerRunning(EdmTimerTask::INSTALLED_BUNDLE_TIMER));

    bool ret2 = instance_->SetTimer(EdmTimerTask::INSTALLED_BUNDLE_TIMER, 5000, [&callbackExecuted]() {
        callbackExecuted.store(true);
    });
    EXPECT_TRUE(ret2);
    EXPECT_TRUE(instance_->IsTimerRunning(EdmTimerTask::INSTALLED_BUNDLE_TIMER));
}

/**
 * @tc.name: EdmTimerManager_GetSystemBootTime_ReturnNonZero_TimeServiceAvailable
 * @tc.desc: Test GetSystemBootTime returns a value when TimeServiceClient is available.
 * @tc.type: FUNC
 */
HWTEST_F(EdmTimerManagerTest, GetSystemBootTime_ReturnNonZero_TimeServiceAvailable, TestSize.Level1)
{
    uint64_t bootTime = instance_->GetSystemBootTime();
    EXPECT_TRUE(bootTime > 0);
}

/**
 * @tc.name: EdmTimerManager_SetTimer_TimerTaskMapSizeIncreased_MapSizeOne
 * @tc.desc: Test SetTimer increases timerTaskMap size by one.
 * @tc.type: FUNC
 */
HWTEST_F(EdmTimerManagerTest, SetTimer_TimerTaskMapSizeIncreased_MapSizeOne, TestSize.Level1)
{
    std::atomic<bool> callbackExecuted{false};
    size_t initialSize = instance_->timerTaskMap_.size();
    bool ret = instance_->SetTimer(EdmTimerTask::INSTALLED_BUNDLE_TIMER, 5000, [&callbackExecuted]() {
        callbackExecuted.store(true);
    });
    EXPECT_TRUE(ret);
    EXPECT_EQ(instance_->timerTaskMap_.size(), initialSize + 1);

    instance_->CancelTimer(EdmTimerTask::INSTALLED_BUNDLE_TIMER);
    EXPECT_EQ(instance_->timerTaskMap_.size(), 0);
}

/**
 * @tc.name: EdmTimerManager_SetTimer_CleanupCallbackInvoked_CancelTimerCalled
 * @tc.desc: Test cleanupCallback of EdmTimerInfo calls CancelTimer to remove the timer task.
 * @tc.type: FUNC
 */
HWTEST_F(EdmTimerManagerTest, SetTimer_CleanupCallbackInvoked_CancelTimerCalled, TestSize.Level1)
{
    std::atomic<bool> callbackExecuted{false};
    bool ret = instance_->SetTimer(EdmTimerTask::INSTALLED_BUNDLE_TIMER, 5000, [&callbackExecuted]() {
        callbackExecuted.store(true);
    });
    EXPECT_TRUE(ret);
    EXPECT_TRUE(instance_->IsTimerRunning(EdmTimerTask::INSTALLED_BUNDLE_TIMER));

    // 获取cleanupCallback_（不持有锁，避免死锁）
    std::function<void()> cleanupCallback;
    {
        std::lock_guard<std::mutex> lock(instance_->mutex_);
        auto it = instance_->timerTaskMap_.find(EdmTimerTask::INSTALLED_BUNDLE_TIMER);
        ASSERT_TRUE(it != instance_->timerTaskMap_.end());
        cleanupCallback = it->second.timerInfo->cleanupCallback_;
    }
    ASSERT_TRUE(cleanupCallback != nullptr);

    // 调用cleanupCallback_，验证其会调用CancelTimer
    cleanupCallback();
    EXPECT_FALSE(instance_->IsTimerRunning(EdmTimerTask::INSTALLED_BUNDLE_TIMER));
}

/**
 * @tc.name: EdmTimerManager_SetTimer_CallbackInvoked_CallbackExecuted
 * @tc.desc: Test callback of EdmTimerInfo executes the user-provided callback function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmTimerManagerTest, SetTimer_CallbackInvoked_CallbackExecuted, TestSize.Level1)
{
    std::atomic<bool> callbackExecuted{false};
    bool ret = instance_->SetTimer(EdmTimerTask::INSTALLED_BUNDLE_TIMER, 5000, [&callbackExecuted]() {
        callbackExecuted.store(true);
    });
    EXPECT_TRUE(ret);

    // 获取callback_（不持有锁）
    std::function<void()> mainCallback;
    {
        std::lock_guard<std::mutex> lock(instance_->mutex_);
        auto it = instance_->timerTaskMap_.find(EdmTimerTask::INSTALLED_BUNDLE_TIMER);
        ASSERT_TRUE(it != instance_->timerTaskMap_.end());
        mainCallback = it->second.timerInfo->callback_;
    }
    ASSERT_TRUE(mainCallback != nullptr);

    // 调用callback_，验证其执行了用户回调
    mainCallback();
    EXPECT_TRUE(callbackExecuted.load());
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
