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
} // namespace TEST
} // namespace EDM
} // namespace OHOS
