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

#include <chrono>
#include <condition_variable>
#include <gtest/gtest.h>
#include <memory>
#include <mutex>
#include <thread>

#include "delay_cancel_timer.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {

class DelayCancelTimerTest : public testing::Test {
protected:
    void SetUp() override
    {
        timer_ = std::make_unique<DelayCancelTimer>();
    }

    void TearDown() override
    {
        timer_.reset();
    }

    std::unique_ptr<DelayCancelTimer> timer_;
};

/**
 * @tc.name: Test_StartTaskExecutesAfterDelay
 * @tc.desc: Test Start executes the task after the specified delay.
 * @tc.type: FUNC
 */
HWTEST_F(DelayCancelTimerTest, Start_TaskExecutesAfterDelay_Success, TestSize.Level1)
{
    std::atomic<bool> executed{false};
    std::mutex mtx;
    std::condition_variable cv;

    timer_->Start([&]() {
        std::lock_guard<std::mutex> lock(mtx);
        executed = true;
        cv.notify_one();
    }, std::chrono::seconds(1));

    std::unique_lock<std::mutex> lock(mtx);
    cv.wait_for(lock, std::chrono::seconds(3), [&]() { return executed.load(); });

    EXPECT_TRUE(executed);
    EXPECT_FALSE(timer_->IsRunning());
}

/**
 * @tc.name: Test_StartCancelBeforeExpiry
 * @tc.desc: Test Cancel prevents the task from executing when called before expiry.
 * @tc.type: FUNC
 */
HWTEST_F(DelayCancelTimerTest, Start_CancelBeforeExpiry_TaskNotExecuted, TestSize.Level1)
{
    std::atomic<bool> executed{false};

    timer_->Start([&]() { executed = true; }, std::chrono::seconds(10));
    EXPECT_TRUE(timer_->IsRunning());

    timer_->Cancel();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    EXPECT_FALSE(executed);
    EXPECT_FALSE(timer_->IsRunning());
}

/**
 * @tc.name: Test_CancelWhenNotStarted
 * @tc.desc: Test Cancel on an idle timer has no effect and does not crash.
 * @tc.type: FUNC
 */
HWTEST_F(DelayCancelTimerTest, Cancel_WhenNotStarted_NoEffect, TestSize.Level1)
{
    EXPECT_FALSE(timer_->IsRunning());
    timer_->Cancel();
    EXPECT_FALSE(timer_->IsRunning());
}

/**
 * @tc.name: Test_StartReplacesPreviousTimer
 * @tc.desc: Test Start replaces a previous timer; the old task is not executed.
 * @tc.type: FUNC
 */
HWTEST_F(DelayCancelTimerTest, Start_ReplacesPreviousTimer_PreviousTaskNotExecuted, TestSize.Level1)
{
    std::atomic<int> counter{0};
    std::mutex mtx;
    std::condition_variable cv;

    timer_->Start([&]() { counter++; }, std::chrono::seconds(10));
    EXPECT_TRUE(timer_->IsRunning());

    timer_->Start([&]() {
        std::lock_guard<std::mutex> lock(mtx);
        counter += 100;
        cv.notify_one();
    }, std::chrono::seconds(1));

    std::unique_lock<std::mutex> lock(mtx);
    cv.wait_for(lock, std::chrono::seconds(3), [&]() { return counter.load() >= 100; });

    EXPECT_EQ(counter.load(), 100);
    EXPECT_FALSE(timer_->IsRunning());
}

/**
 * @tc.name: Test_IsRunningReturnsTrueWhenActive
 * @tc.desc: Test IsRunning returns true while the timer is active, false after cancel.
 * @tc.type: FUNC
 */
HWTEST_F(DelayCancelTimerTest, IsRunning_ReturnsTrueWhenActive, TestSize.Level1)
{
    timer_->Start([&]() {}, std::chrono::seconds(10));
    EXPECT_TRUE(timer_->IsRunning());
    timer_->Cancel();
    EXPECT_FALSE(timer_->IsRunning());
}

/**
 * @tc.name: Test_DestructorCancelsActiveTimer
 * @tc.desc: Test the destructor cancels an active timer and the task is not executed.
 * @tc.type: FUNC
 */
HWTEST_F(DelayCancelTimerTest, Destructor_CancelsActiveTimer, TestSize.Level1)
{
    std::atomic<bool> executed{false};
    {
        DelayCancelTimer localTimer;
        localTimer.Start([&]() { executed = true; }, std::chrono::seconds(10));
        EXPECT_TRUE(localTimer.IsRunning());
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_FALSE(executed);
}

/**
 * @tc.name: Test_ConcurrentStartAndCancelNoCrash
 * @tc.desc: Test concurrent Start/Cancel from different threads does not crash.
 * @tc.type: FUNC
 */
HWTEST_F(DelayCancelTimerTest, StartAndCancel_Concurrent_NoCrash, TestSize.Level1)
{
    auto timer = std::make_shared<DelayCancelTimer>();
    std::atomic<bool> stop{false};

    std::thread starter([timer, &stop]() {
        int count = 0;
        while (!stop.load()) {
            timer->Start([]() {}, std::chrono::seconds(5));
            count++;
            if (count > 10) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    });

    std::thread canceller([timer, &stop]() {
        for (int i = 0; i < 10; i++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(15));
            timer->Cancel();
        }
        stop = true;
    });

    starter.join();
    canceller.join();
    timer->Cancel();
}

/**
 * @tc.name: Test_ConcurrentCancelNoDoubleJoin
 * @tc.desc: Test concurrent Cancel from multiple threads does not cause double-join UB.
 * @tc.type: FUNC
 */
HWTEST_F(DelayCancelTimerTest, ConcurrentCancel_NoDoubleJoin, TestSize.Level1)
{
    for (int iter = 0; iter < 20; iter++) {
        auto timer = std::make_shared<DelayCancelTimer>();
        timer->Start([]() {}, std::chrono::seconds(5));
        std::thread t1([timer]() { timer->Cancel(); });
        std::thread t2([timer]() { timer->Cancel(); });
        t1.join();
        t2.join();
        EXPECT_FALSE(timer->IsRunning());
    }
}

/**
 * @tc.name: Test_ConcurrentStartAndCancelHighContention
 * @tc.desc: Test high-contention concurrent Start/Cancel preserves correct state.
 * @tc.type: FUNC
 */
HWTEST_F(DelayCancelTimerTest, ConcurrentStartAndCancel_HighContention, TestSize.Level1)
{
    auto timer = std::make_shared<DelayCancelTimer>();
    std::atomic<int> startCount{0};
    std::atomic<int> cancelCount{0};
    std::atomic<bool> stop{false};

    std::thread starter([&stop, &timer, &startCount]() {
        while (!stop.load()) {
            timer->Start([]() {}, std::chrono::seconds(5));
            startCount++;
        }
    });

    std::thread canceller([&stop, &timer, &cancelCount]() {
        for (int i = 0; i < 50; i++) {
            timer->Cancel();
            cancelCount++;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        stop = true;
    });

    starter.join();
    canceller.join();
    timer->Cancel();
    EXPECT_FALSE(timer->IsRunning());
    EXPECT_EQ(cancelCount.load(), 50);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
