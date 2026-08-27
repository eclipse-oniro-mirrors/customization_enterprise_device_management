/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
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

#include "delay_cancel_timer.h"

namespace OHOS {
namespace EDM {
DelayCancelTimer::~DelayCancelTimer()
{
    Cancel();
}

void DelayCancelTimer::Start(std::function<void()> task, std::chrono::seconds delay)
{
    std::unique_lock<std::mutex> threadLock(threadMutex_);
    {
        std::unique_lock<std::mutex> lock(mutex_);
        active_ = false;
    }
    cv_.notify_one();
    if (timerThread_.joinable()) {
        timerThread_.join();
    }
    {
        std::unique_lock<std::mutex> lock(mutex_);
        active_ = true;
    }
    timerThread_ = std::thread([this, task = std::move(task), delay]() {
        std::unique_lock<std::mutex> lock(mutex_);
        if (cv_.wait_for(lock, delay, [this]() { return !active_.load(); })) {
            return;
        }
        lock.unlock();
        if (active_.load()) {
            task();
            active_ = false;
        }
    });
}

void DelayCancelTimer::Cancel()
{
    std::unique_lock<std::mutex> threadLock(threadMutex_);
    {
        std::unique_lock<std::mutex> lock(mutex_);
        active_ = false;
    }
    cv_.notify_one();
    if (timerThread_.joinable()) {
        timerThread_.join();
    }
}

bool DelayCancelTimer::IsRunning() const
{
    return active_.load();
}
} // namespace EDM
} // namespace OHOS
