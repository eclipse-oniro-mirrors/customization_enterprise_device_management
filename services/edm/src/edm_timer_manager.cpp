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

#include "edm_timer_manager.h"

#include "edm_log.h"
#include "edm_timer_info.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<EdmTimerManager> EdmTimerManager::instance_;
std::once_flag EdmTimerManager::flag_;

std::shared_ptr<EdmTimerManager> EdmTimerManager::GetInstance()
{
    std::call_once(flag_, []() {
        if (instance_ == nullptr) {
            instance_.reset(new (std::nothrow) EdmTimerManager());
        }
    });
    IEdmTimerManager::edmTimerManagerInstance_ = instance_.get();
    return instance_;
}

EdmTimerManager::EdmTimerManager() {}

EdmTimerManager::~EdmTimerManager()
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto timer = MiscServices::TimeServiceClient::GetInstance();
    for (auto &[timerTask, task] : timerTaskMap_) {
        if (timer != nullptr && task.timerId != 0) {
            timer->DestroyTimer(task.timerId);
        }
    }
    timerTaskMap_.clear();
}

bool EdmTimerManager::SetTimer(EdmTimerTask timerTask, uint64_t delayMs,
    const std::function<void()> &callback)
{
    EDMLOGI("EdmTimerManager::SetTimer timerTask %{public}d", static_cast<int32_t>(timerTask));
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = timerTaskMap_.find(timerTask);
    if (it != timerTaskMap_.end()) {
        EDMLOGW("EdmTimerManager timer %{public}d already running", static_cast<int32_t>(timerTask));
        return true;
    }
    auto timer = MiscServices::TimeServiceClient::GetInstance();
    if (timer == nullptr) {
        EDMLOGE("EdmTimerManager TimeServiceClient is nullptr");
        return false;
    }
    auto timerInfo = std::make_shared<EdmTimerInfo>(callback, [timerTask]() {
        auto edmTimerManager = IEdmTimerManager::GetInstance();
        if (edmTimerManager != nullptr) {
            edmTimerManager->CancelTimer(timerTask);
        }
    });
    timerInfo->SetType(static_cast<int32_t>(
        static_cast<uint8_t>(timerInfo->TIMER_TYPE_REALTIME) |
        static_cast<uint8_t>(timerInfo->TIMER_TYPE_WAKEUP) |
        static_cast<uint8_t>(timerInfo->TIMER_TYPE_EXACT)));
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(0);
    uint64_t timerId = timer->CreateTimer(timerInfo);
    if (timerId == 0) {
        EDMLOGE("EdmTimerManager CreateTimer failed");
        return false;
    }
    uint64_t triggerTime = GetSystemBootTime() + delayMs;
    bool ret = timer->StartTimer(timerId, triggerTime);
    if (!ret) {
        EDMLOGE("EdmTimerManager StartTimer failed");
        timer->DestroyTimer(timerId);
        return false;
    }
    TimerTask task;
    task.timerId = timerId;
    task.timerInfo = timerInfo;
    timerTaskMap_[timerTask] = task;
    return true;
}

void EdmTimerManager::CancelTimer(EdmTimerTask timerTask)
{
    EDMLOGI("EdmTimerManager::CancelTimer timerTask %{public}d", static_cast<int32_t>(timerTask));
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = timerTaskMap_.find(timerTask);
    if (it == timerTaskMap_.end()) {
        return;
    }
    auto timer = MiscServices::TimeServiceClient::GetInstance();
    if (timer != nullptr && it->second.timerId != 0) {
        timer->DestroyTimer(it->second.timerId);
    }
    timerTaskMap_.erase(it);
}

bool EdmTimerManager::IsTimerRunning(EdmTimerTask timerTask)
{
    std::lock_guard<std::mutex> lock(mutex_);
    return timerTaskMap_.find(timerTask) != timerTaskMap_.end();
}

uint64_t EdmTimerManager::GetSystemBootTime()
{
    int64_t currentBootTime = 0;
    auto client = MiscServices::TimeServiceClient::GetInstance();
    if (client != nullptr) {
        if (client->GetBootTimeMs(currentBootTime) != 0) {
            EDMLOGE("EdmTimerManager::GetSystemBootTime failed to get boot time");
            return 0;
        }
    }
    return static_cast<uint64_t>(currentBootTime);
}
} // namespace EDM
} // namespace OHOS