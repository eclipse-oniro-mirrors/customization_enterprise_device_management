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

#ifndef SERVICES_EDM_INCLUDE_EDM_TIMER_MANAGER_H
#define SERVICES_EDM_INCLUDE_EDM_TIMER_MANAGER_H

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>

#include "iedm_timer_manager.h"
#include "time_service_client.h"

namespace OHOS {
namespace EDM {
class EdmTimerInfo;
struct TimerTask {
    uint64_t timerId;
    std::shared_ptr<EdmTimerInfo> timerInfo;
};

class EdmTimerManager : public IEdmTimerManager {
public:
    static std::shared_ptr<EdmTimerManager> GetInstance();

    bool SetTimer(EdmTimerTask timerTask, uint64_t delayMs,
        const std::function<void()> &callback) override;
    void CancelTimer(EdmTimerTask timerTask) override;
    bool IsTimerRunning(EdmTimerTask timerTask) override;
    ~EdmTimerManager() override;

private:
    EdmTimerManager();
    uint64_t GetSystemBootTime();

    static std::once_flag flag_;
    static std::shared_ptr<EdmTimerManager> instance_;
    std::map<EdmTimerTask, TimerTask> timerTaskMap_;
    std::mutex mutex_;
};
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_INCLUDE_EDM_TIMER_MANAGER_H
