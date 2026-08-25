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

#ifndef SERVICES_EDM_INCLUDE_SYSTEM_MANAGER_EDM_TIMER_INFO_SA_H
#define SERVICES_EDM_INCLUDE_SYSTEM_MANAGER_EDM_TIMER_INFO_SA_H

#include <cstdint>
#include <functional>

#include "itimer_info.h"

namespace OHOS {
namespace EDM {
class EdmTimerInfoSa : public MiscServices::ITimerInfo {
public:
    explicit EdmTimerInfoSa(uint64_t timerId) : timerId_(timerId) {}
    ~EdmTimerInfoSa() override = default;

    void OnTrigger() override;
    void SetType(const int32_t &type) override { this->type = type; }
    void SetRepeat(bool repeat) override { this->repeat = repeat; }
    void SetInterval(const uint64_t &interval) override { this->interval = interval; }
    void SetWantAgent(std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> wantAgent) override
    {
        this->wantAgent = wantAgent;
    }

    void SetTimerId(uint64_t timerId) { timerId_ = timerId; }
    void SetTriggerCallback(const std::function<void(uint64_t)> &callback)
    {
        triggerCallback_ = callback;
    }

private:
    uint64_t timerId_ = 0;
    std::function<void(uint64_t)> triggerCallback_ = nullptr;
};
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_INCLUDE_SYSTEM_MANAGER_EDM_TIMER_INFO_SA_H
