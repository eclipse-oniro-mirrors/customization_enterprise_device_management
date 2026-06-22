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

#ifndef SERVICES_EDM_INCLUDE_EDM_TIMER_INFO_H
#define SERVICES_EDM_INCLUDE_EDM_TIMER_INFO_H

#include <functional>

#include "itimer_info.h"

namespace OHOS {
namespace EDM {
class EdmTimerInfo : public MiscServices::ITimerInfo {
public:
    EdmTimerInfo(const std::function<void()> &callback, const std::function<void()> &cleanupCallback)
        : callback_(callback), cleanupCallback_(cleanupCallback) {};
    virtual ~EdmTimerInfo() {};

    void OnTrigger() override;
    void SetType(const int32_t &type) override;
    void SetRepeat(bool repeat) override;
    void SetInterval(const uint64_t &interval) override;
    void SetWantAgent(std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> wantAgent) override;

private:
    std::function<void()> callback_ = nullptr;
    std::function<void()> cleanupCallback_ = nullptr;
};
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_INCLUDE_EDM_TIMER_INFO_H
