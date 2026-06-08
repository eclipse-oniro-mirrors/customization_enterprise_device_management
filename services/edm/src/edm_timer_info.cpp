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

#include "edm_timer_info.h"

#include "edm_log.h"

namespace OHOS {
namespace EDM {
void EdmTimerInfo::SetType(const int32_t &type)
{
    this->type = type;
}

void EdmTimerInfo::SetRepeat(bool repeat)
{
    this->repeat = repeat;
}

void EdmTimerInfo::SetInterval(const uint64_t &interval)
{
    this->interval = interval;
}

void EdmTimerInfo::SetWantAgent(std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> wantAgent)
{
    this->wantAgent = wantAgent;
}

void EdmTimerInfo::OnTrigger()
{
    EDMLOGI("EdmTimerInfo::OnTrigger");
    if (callback_ != nullptr) {
        callback_();
    }
    if (cleanupCallback_ != nullptr) {
        cleanupCallback_();
    }
}
} // namespace EDM
} // namespace OHOS
