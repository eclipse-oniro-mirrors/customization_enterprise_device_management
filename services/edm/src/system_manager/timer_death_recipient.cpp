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

#include "timer_death_recipient.h"

#include "edm_log.h"
#include "system_timer_manager.h"

namespace OHOS {
namespace EDM {
void TimerDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remoteObject)
{
    EDMLOGI("TimerDeathRecipient::OnRemoteDied");
    auto* manager = SystemTimerManager::GetInstance();
    if (manager != nullptr) {
        manager->OnRemoteDied(remoteObject);
    }
}
} // namespace EDM
} // namespace OHOS
