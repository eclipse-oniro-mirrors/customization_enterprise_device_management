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

#ifndef INTERFACES_INNER_API_INCLUDE_IEDM_TIMER_MANAGER_H
#define INTERFACES_INNER_API_INCLUDE_IEDM_TIMER_MANAGER_H

#include <cstdint>
#include <functional>

namespace OHOS {
namespace EDM {
enum class EdmTimerTask {
    INSTALLED_BUNDLE_TIMER = 0,
};

class IEdmTimerManager {
public:
    virtual ~IEdmTimerManager() = default;

    static IEdmTimerManager *GetInstance();

    virtual bool SetTimer(EdmTimerTask timerTask, uint64_t delayMs,
        const std::function<void()> &callback);
    virtual void CancelTimer(EdmTimerTask timerTask);
    virtual bool IsTimerRunning(EdmTimerTask timerTask);

    static IEdmTimerManager* edmTimerManagerInstance_;
};
} // namespace EDM
} // namespace OHOS
#endif // INTERFACES_INNER_API_INCLUDE_IEDM_TIMER_MANAGER_H
