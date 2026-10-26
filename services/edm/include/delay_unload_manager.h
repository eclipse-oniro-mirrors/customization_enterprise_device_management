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

#ifndef SERVICES_EDM_INCLUDE_DELAY_UNLOAD_MANAGER_H
#define SERVICES_EDM_INCLUDE_DELAY_UNLOAD_MANAGER_H

#include <atomic>
#include <memory>
#include <mutex>

#include "event_handler.h"
#include "event_runner.h"
#include "singleton.h"

namespace OHOS {
namespace EDM {
class DelayUnloadManager : public DelayedSingleton<DelayUnloadManager> {
public:
    DelayUnloadManager() = default;
    ~DelayUnloadManager() = default;

    void TryStartDelayUnload();
    void CancelDelayUnload();
    void OnDelayUnloadTimeout();
    bool IsPending() const;

private:
    std::shared_ptr<AppExecFwk::EventHandler> GetEventHandler();
    void UnloadEdmSa();

    std::mutex handlerMutex_;
    std::shared_ptr<AppExecFwk::EventHandler> eventHandler_;
    std::atomic<bool> pendingUnload_{false};
};
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_INCLUDE_DELAY_UNLOAD_MANAGER_H
