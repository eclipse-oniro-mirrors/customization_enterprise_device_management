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

#include "delay_unload_manager.h"

#include <functional>
#include <iservice_registry.h>

#include "admin_manager.h"
#include "edm_log.h"
#include "parameters.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace EDM {
namespace {
constexpr int64_t DELAY_UNLOAD_TIMEOUT_MS = 30000;
const std::string PARAM_EDM_ENABLE = "persist.edm.edm_enable";
const std::string DELAY_UNLOAD_THREAD_NAME = "edmDelayUnload";
const std::string DELAY_UNLOAD_TASK_NAME = "DelayUnloadTask";
} // namespace

void DelayUnloadManager::TryStartDelayUnload()
{
    EDMLOGI("DelayUnloadManager::TryStartDelayUnload");
    if (AdminManager::GetInstance()->IsAdminExist()) {
        EDMLOGI("DelayUnloadManager admin exist, no need to delay unload");
        return;
    }
    auto handler = GetEventHandler();
    if (handler == nullptr) { // LCOV_EXCL_BR_LINE
        EDMLOGE("DelayUnloadManager get event handler failed");
        return;
    }
    handler->RemoveTask(DELAY_UNLOAD_TASK_NAME);
    bool ret = handler->PostTask(std::bind(&DelayUnloadManager::OnDelayUnloadTimeout,
        DelayUnloadManager::GetInstance()), DELAY_UNLOAD_TASK_NAME, DELAY_UNLOAD_TIMEOUT_MS);
    EDMLOGI("DelayUnloadManager post delay unload task ret %{public}d", ret);
    pendingUnload_.store(ret);
}

void DelayUnloadManager::CancelDelayUnload()
{
    EDMLOGI("DelayUnloadManager::CancelDelayUnload");
    auto handler = GetEventHandler();
    if (handler == nullptr) { // LCOV_EXCL_BR_LINE
        return;
    }
    handler->RemoveTask(DELAY_UNLOAD_TASK_NAME);
    pendingUnload_.store(false);
}

void DelayUnloadManager::OnDelayUnloadTimeout()
{
    EDMLOGI("DelayUnloadManager::OnDelayUnloadTimeout");
    pendingUnload_.store(false);
    if (AdminManager::GetInstance()->IsAdminExist()) {
        EDMLOGI("DelayUnloadManager admin exist, cancel unload");
        return;
    }
    std::string edmParaValue = system::GetParameter(PARAM_EDM_ENABLE, "false");
    if (edmParaValue == "true") {
        EDMLOGI("DelayUnloadManager edm is enabled, cancel unload");
        return;
    }
    UnloadEdmSa();
}

std::shared_ptr<AppExecFwk::EventHandler> DelayUnloadManager::GetEventHandler()
{
    std::lock_guard<std::mutex> lock(handlerMutex_);
    if (eventHandler_ == nullptr) {
        auto runner = AppExecFwk::EventRunner::Create(DELAY_UNLOAD_THREAD_NAME);
        if (runner == nullptr) { // LCOV_EXCL_BR_LINE
            EDMLOGE("DelayUnloadManager create event runner failed");
            return nullptr;
        }
        eventHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
        EDMLOGI("DelayUnloadManager event handler created");
    }
    return eventHandler_;
}

void DelayUnloadManager::UnloadEdmSa()
{
    EDMLOGI("DelayUnloadManager::UnloadEdmSa");
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) { // LCOV_EXCL_BR_LINE
        EDMLOGE("DelayUnloadManager get system ability manager failed");
        return;
    }
    int32_t ret = samgr->UnloadSystemAbility(ENTERPRISE_DEVICE_MANAGER_SA_ID);
    if (ret != ERR_OK) { // LCOV_EXCL_BR_LINE
        EDMLOGE("DelayUnloadManager unload system ability failed, ret = %{public}d", ret);
        return;
    }
    EDMLOGI("DelayUnloadManager unload system ability success");
}

bool DelayUnloadManager::IsPending() const
{
    return pendingUnload_.load();
}
} // namespace EDM
} // namespace OHOS
