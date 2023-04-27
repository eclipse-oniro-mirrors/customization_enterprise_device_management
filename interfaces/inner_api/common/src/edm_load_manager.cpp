/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "edm_load_manager.h"

#include <system_ability_definition.h>

#include "edm_load_callback.h"
#include "edm_log.h"
#include "edm_sys_manager.h"
#include "iremote_broker.h"
#include "iremote_object.h"
#include "iservice_registry.h"

namespace OHOS {
namespace EDM {
static constexpr int32_t EDM_LOADSA_TIMEOUT_MS = 1000;

EdmLoadManager& EdmLoadManager::GetInstance()
{
    static auto instance = new EdmLoadManager();
    return *instance;
}

sptr<IRemoteObject> EdmLoadManager::LoadAndGetEdmService()
{
    if (SUCCEEDED(LoadEdmSa())) {
        return EdmSysManager::GetRemoteObjectOfSystemAbility(ENTERPRISE_DEVICE_MANAGER_SA_ID);
    }
    return nullptr;
}

ErrCode EdmLoadManager::LoadEdmSa()
{
    EDMLOGI("%{public}s enter, systemAbilityId = [%{public}d] loading", __func__, ENTERPRISE_DEVICE_MANAGER_SA_ID);
    InitLoadState();
    sptr<ISystemAbilityManager> samgr =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        EDMLOGE("%{public}s: get system ability manager failed!", __func__);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }

    auto edmLoadCallback = sptr<EdmLoadCallback>(new EdmLoadCallback());
    int32_t ret = samgr->LoadSystemAbility(ENTERPRISE_DEVICE_MANAGER_SA_ID, edmLoadCallback);
    if (ret != ERR_OK) {
        EDMLOGE("%{public}s: Failed to load system ability, SA Id = [%{public}d], ret = [%{public}d].",
            __func__, ENTERPRISE_DEVICE_MANAGER_SA_ID, ret);
        return ERR_EDM_SA_LOAD_FAILED;
    }
    return WaitLoadStateChange();
}

void EdmLoadManager::InitLoadState()
{
    std::unique_lock<std::mutex> lock(locatorMutex_);
    state_ = false;
}

ErrCode EdmLoadManager::WaitLoadStateChange()
{
    std::unique_lock<std::mutex> lock(locatorMutex_);
    auto wait = locatorCon_.wait_for(lock, std::chrono::milliseconds(EDM_LOADSA_TIMEOUT_MS), [this] {
        return state_;
    });
    if (!wait) {
        EDMLOGE("locator sa edm start time out.");
        return ERR_EDM_SA_LOAD_FAILED;
    }
    EDMLOGI("sa edm load success.");
    return ERR_OK;
}

ErrCode EdmLoadManager::UnloadEdmSa()
{
    EDMLOGI("%{public}s enter, systemAbilityId = [%{public}d] unloading", __func__, ENTERPRISE_DEVICE_MANAGER_SA_ID);
    sptr<ISystemAbilityManager> samgr =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        EDMLOGE("%{public}s: get system ability manager failed!", __func__);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int32_t ret = samgr->UnloadSystemAbility(ENTERPRISE_DEVICE_MANAGER_SA_ID);
    if (ret != ERR_OK) {
        EDMLOGE("%{public}s: Failed to unload system ability, SA Id = [%{public}d], ret = [%{public}d].",
            __func__, ENTERPRISE_DEVICE_MANAGER_SA_ID, ret);
        return ERR_EDM_SA_LOAD_FAILED;
    }
    return ERR_OK;
}

void EdmLoadManager::LoadSystemAbilitySuccess()
{
    std::unique_lock<std::mutex> lock(locatorMutex_);
    state_ = true;
    locatorCon_.notify_one();
}

void EdmLoadManager::LoadSystemAbilityFail()
{
    std::unique_lock<std::mutex> lock(locatorMutex_);
    state_ = false;
    locatorCon_.notify_one();
}
}; // namespace EDM
}; // namespace OHOS