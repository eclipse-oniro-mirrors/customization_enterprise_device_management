/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "watermark_observer_manager.h"

#include "system_ability_definition.h"

namespace OHOS {
namespace EDM {
WatermarkObserverManager* WatermarkObserverManager::instance_;
std::once_flag WatermarkObserverManager::flag_;

WatermarkObserverManager* WatermarkObserverManager::GetInstance()
{
    EDMLOGI("WatermarkObserverManager::GetInstance");
    std::call_once(flag_, []() {
        if (instance_ == nullptr) {
            instance_ = new (std::nothrow) WatermarkObserverManager();
        }
    });
    IWatermarkObserverManager::observerInstance_ = instance_;
    return instance_;
}

bool WatermarkObserverManager::SubscribeAppStateObserver()
{
    EDMLOGI("WatermarkObserverManager SubscribeAppStateObserver start");
    if (observer_) {
        EDMLOGD("WatermarkObserverManager has subscribed");
        return true;
    }
    observer_ = new (std::nothrow) WatermarkApplicationObserver();
    auto appManager = GetAppManager();
    if (!observer_ || !appManager) {
        EDMLOGE("register WatermarkApplicationObserver fail!");
        observer_.clear();
        observer_ = nullptr;
        return false;
    }
    if (appManager->RegisterApplicationStateObserver(observer_) != ERR_OK) {
        EDMLOGE("register WatermarkApplicationObserver fail!");
        observer_.clear();
        observer_ = nullptr;
        return false;
    }
    return true;
}

bool WatermarkObserverManager::UnSubscribeAppStateObserver()
{
    EDMLOGI("WatermarkObserverManager UnSubscribeAppStateObserver start");
    if (!observer_) {
        EDMLOGD("WatermarkObserverManager has unsubscribed");
        return true;
    }
    auto appManager = GetAppManager();
    if (!appManager) {
        EDMLOGE("appManager null");
        return false;
    }
    if (appManager->UnregisterApplicationStateObserver(observer_) != ERR_OK) {
        EDMLOGE("Unregister WatermarkApplicationObserver fail!");
        return false;
    }
    observer_.clear();
    observer_ = nullptr;
    return true;
}

sptr<AppExecFwk::IAppMgr> WatermarkObserverManager::GetAppManager()
{
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(APP_MGR_SERVICE_ID);
    return iface_cast<AppExecFwk::IAppMgr>(remoteObject);
}
} // namespace EDM
} // namespace OHOS