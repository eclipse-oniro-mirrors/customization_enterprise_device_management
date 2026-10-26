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

#include "user_auth_event_adapter.h"

#include "edm_log.h"

#ifdef USERIAM_EDM_ENABLE
#include "edm_user_auth_listener.h"
#include "pinauth_register.h"
#endif

namespace OHOS {
namespace EDM {
UserAuthEventAdapter::UserAuthEventAdapter(EventSubscriptionManager &manager) : manager_(manager) {}

UserAuthEventAdapter::~UserAuthEventAdapter()
{
    if (isListenerRegistered_) {
        UnregisterIamListener();
    }
}

bool UserAuthEventAdapter::SubscribeEvent()
{
    return RegisterIamListener();
}

bool UserAuthEventAdapter::UnsubscribeEvent()
{
    return UnregisterIamListener();
}

bool UserAuthEventAdapter::RegisterIamListener()
{
#ifdef USERIAM_EDM_ENABLE
    if (listener_ == nullptr) {
        listener_ = std::make_shared<EdmUserAuthListener>(manager_);
    }
    int32_t ret = DoRegisterIamListener();
    if (ret != ERR_OK) {
        EDMLOGE("UserAuthEventAdapter::RegisterIamListener failed ret=%{public}d", ret);
        return false;
    }
    isListenerRegistered_ = true;
    EDMLOGI("UserAuthEventAdapter::RegisterIamListener success");
    return true;
#else
    EDMLOGW("UserAuthEventAdapter::RegisterIamListener useriam part not enabled");
    return false;
#endif
}

bool UserAuthEventAdapter::UnregisterIamListener()
{
#ifdef USERIAM_EDM_ENABLE
    if (listener_ == nullptr || !isListenerRegistered_) {
        isListenerRegistered_ = false;
        return true;
    }
    int32_t ret = DoUnregisterIamListener();
    if (ret != ERR_OK) {
        EDMLOGE("UserAuthEventAdapter::UnregisterIamListener failed ret=%{public}d", ret);
    }
    isListenerRegistered_ = false;
    return true;
#else
    isListenerRegistered_ = false;
    return true;
#endif
}

int32_t UserAuthEventAdapter::DoRegisterIamListener()
{
#ifdef USERIAM_EDM_ENABLE
    return UserIam::PinAuth::PinAuthRegister::GetInstance().RegisterAuthFailureCountListener(listener_);
#else
    return -1;
#endif
}

int32_t UserAuthEventAdapter::DoUnregisterIamListener()
{
#ifdef USERIAM_EDM_ENABLE
    return UserIam::PinAuth::PinAuthRegister::GetInstance().UnregisterAuthFailureCountListener(listener_);
#else
    return -1;
#endif
}
} // namespace EDM
} // namespace OHOS
