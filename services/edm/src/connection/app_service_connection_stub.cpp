/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#include "app_service_connection_stub.h"

#include "edm_errors.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
AppServiceConnectionStub::AppServiceConnectionStub(int32_t connectionId,
    const sptr<IEdmConnectionCallback> &callback)
    : connectionId_(connectionId), callback_(callback) {}

void AppServiceConnectionStub::OnAbilityConnectDone(const AppExecFwk::ElementName &element,
    const sptr<IRemoteObject> &remoteObject, int32_t resultCode)
{
    EDMLOGI("OnAbilityConnectDone connectionId=%{public}d resultCode=%{public}d", connectionId_, resultCode);
    if (callback_ == nullptr) {
        EDMLOGE("callback is null");
        return;
    }
    if (resultCode == 0) {
        callback_->OnConnect(element, remoteObject);
    } else {
        callback_->OnFailed(MapErrorCode(resultCode));
    }
}

void AppServiceConnectionStub::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element,
    int32_t resultCode)
{
    EDMLOGI("OnAbilityDisconnectDone connectionId=%{public}d resultCode=%{public}d", connectionId_, resultCode);
    if (callback_ == nullptr) {
        EDMLOGE("callback is null");
        return;
    }
    callback_->OnDisconnect(element);
}

int32_t AppServiceConnectionStub::MapErrorCode(int32_t abilityManagerCode)
{
    const int32_t ERR_ABILITY_NOT_EXIST = 16000001;
    const int32_t ERR_ABILITY_TYPE_INVALID = 16000002;
    const int32_t ERR_ABILITY_NOT_VISIBLE = 16000004;
    if (abilityManagerCode == ERR_ABILITY_NOT_EXIST) {
        return EdmReturnErrCode::ABILITY_NOT_EXIST;
    }
    if (abilityManagerCode == ERR_ABILITY_TYPE_INVALID) {
        return EdmReturnErrCode::CONNECT_APP_SERVICE_EXTENSION_INVALID_TYPE;
    }
    if (abilityManagerCode == ERR_ABILITY_NOT_VISIBLE) {
        return EdmReturnErrCode::CONNECT_APP_SERVICE_EXTENSION_NOT_VISIBLE;
    }
    return EdmReturnErrCode::CONNECT_APP_SERVICE_EXTENSION_FAILED;
}
} // namespace EDM
} // namespace OHOS
