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

#ifndef SERVICES_EDM_INCLUDE_CONNECTION_APP_SERVICE_CONNECTION_STUB_H
#define SERVICES_EDM_INCLUDE_CONNECTION_APP_SERVICE_CONNECTION_STUB_H

#include "ability_connect_callback_stub.h"
#include "element_name.h"
#include "i_edm_connection_callback.h"
#include "iremote_object.h"

namespace OHOS {
namespace EDM {
class AppServiceConnectionStub : public AAFwk::AbilityConnectionStub {
public:
    AppServiceConnectionStub(int32_t connectionId, const sptr<IEdmConnectionCallback> &callback);
    ~AppServiceConnectionStub() override = default;

    void OnAbilityConnectDone(const AppExecFwk::ElementName &element,
        const sptr<IRemoteObject> &remoteObject, int32_t resultCode) override;
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int32_t resultCode) override;

private:
    int32_t MapErrorCode(int32_t abilityManagerCode);
    int32_t connectionId_;
    sptr<IEdmConnectionCallback> callback_;
};
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_INCLUDE_CONNECTION_APP_SERVICE_CONNECTION_STUB_H
