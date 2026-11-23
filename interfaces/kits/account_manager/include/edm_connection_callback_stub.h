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

#ifndef INTERFACES_KITS_ACCOUNT_MANAGER_INCLUDE_EDM_CONNECTION_CALLBACK_STUB_H
#define INTERFACES_KITS_ACCOUNT_MANAGER_INCLUDE_EDM_CONNECTION_CALLBACK_STUB_H

#include <atomic>

#include "i_edm_connection_callback.h"
#include "iremote_object.h"
#include "iremote_stub.h"
#include "element_name.h"
#include "napi/native_api.h"
#include "napi/native_common.h"

namespace OHOS {
namespace EDM {
class EdmConnectionCallbackStub : public IRemoteStub<IEdmConnectionCallback> {
public:
    EdmConnectionCallbackStub(napi_env env, napi_value callback);
    ~EdmConnectionCallbackStub() override;

    void OnConnect(const AppExecFwk::ElementName &element,
        const sptr<IRemoteObject> &remote) override;
    void OnDisconnect(const AppExecFwk::ElementName &element) override;
    void OnFailed(int32_t code) override;

    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option) override;

private:
    struct ConnectData {
        std::string bundleName;
        std::string abilityName;
        sptr<IRemoteObject> remote;
    };
    struct DisconnectData {
        std::string bundleName;
        std::string abilityName;
    };

    static void TsfnOnConnectCallJs(napi_env env, napi_value jsCb, void *context, void *data);
    static void TsfnOnDisconnectCallJs(napi_env env, napi_value jsCb, void *context, void *data);
    static void TsfnOnFailedCallJs(napi_env env, napi_value jsCb, void *context, void *data);
    static napi_value WrapElementName(napi_env env, const std::string &bundleName,
        const std::string &abilityName);

    napi_threadsafe_function tsfnOnConnect_ {nullptr};
    napi_threadsafe_function tsfnOnDisconnect_ {nullptr};
    napi_threadsafe_function tsfnOnFailed_ {nullptr};
    napi_ref callbackRef_ {nullptr};
    std::atomic<bool> released_ {false};
};
} // namespace EDM
} // namespace OHOS
#endif // INTERFACES_KITS_ACCOUNT_MANAGER_INCLUDE_EDM_CONNECTION_CALLBACK_STUB_H
