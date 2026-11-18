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

#include "edm_connection_callback_stub.h"

#include "edm_log.h"
#include "edm_errors.h"
#include "napi_remote_object.h"

namespace OHOS {
namespace EDM {
constexpr size_t JS_NAPI_ARGC_ONE = 1;
constexpr size_t JS_NAPI_ARGC_TWO = 2;
EdmConnectionCallbackStub::EdmConnectionCallbackStub(napi_env env, napi_value callback)
{
    napi_create_reference(env, callback, 1, &callbackRef_);

    napi_value asyncName;
    napi_create_string_utf8(env, "EdmOnConnect", NAPI_AUTO_LENGTH, &asyncName);
    napi_create_threadsafe_function(env, callback, nullptr, asyncName, 0, 1, nullptr, nullptr,
        this, TsfnOnConnectCallJs, &tsfnOnConnect_);

    napi_create_string_utf8(env, "EdmOnDisconnect", NAPI_AUTO_LENGTH, &asyncName);
    napi_create_threadsafe_function(env, callback, nullptr, asyncName, 0, 1, nullptr, nullptr,
        this, TsfnOnDisconnectCallJs, &tsfnOnDisconnect_);

    napi_create_string_utf8(env, "EdmOnFailed", NAPI_AUTO_LENGTH, &asyncName);
    napi_create_threadsafe_function(env, callback, nullptr, asyncName, 0, 1, nullptr, nullptr,
        this, TsfnOnFailedCallJs, &tsfnOnFailed_);
}

EdmConnectionCallbackStub::~EdmConnectionCallbackStub()
{
    if (released_.exchange(true)) {
        return;
    }
    if (tsfnOnConnect_ != nullptr) {
        napi_release_threadsafe_function(tsfnOnConnect_, napi_tsfn_abort);
    }
    if (tsfnOnDisconnect_ != nullptr) {
        napi_release_threadsafe_function(tsfnOnDisconnect_, napi_tsfn_abort);
    }
    if (tsfnOnFailed_ != nullptr) {
        napi_release_threadsafe_function(tsfnOnFailed_, napi_tsfn_abort);
    }
}

int32_t EdmConnectionCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    std::u16string descriptor = data.ReadInterfaceToken();
    if (descriptor != IEdmConnectionCallback::GetDescriptor()) {
        EDMLOGE("descriptor mismatch");
        return ERR_INVALID_STATE;
    }
    switch (code) {
        case static_cast<uint32_t>(EdmConnectionCallbackCode::ON_CONNECT): {
            AppExecFwk::ElementName element;
            element.ReadFromParcel(data);
            sptr<IRemoteObject> remote = data.ReadRemoteObject();
            OnConnect(element, remote);
            break;
        }
        case static_cast<uint32_t>(EdmConnectionCallbackCode::ON_DISCONNECT): {
            AppExecFwk::ElementName element;
            element.ReadFromParcel(data);
            OnDisconnect(element);
            break;
        }
        case static_cast<uint32_t>(EdmConnectionCallbackCode::ON_FAILED): {
            int32_t codeValue = data.ReadInt32();
            OnFailed(codeValue);
            break;
        }
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return ERR_OK;
}

void EdmConnectionCallbackStub::OnConnect(const AppExecFwk::ElementName &element,
    const sptr<IRemoteObject> &remote)
{
    EDMLOGI("EdmConnectionCallbackStub::OnConnect");
    auto *data = new (std::nothrow) ConnectData();
    if (data == nullptr) {
        return;
    }
    data->bundleName = element.GetBundleName();
    data->abilityName = element.GetAbilityName();
    data->remote = remote;
    napi_call_threadsafe_function(tsfnOnConnect_, data, napi_tsfn_blocking);
}

void EdmConnectionCallbackStub::OnDisconnect(const AppExecFwk::ElementName &element)
{
    EDMLOGI("EdmConnectionCallbackStub::OnDisconnect");
    auto *data = new (std::nothrow) DisconnectData();
    if (data == nullptr) {
        return;
    }
    data->bundleName = element.GetBundleName();
    data->abilityName = element.GetAbilityName();
    napi_call_threadsafe_function(tsfnOnDisconnect_, data, napi_tsfn_blocking);
}

void EdmConnectionCallbackStub::OnFailed(int32_t code)
{
    EDMLOGI("EdmConnectionCallbackStub::OnFailed code=%{public}d", code);
    int32_t *codePtr = new (std::nothrow) int32_t(code);
    if (codePtr == nullptr) {
        return;
    }
    napi_call_threadsafe_function(tsfnOnFailed_, codePtr, napi_tsfn_blocking);
}

napi_value EdmConnectionCallbackStub::WrapElementName(napi_env env, const std::string &bundleName,
    const std::string &abilityName)
{
    napi_value elementObj;
    napi_create_object(env, &elementObj);
    napi_value bundleVal;
    napi_value abilityVal;
    napi_create_string_utf8(env, bundleName.c_str(), NAPI_AUTO_LENGTH, &bundleVal);
    napi_create_string_utf8(env, abilityName.c_str(), NAPI_AUTO_LENGTH, &abilityVal);
    napi_set_named_property(env, elementObj, "bundleName", bundleVal);
    napi_set_named_property(env, elementObj, "abilityName", abilityVal);
    return elementObj;
}

void EdmConnectionCallbackStub::TsfnOnConnectCallJs(napi_env env, napi_value jsCb,
    void *context, void *data)
{
    auto *cbData = static_cast<ConnectData *>(data);
    if (cbData == nullptr || env == nullptr) {
        return;
    }
    napi_value callbackObj;
    napi_get_reference_value(env, reinterpret_cast<EdmConnectionCallbackStub *>(context)->callbackRef_,
        &callbackObj);
    if (callbackObj == nullptr) {
        delete cbData;
        return;
    }
    napi_value onConnect;
    napi_get_named_property(env, callbackObj, "onConnect", &onConnect);
    napi_value elementObj = WrapElementName(env, cbData->bundleName, cbData->abilityName);
    napi_value args[2] = {elementObj, nullptr};
    napi_get_undefined(env, &args[1]);
    if (cbData->remote != nullptr) {
        args[1] = NAPI_ohos_rpc_CreateJsRemoteObject(env, cbData->remote);
    }
    napi_value undefined;
    napi_get_undefined(env, &undefined);
    napi_call_function(env, undefined, onConnect, JS_NAPI_ARGC_TWO, args, nullptr);
    delete cbData;
}

void EdmConnectionCallbackStub::TsfnOnDisconnectCallJs(napi_env env, napi_value jsCb,
    void *context, void *data)
{
    auto *cbData = static_cast<DisconnectData *>(data);
    if (cbData == nullptr || env == nullptr) {
        return;
    }
    napi_value callbackObj;
    napi_get_reference_value(env, reinterpret_cast<EdmConnectionCallbackStub *>(context)->callbackRef_,
        &callbackObj);
    if (callbackObj == nullptr) {
        delete cbData;
        return;
    }
    napi_value onDisconnect;
    napi_get_named_property(env, callbackObj, "onDisconnect", &onDisconnect);
    napi_value elementObj = WrapElementName(env, cbData->bundleName, cbData->abilityName);
    napi_value undefined;
    napi_get_undefined(env, &undefined);
    napi_call_function(env, undefined, onDisconnect, JS_NAPI_ARGC_ONE, &elementObj, nullptr);
    delete cbData;
}

void EdmConnectionCallbackStub::TsfnOnFailedCallJs(napi_env env, napi_value jsCb,
    void *context, void *data)
{
    auto *codePtr = static_cast<int32_t *>(data);
    if (codePtr == nullptr || env == nullptr) {
        return;
    }
    napi_value callbackObj;
    napi_get_reference_value(env, reinterpret_cast<EdmConnectionCallbackStub *>(context)->callbackRef_,
        &callbackObj);
    if (callbackObj == nullptr) {
        delete codePtr;
        return;
    }
    napi_value onFailed;
    napi_get_named_property(env, callbackObj, "onFailed", &onFailed);
    napi_value codeVal;
    napi_create_int32(env, *codePtr, &codeVal);
    napi_value undefined;
    napi_get_undefined(env, &undefined);
    napi_call_function(env, undefined, onFailed, JS_NAPI_ARGC_ONE, &codeVal, nullptr);
    delete codePtr;
}
} // namespace EDM
} // namespace OHOS
