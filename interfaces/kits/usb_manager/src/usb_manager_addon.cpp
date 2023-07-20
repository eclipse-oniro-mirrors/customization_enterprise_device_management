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
#include "usb_manager_addon.h"

#include "edm_log.h"
#include "usb_manager_proxy.h"

using namespace OHOS::EDM;

napi_value UsbManagerAddon::Init(napi_env env, napi_value exports)
{
    napi_value policyValue = nullptr;
    NAPI_CALL(env, napi_create_object(env, &policyValue));
    CreateUsbPolicyEnum(env, policyValue);
    napi_property_descriptor property[] = {
        DECLARE_NAPI_PROPERTY("UsbPolicy", policyValue),
        DECLARE_NAPI_FUNCTION("setUsbPolicy", SetUsbPolicy),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(property) / sizeof(property[0]), property));
    return exports;
}

void UsbManagerAddon::CreateUsbPolicyEnum(napi_env env, napi_value value)
{
    napi_value readWrite;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, READ_WRITE, &readWrite));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "READ_WRITE", readWrite));

    napi_value readOnly;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, READ_ONLY, &readOnly));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "READ_ONLY", readOnly));
}

napi_value UsbManagerAddon::SetUsbPolicy(napi_env env, napi_callback_info info)
{
    EDMLOGI("UsbManagerAddon::SetUsbPolicy called");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    bool hasAdmin = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, hasAdmin, "type admin error");
    bool usbPolicy = MatchValueType(env, argv[ARR_INDEX_ONE], napi_number);
    ASSERT_AND_THROW_PARAM_ERROR(env, usbPolicy, "type usbPolicy error");
    if (argc > ARGS_SIZE_TWO) {
        bool hasCallback = MatchValueType(env, argv[ARR_INDEX_TWO], napi_function);
        ASSERT_AND_THROW_PARAM_ERROR(env, hasCallback, "type callback error");
    }

    auto asyncCallbackInfo = new (std::nothrow) AsyncSetUsbPolicyCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncSetUsbPolicyCallbackInfo> callbackPtr{asyncCallbackInfo};
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    EDMLOGD(
        "SetUsbPolicy: asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->abilityname:%{public}s",
        asyncCallbackInfo->elementName.GetBundleName().c_str(),
        asyncCallbackInfo->elementName.GetAbilityName().c_str());
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, asyncCallbackInfo->policy, argv[ARR_INDEX_ONE]),
        "wifiProfile param error");
    if (argc > ARGS_SIZE_TWO) {
        EDMLOGD("NAPI_SetUsbPolicy argc == ARGS_SIZE_THREE");
        napi_create_reference(env, argv[ARGS_SIZE_TWO], NAPI_RETURN_ONE, &asyncCallbackInfo->callback);
    }
    bool existUsbPolicy = std::any_of(std::begin(USB_POLICY), std::end(USB_POLICY),
        [&](int item) { return item == asyncCallbackInfo->policy; });
    ASSERT_AND_THROW_PARAM_ERROR(env, existUsbPolicy, "usb policy value error");
    napi_value asyncWorkReturn =
        HandleAsyncWork(env, asyncCallbackInfo, "SetUsbPolicy", NativeSetUsbPolicy, NativeVoidCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

void UsbManagerAddon::NativeSetUsbPolicy(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeSetUsbPolicy called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncSetUsbPolicyCallbackInfo *asyncCallbackInfo = static_cast<AsyncSetUsbPolicyCallbackInfo *>(data);
    switch (asyncCallbackInfo->policy) {
        case READ_WRITE:
            asyncCallbackInfo->ret =
                UsbManagerProxy::GetUsbManagerProxy()->SetUsbReadOnly(asyncCallbackInfo->elementName, false);
            break;
        case READ_ONLY:
            asyncCallbackInfo->ret =
                UsbManagerProxy::GetUsbManagerProxy()->SetUsbReadOnly(asyncCallbackInfo->elementName, true);
            break;
        default:
            asyncCallbackInfo->ret = EdmReturnErrCode::PARAM_ERROR;
            break;
    }
}

static napi_module g_usbManagerModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = UsbManagerAddon::Init,
    .nm_modname = "enterprise.usbManager",
    .nm_priv = ((void *)0),
    .reserved = {0},
};

extern "C" __attribute__((constructor)) void UsbManagerRegister()
{
    napi_module_register(&g_usbManagerModule);
}