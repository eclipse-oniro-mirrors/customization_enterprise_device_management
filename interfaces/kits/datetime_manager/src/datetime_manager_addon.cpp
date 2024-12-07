/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "datetime_manager_addon.h"
#include "edm_log.h"

#include "napi_edm_adapter.h"
using namespace OHOS::EDM;

napi_value DatetimeManagerAddon::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor property[] = {
        DECLARE_NAPI_FUNCTION("setDateTime", SetDateTime),
        DECLARE_NAPI_FUNCTION("disallowModifyDateTime", DisallowModifyDateTime),
        DECLARE_NAPI_FUNCTION("isModifyDateTimeDisallowed", IsModifyDateTimeDisallowed),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(property) / sizeof(property[0]), property));
    return exports;
}

napi_value DatetimeManagerAddon::SetDateTime(napi_env env, napi_callback_info info)
{
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "SetDateTime";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::INT64};
    addonMethodSign.methodAttribute = MethodAttribute::HANDLE;
    addonMethodSign.apiVersionTag = WITHOUT_PERMISSION_TAG;
    return AddonMethodAdapter(env, info, addonMethodSign, NativeSetDateTime, NativeVoidCallbackComplete);
}

void DatetimeManagerAddon::NativeSetDateTime(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeSetDateTime called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AdapterAddonData *asyncCallbackInfo = static_cast<AdapterAddonData *>(data);
    auto dateTimeManagerProxy = DatetimeManagerProxy::GetDatetimeManagerProxy();
    if (dateTimeManagerProxy == nullptr) {
        EDMLOGE("can not get DatetimeManagerProxy");
        return;
    }
    asyncCallbackInfo->ret = dateTimeManagerProxy->SetDateTime(asyncCallbackInfo->data);
}

napi_value DatetimeManagerAddon::DisallowModifyDateTime(napi_env env, napi_callback_info info)
{
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "DisallowModifyDateTime";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::BOOLEAN};
    addonMethodSign.methodAttribute = MethodAttribute::HANDLE;
    addonMethodSign.apiVersionTag = EdmConstants::PERMISSION_TAG_VERSION_11;
    return AddonMethodAdapter(env, info, addonMethodSign, NativeDisallowModifyDateTime, NativeVoidCallbackComplete);
}

void DatetimeManagerAddon::NativeDisallowModifyDateTime(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeDisallowModifyDateTime called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AdapterAddonData *asyncCallbackInfo =
        static_cast<AdapterAddonData *>(data);
    auto dateTimeManagerProxy = DatetimeManagerProxy::GetDatetimeManagerProxy();
    if (dateTimeManagerProxy == nullptr) {
        EDMLOGE("can not get DatetimeManagerProxy");
        return;
    }
    asyncCallbackInfo->ret = dateTimeManagerProxy->DisallowModifyDateTime(asyncCallbackInfo->data);
}

napi_value DatetimeManagerAddon::IsModifyDateTimeDisallowed(napi_env env, napi_callback_info info)
{
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "IsModifyDateTimeDisallowed";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT_NULL};
    addonMethodSign.methodAttribute = MethodAttribute::GET;
    addonMethodSign.apiVersionTag = EdmConstants::PERMISSION_TAG_VERSION_11;
    return AddonMethodAdapter(env, info, addonMethodSign, NativeIsModifyDateTimeDisallowed, NativeBoolCallbackComplete);
}

void DatetimeManagerAddon::NativeIsModifyDateTimeDisallowed(napi_env env, void *data)
{
    EDMLOGI("NativeIsModifyDateTimeDisallowed called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AdapterAddonData *asyncCallbackInfo =
        static_cast<AdapterAddonData *>(data);
    auto dateTimeManagerProxy = DatetimeManagerProxy::GetDatetimeManagerProxy();
    if (dateTimeManagerProxy == nullptr) {
        EDMLOGE("can not get DatetimeManagerProxy");
        return;
    }
    asyncCallbackInfo->ret = dateTimeManagerProxy->IsModifyDateTimeDisallowed(asyncCallbackInfo->data,
        asyncCallbackInfo->boolRet);
}

static napi_module g_dateTimeManagerModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = DatetimeManagerAddon::Init,
    .nm_modname = "enterprise.dateTimeManager",
    .nm_priv = ((void *)0),
    .reserved = { 0 },
};

extern "C" __attribute__((constructor)) void DateTimeManagerRegister()
{
    napi_module_register(&g_dateTimeManagerModule);
}