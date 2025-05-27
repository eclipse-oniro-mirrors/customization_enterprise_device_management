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
#include "telephony_manager_addon.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "hisysevent_adapter.h"
#include "iptables_utils.h"

using namespace OHOS::EDM;

napi_value TelephonyManagerAddon::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor property[] = {
        DECLARE_NAPI_FUNCTION("setSimDisabled", SetSimDisabled),
        DECLARE_NAPI_FUNCTION("setSimEnabled", SetSimEnabled),
        DECLARE_NAPI_FUNCTION("isSimDisabled", IsSimDisabled),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(property) / sizeof(property[0]), property));
    return exports;
}


napi_value TelephonyManagerAddon::SetSimDisabled(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_SetSimDisabled called");
#if defined(TELEPHONY_EDM_ENABLE)
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "setSimDisabled";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::INT32};
    addonMethodSign.methodAttribute = MethodAttribute::HANDLE;
    AdapterAddonData adapterAddonData{};
    napi_value result = JsObjectToData(env, info, addonMethodSign, &adapterAddonData);
    if (result == nullptr) {
        return nullptr;
    }
    int32_t ret = TelephonyManagerProxy::GetTelephonyManagerProxy()->SetSimDisabled(adapterAddonData.data);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
#else
    EDMLOGW("TelephonyManagerAddon::SetSimDisabled Unsupported Capabilities.");
    napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
    return nullptr;
#endif
}

napi_value TelephonyManagerAddon::SetSimEnabled(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_SetSimEnabled called");
#if defined(TELEPHONY_EDM_ENABLE)
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "setSimEnabled";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::INT32};
    addonMethodSign.methodAttribute = MethodAttribute::HANDLE;
    AdapterAddonData adapterAddonData{};
    napi_value result = JsObjectToData(env, info, addonMethodSign, &adapterAddonData);
    if (result == nullptr) {
        return nullptr;
    }
    int32_t ret = TelephonyManagerProxy::GetTelephonyManagerProxy()->SetSimEnabled(adapterAddonData.data);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
#else
    EDMLOGW("TelephonyManagerAddon::SetSimEnabled Unsupported Capabilities.");
    napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
    return nullptr;
#endif
}

napi_value TelephonyManagerAddon::IsSimDisabled(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_IsSimDisabled called");
#if defined(TELEPHONY_EDM_ENABLE)
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "isSimDisabled";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::INT32};
    addonMethodSign.methodAttribute = MethodAttribute::GET;
    AdapterAddonData adapterAddonData{};
    napi_value result = JsObjectToData(env, info, addonMethodSign, &adapterAddonData);
    if (result == nullptr) {
        return nullptr;
    }
    bool isDisable = false;
    int32_t ret = TelephonyManagerProxy::GetTelephonyManagerProxy()->IsSimDisabled(adapterAddonData.data, isDisable);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    result = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, isDisable, &result));
    return result;
#else
    EDMLOGW("TelephonyManagerAddon::IsSimDisabled Unsupported Capabilities.");
    napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
    return nullptr;
#endif
}

static napi_module g_telephonyManagerModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = TelephonyManagerAddon::Init,
    .nm_modname = "enterprise.telephonyManager",
    .nm_priv = ((void *)0),
    .reserved = {0},
};

extern "C" __attribute__((constructor)) void TelephonyManagerRegister()
{
    napi_module_register(&g_telephonyManagerModule);
}