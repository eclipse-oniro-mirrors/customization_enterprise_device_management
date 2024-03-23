/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "bluetooth_manager_addon.h"

#include "edm_constants.h"
#include "edm_log.h"
#include "js_native_api.h"
#include "napi_edm_common.h"

using namespace OHOS::EDM;

napi_value BluetoothManagerAddon::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor property[] = {
        DECLARE_NAPI_FUNCTION("getBluetoothInfo", GetBluetoothInfo),
        DECLARE_NAPI_FUNCTION("setBluetoothDisabled", SetBluetoothDisabled),
        DECLARE_NAPI_FUNCTION("isBluetoothDisabled", IsBluetoothDisabled),
        DECLARE_NAPI_FUNCTION("addAllowedBluetoothDevices", SetBluetoothWhitelist),
        DECLARE_NAPI_FUNCTION("getAllowedBluetoothDevices", GetBluetoothWhitelist),
        DECLARE_NAPI_FUNCTION("removeAllowedBluetoothDevices", RemoveBluetoothWhitelist),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(property) / sizeof(property[0]), property));
    return exports;
}

napi_value BluetoothManagerAddon::GetBluetoothInfo(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetBluetoothInfo called");
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_value thisArg = nullptr;
    void* data = nullptr;
    OHOS::AppExecFwk::ElementName elementName;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter type error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    EDMLOGD(
        "EnableAdmin: elementName.bundlename %{public}s, "
        "elementName.abilityname:%{public}s",
        elementName.GetBundleName().c_str(),
        elementName.GetAbilityName().c_str());
    BluetoothInfo bluetoothInfo;
    auto bluetoothManagerProxy = BluetoothManagerProxy::GetBluetoothManagerProxy();
    int32_t ret = bluetoothManagerProxy->GetBluetoothInfo(elementName, bluetoothInfo);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    return ConvertBluetoothInfo(env, bluetoothInfo);
}

napi_value BluetoothManagerAddon::ConvertBluetoothInfo(napi_env env, BluetoothInfo &bluetoothInfo)
{
    napi_value objBluetoothInfo = nullptr;
    NAPI_CALL(env, napi_create_object(env, &objBluetoothInfo));
    napi_value napi_name;
    napi_value napi_state;
    napi_value napi_connectionState;
    NAPI_CALL(env, napi_create_string_utf8(env, bluetoothInfo.name.c_str(), bluetoothInfo.name.size(), &napi_name));
    NAPI_CALL(env, napi_create_int32(env, bluetoothInfo.state, &napi_state));
    NAPI_CALL(env, napi_create_int32(env, bluetoothInfo.connectionState, &napi_connectionState));
    NAPI_CALL(env, napi_set_named_property(env, objBluetoothInfo, "name", napi_name));
    NAPI_CALL(env, napi_set_named_property(env, objBluetoothInfo, "state", napi_state));
    NAPI_CALL(env, napi_set_named_property(env, objBluetoothInfo, "connectionState", napi_connectionState));
    return objBluetoothInfo;
}

napi_value BluetoothManagerAddon::SetBluetoothDisabled(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_SetBluetoothDisabled called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = { nullptr };
    napi_value thisArg = nullptr;
    void* data = nullptr;
    OHOS::AppExecFwk::ElementName elementName;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));

    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object),
        "The first parameter must be want.");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ONE], napi_boolean),
        "The second parameter must be bool.");

    bool ret = ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]);
    ASSERT_AND_THROW_PARAM_ERROR(env, ret, "param 'admin' parse error");
    EDMLOGD("EnableAdmin: elementName.bundlename %{public}s, elementName.abilityname:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());

    bool disabled = false;
    ret = ParseBool(env, disabled, argv[ARR_INDEX_ONE]);
    ASSERT_AND_THROW_PARAM_ERROR(env, ret, "param 'disabled' parse error");

    auto bluetoothManagerProxy = BluetoothManagerProxy::GetBluetoothManagerProxy();
    int32_t retCode = bluetoothManagerProxy->SetBluetoothDisabled(elementName, disabled);
    if (FAILED(retCode)) {
        napi_throw(env, CreateError(env, retCode));
    }
    return nullptr;
}

napi_value BluetoothManagerAddon::IsBluetoothDisabled(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_IsBluetoothDisabled called");
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_value thisArg = nullptr;
    void* data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    bool hasAdmin = false;
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, CheckGetPolicyAdminParam(env, argv[ARR_INDEX_ZERO], hasAdmin, elementName),
        "param admin need be null or want");
    bool isDisabled = false;
    int32_t ret = ERR_OK;
    if (hasAdmin) {
        ret = BluetoothManagerProxy::GetBluetoothManagerProxy()->IsBluetoothDisabled(&elementName, isDisabled);
    } else {
        ret = BluetoothManagerProxy::GetBluetoothManagerProxy()->IsBluetoothDisabled(nullptr, isDisabled);
    }
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    napi_value result = nullptr;
    napi_get_boolean(env, isDisabled, &result);
    return result;
}

napi_value BluetoothManagerAddon::SetBluetoothWhitelist(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_SetBluetoothWhitelist called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = { nullptr };
    napi_value thisArg = nullptr;
    void *data = nullptr;
    OHOS::AppExecFwk::ElementName elementName;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));

    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter type error");
    bool ret = ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]);
    ASSERT_AND_THROW_PARAM_ERROR(env, ret, "param 'admin' parse error");
    EDMLOGD("EnableAdmin: elementName.bundlename %{public}s, elementName.abilityname:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());

    auto bluetoothManagerProxy = BluetoothManagerProxy::GetBluetoothManagerProxy();
    std::vector<std::string> whitelist;
    ret = ParseStringArray(env, whitelist, argv[ARR_INDEX_ONE]);
    ASSERT_AND_THROW_PARAM_ERROR(env, ret, "param 'whitelist' parse error");
    int32_t retCode = bluetoothManagerProxy->SetBluetoothWhitelist(elementName, whitelist);
    if (FAILED(retCode)) {
        napi_throw(env, CreateError(env, retCode));
    }
    return nullptr;
}

napi_value BluetoothManagerAddon::GetBluetoothWhitelist(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetBluetoothWhitelist called");
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_value thisArg = nullptr;
    void *data = nullptr;
    bool hasAdmin = false;
    OHOS::AppExecFwk::ElementName elementName;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, CheckGetPolicyAdminParam(env, argv[ARR_INDEX_ZERO], hasAdmin, elementName),
        "param admin need be null or want");
    EDMLOGD("EnableAdmin: elementName.bundlename %{public}s, "
        "elementName.abilityname:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());
    auto bluetoothManagerProxy = BluetoothManagerProxy::GetBluetoothManagerProxy();
    std::vector<std::string> whitelist;
    int32_t ret = bluetoothManagerProxy->GetBluetoothWhitelist(elementName, whitelist);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    napi_value result = nullptr;
    napi_create_array(env, &result);
    for (size_t i = 0; i < whitelist.size(); i++) {
        napi_value whiteMac = nullptr;
        napi_create_string_utf8(env, whitelist[i].c_str(), NAPI_AUTO_LENGTH, &whiteMac);
        napi_set_element(env, result, i, whiteMac);
    }
    return result;
}

napi_value BluetoothManagerAddon::RemoveBluetoothWhitelist(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_RemoveBluetoothWhitelist called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = { nullptr };
    napi_value thisArg = nullptr;
    void *data = nullptr;
    OHOS::AppExecFwk::ElementName elementName;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));

    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter type error");
    bool ret = ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]);
    ASSERT_AND_THROW_PARAM_ERROR(env, ret, "param 'admin' parse error");
    EDMLOGD("EnableAdmin: elementName.bundlename %{public}s, elementName.abilityname:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());

    auto bluetoothManagerProxy = BluetoothManagerProxy::GetBluetoothManagerProxy();
    std::vector<std::string> whitelist;
    ret = ParseStringArray(env, whitelist, argv[ARR_INDEX_ONE]);
    ASSERT_AND_THROW_PARAM_ERROR(env, ret, "param 'whitelist' parse error");
    int32_t retCode = bluetoothManagerProxy->RemoveBluetoothWhitelist(elementName, whitelist);
    if (FAILED(retCode)) {
        napi_throw(env, CreateError(env, retCode));
    }
    return nullptr;
}

static napi_module g_bluetoothModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = BluetoothManagerAddon::Init,
    .nm_modname = "enterprise.bluetoothManager",
    .nm_priv = ((void *)0),
    .reserved = {0},
};

extern "C" __attribute__((constructor)) void BluetoothManagerRegister()
{
    napi_module_register(&g_bluetoothModule);
}
