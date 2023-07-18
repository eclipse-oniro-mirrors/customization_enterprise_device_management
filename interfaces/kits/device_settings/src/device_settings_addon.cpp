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
#include "device_settings_addon.h"

#include "edm_log.h"

using namespace OHOS::EDM;

napi_value DeviceSettingsAddon::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor property[] = {
        DECLARE_NAPI_FUNCTION("getScreenOffTime", GetScreenOffTime),
        DECLARE_NAPI_FUNCTION("installUserCertificate", InstallUserCertificate),
        DECLARE_NAPI_FUNCTION("uninstallUserCertificate", UninstallUserCertificate),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(property) / sizeof(property[0]), property));
    return exports;
}

napi_value DeviceSettingsAddon::GetScreenOffTime(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetScreenOffTime called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    bool matchFlag = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    if (argc > ARGS_SIZE_ONE) {
        matchFlag = matchFlag && MatchValueType(env, argv[ARR_INDEX_ONE], napi_function);
    }
    ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter type error");
    auto asyncCallbackInfo = new (std::nothrow) AsyncDeviceSettingsCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncDeviceSettingsCallbackInfo> callbackPtr{asyncCallbackInfo};
    bool ret = ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]);
    ASSERT_AND_THROW_PARAM_ERROR(env, ret, "element name param error");
    EDMLOGD(
        "GetScreenOffTime: asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->abilityname:%{public}s",
        asyncCallbackInfo->elementName.GetBundleName().c_str(),
        asyncCallbackInfo->elementName.GetAbilityName().c_str());
    if (argc > ARGS_SIZE_ONE) {
        EDMLOGD("GetScreenOffTime argc == ARGS_SIZE_TWO");
        napi_create_reference(env, argv[ARR_INDEX_ONE], NAPI_RETURN_ONE, &asyncCallbackInfo->callback);
    }
    napi_value asyncWorkReturn = HandleAsyncWork(env, asyncCallbackInfo, "GetScreenOffTime", NativeGetScreenOffTime,
        NativeNumberCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

void DeviceSettingsAddon::NativeGetScreenOffTime(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeGetScreenOffTime called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncDeviceSettingsCallbackInfo *asyncCallbackInfo = static_cast<AsyncDeviceSettingsCallbackInfo *>(data);
    auto proxy = DeviceSettingsProxy::GetDeviceSettingsProxy();
    if (proxy == nullptr) {
        EDMLOGE("can not get DeviceSettingsProxy");
        return;
    }
    asyncCallbackInfo->ret = proxy->GetScreenOffTime(asyncCallbackInfo->elementName, asyncCallbackInfo->intRet);
}

napi_value DeviceSettingsAddon::InstallUserCertificate(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_InstallUserCertificate called");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    bool matchFlag = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter want error");
    matchFlag = MatchValueType(env, argv[ARR_INDEX_ONE], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter certblob error");
    if (argc > ARGS_SIZE_TWO) {
        matchFlag = MatchValueType(env, argv[ARR_INDEX_TWO], napi_function);
        ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter callback error");
    }
    auto asyncCallbackInfo = new (std::nothrow) AsyncCertCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncCertCallbackInfo> callbackPtr{asyncCallbackInfo};
    bool retAdmin = ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]);
    ASSERT_AND_THROW_PARAM_ERROR(env, retAdmin, "element name param error");
    EDMLOGD(
        "InstallUserCertificate: asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->abilityname:%{public}s",
        asyncCallbackInfo->elementName.GetBundleName().c_str(),
        asyncCallbackInfo->elementName.GetAbilityName().c_str());

    bool retCertBlob = ParseCertBlob(env, argv[ARR_INDEX_ONE], asyncCallbackInfo);
    ASSERT_AND_THROW_PARAM_ERROR(env, retCertBlob, "element cert blob error");

    if (argc > ARGS_SIZE_TWO) {
        napi_create_reference(env, argv[ARR_INDEX_TWO], NAPI_RETURN_ONE, &asyncCallbackInfo->callback);
    }
    napi_value asyncWorkReturn = HandleAsyncWork(env, asyncCallbackInfo, "InstallUserCertificate",
        NativeInstallUserCertificate, NativeStringCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

void DeviceSettingsAddon::NativeInstallUserCertificate(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeInstallUserCertificate called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncCertCallbackInfo *asyncCallbackInfo = static_cast<AsyncCertCallbackInfo *>(data);
    asyncCallbackInfo->ret = DeviceSettingsProxy::GetDeviceSettingsProxy()->InstallUserCertificate(
        asyncCallbackInfo->elementName, asyncCallbackInfo->certArray, asyncCallbackInfo->alias,
        asyncCallbackInfo->stringRet, asyncCallbackInfo->innerCodeMsg);
}

napi_value DeviceSettingsAddon::UninstallUserCertificate(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_UninstallUserCertificate called");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    bool matchFlag = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter want error");
    matchFlag = MatchValueType(env, argv[ARR_INDEX_ONE], napi_string);
    ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter uri error");
    if (argc > ARGS_SIZE_TWO) {
        matchFlag = MatchValueType(env, argv[ARR_INDEX_TWO], napi_function);
        ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter callback error");
    }
    auto asyncCallbackInfo = new (std::nothrow) AsyncCertCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncCertCallbackInfo> callbackPtr{asyncCallbackInfo};
    bool retAdmin = ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]);
    ASSERT_AND_THROW_PARAM_ERROR(env, retAdmin, "element name param error");
    EDMLOGD(
        "UninstallUserCertificate: asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->abilityname:%{public}s",
        asyncCallbackInfo->elementName.GetBundleName().c_str(),
        asyncCallbackInfo->elementName.GetAbilityName().c_str());

    bool retAlias = ParseString(env, asyncCallbackInfo->alias, argv[ARR_INDEX_ONE]);
    ASSERT_AND_THROW_PARAM_ERROR(env, retAlias, "element alias error");

    if (argc > ARGS_SIZE_TWO) {
        napi_create_reference(env, argv[ARR_INDEX_TWO], NAPI_RETURN_ONE, &asyncCallbackInfo->callback);
    }
    napi_value asyncWorkReturn = HandleAsyncWork(env, asyncCallbackInfo, "uninstallUserCertificate",
        NativeUninstallUserCertificate, NativeVoidCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

void DeviceSettingsAddon::NativeUninstallUserCertificate(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeUninstallUserCertificate called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncCertCallbackInfo *asyncCallbackInfo = static_cast<AsyncCertCallbackInfo *>(data);
    asyncCallbackInfo->ret = DeviceSettingsProxy::GetDeviceSettingsProxy()->UninstallUserCertificate(
        asyncCallbackInfo->elementName, asyncCallbackInfo->alias, asyncCallbackInfo->innerCodeMsg);
}

bool DeviceSettingsAddon::ParseCertBlob(napi_env env, napi_value object, AsyncCertCallbackInfo *asyncCertCallbackInfo)
{
    napi_valuetype type = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, object, &type), false);
    if (type != napi_object) {
        EDMLOGE("type of param certblob is not object");
        return false;
    }
    if (!JsObjectToU8Vector(env, object, "inData", asyncCertCallbackInfo->certArray)) {
        EDMLOGE("uint8Array to vector failed");
        return false;
    }
    return JsObjectToString(env, object, "alias", true, asyncCertCallbackInfo->alias);
}

static napi_module g_deviceSettingsModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = DeviceSettingsAddon::Init,
    .nm_modname = "enterprise.deviceSettings",
    .nm_priv = ((void *)0),
    .reserved = {0},
};

extern "C" __attribute__((constructor)) void DeviceSettingsRegister()
{
    napi_module_register(&g_deviceSettingsModule);
}