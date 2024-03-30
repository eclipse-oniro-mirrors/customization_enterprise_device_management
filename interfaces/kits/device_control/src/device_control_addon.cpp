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

#include "device_control_addon.h"
#include "operate_device_param.h"
#ifdef OS_ACCOUNT_EDM_ENABLE
#include "os_account_manager.h"
#endif
#include "edm_log.h"

using namespace OHOS::EDM;

napi_value DeviceControlAddon::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor property[] = {
        DECLARE_NAPI_FUNCTION("resetFactory", ResetFactory),
        DECLARE_NAPI_FUNCTION("shutdown", Shutdown),
        DECLARE_NAPI_FUNCTION("reboot", Reboot),
        DECLARE_NAPI_FUNCTION("lockScreen", LockScreen),
        DECLARE_NAPI_FUNCTION("operateDevice", OperateDevice),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(property) / sizeof(property[0]), property));
    return exports;
}

napi_value DeviceControlAddon::ResetFactory(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_resetFactory called");
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
    auto asyncCallbackInfo = new (std::nothrow) AsyncDeviceControlCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncDeviceControlCallbackInfo> callbackPtr {asyncCallbackInfo};
    bool ret = ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]);
    ASSERT_AND_THROW_PARAM_ERROR(env, ret, "element name param error");
    EDMLOGD("resetFactory: asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->abilityname:%{public}s",
        asyncCallbackInfo->elementName.GetBundleName().c_str(),
        asyncCallbackInfo->elementName.GetAbilityName().c_str());
    if (argc > ARGS_SIZE_ONE) {
        EDMLOGD("NAPI_resetFactory argc == ARGS_SIZE_TWO");
        napi_create_reference(env, argv[ARR_INDEX_ONE], NAPI_RETURN_ONE, &asyncCallbackInfo->callback);
    }
    napi_value asyncWorkReturn = HandleAsyncWork(env, asyncCallbackInfo, "ResetFactory",
        NativeResetFactory, NativeVoidCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

napi_value DeviceControlAddon::LockScreen(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_lockScreen called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    bool matchFlag = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter type error");
    OHOS::AppExecFwk::ElementName elementName;
    bool ret = ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]);
    ASSERT_AND_THROW_PARAM_ERROR(env, ret, "element name param error");
    EDMLOGD("lockScreen: asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->abilityname:%{public}s",
        elementName.GetBundleName().c_str(),
        elementName.GetAbilityName().c_str());
    int32_t userId = 0;
#ifdef OS_ACCOUNT_EDM_ENABLE
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromProcess(userId);
    EDMLOGI("NAPI_lockScreen called userId :%{public}d", userId);
#else
    EDMLOGI("NAPI_lockScreen don't call userId");
#endif
    int32_t result = DeviceControlProxy::GetDeviceControlProxy()->LockScreen(elementName, userId);
    if (FAILED(result)) {
        napi_throw(env, CreateError(env, result));
    }
    return nullptr;
}

napi_value DeviceControlAddon::Shutdown(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_shutdown called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    bool matchFlag = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter type error");
    OHOS::AppExecFwk::ElementName elementName;
    bool ret = ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]);
    ASSERT_AND_THROW_PARAM_ERROR(env, ret, "element name param error");
    EDMLOGD("lockScreen: asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->abilityname:%{public}s",
        elementName.GetBundleName().c_str(),
        elementName.GetAbilityName().c_str());
    int32_t result = DeviceControlProxy::GetDeviceControlProxy()->Shutdown(elementName);
    if (FAILED(result)) {
        napi_throw(env, CreateError(env, result));
    }
    return nullptr;
}

napi_value DeviceControlAddon::Reboot(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_reboot called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    bool matchFlag = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter type error");
    OHOS::AppExecFwk::ElementName elementName;
    bool ret = ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]);
    ASSERT_AND_THROW_PARAM_ERROR(env, ret, "element name param error");
    EDMLOGD("lockScreen: asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->abilityname:%{public}s",
        elementName.GetBundleName().c_str(),
        elementName.GetAbilityName().c_str());
    int32_t result = DeviceControlProxy::GetDeviceControlProxy()->Reboot(elementName);
    if (FAILED(result)) {
        napi_throw(env, CreateError(env, result));
    }
    return nullptr;
}

void DeviceControlAddon::NativeResetFactory(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeResetFactory called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncDeviceControlCallbackInfo *asyncCallbackInfo = static_cast<AsyncDeviceControlCallbackInfo *>(data);
    if (DeviceControlProxy::GetDeviceControlProxy() == nullptr) {
        EDMLOGE("can not get GetDeviceControlProxy");
        return;
    }
    asyncCallbackInfo->ret =
        DeviceControlProxy::GetDeviceControlProxy()->ResetFactory(asyncCallbackInfo->elementName);
}

napi_value DeviceControlAddon::OperateDevice(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_OperateDevice called");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    bool matchFlag = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object) &&
        MatchValueType(env, argv[ARR_INDEX_ONE], napi_string);
    if (argc > ARGS_SIZE_TWO) {
        matchFlag = matchFlag && MatchValueType(env, argv[ARR_INDEX_TWO], napi_string);
    }
    ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter type error");

    AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(
        env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]), "element name param error");
    EDMLOGD("resetFactory: elementName.bundlename %{public}s, abilityname:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());
    OperateDeviceParam param;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseString(env, param.operate, argv[ARR_INDEX_ONE]), "operate param error");
    if (argc > ARGS_SIZE_TWO) {
        ASSERT_AND_THROW_PARAM_ERROR(env, ParseString(env, param.addition, argv[ARR_INDEX_TWO]),
            "addition param error");
    }
#ifdef OS_ACCOUNT_EDM_ENABLE
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromProcess(param.userId);
    EDMLOGI("NAPI_lockScreen called userId :%{public}d", param.userId);
#else
    EDMLOGI("NAPI_lockScreen don't call userId");
#endif
    int32_t ret = DeviceControlProxy::GetDeviceControlProxy()->OperateDevice(elementName, param);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
}

static napi_module g_deviceControlModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = DeviceControlAddon::Init,
    .nm_modname = "enterprise.deviceControl",
    .nm_priv = ((void *)0),
    .reserved = { 0 },
};

extern "C" __attribute__((constructor)) void DeviceControlManagerRegister()
{
    napi_module_register(&g_deviceControlModule);
}
