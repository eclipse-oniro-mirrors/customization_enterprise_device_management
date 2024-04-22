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

#include "cJSON.h"
#include "datetime_manager_proxy.h"
#include "edm_constants.h"
#include "edm_log.h"

using namespace OHOS::EDM;

void DeviceSettingsAddon::CreatePowerSceneObject(napi_env env, napi_value value)
{
    napi_value nTimeOut;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, static_cast<uint32_t>(PowerScene::TIME_OUT), &nTimeOut));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "TIME_OUT", nTimeOut));
}

void DeviceSettingsAddon::CreatePowerPolicyActionObject(napi_env env, napi_value value)
{
    napi_value nActionNone;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_uint32(env, static_cast<uint32_t>(PowerPolicyAction::NONE), &nActionNone));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "NONE", nActionNone));
    napi_value nActionAutoSuspend;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_uint32(env, static_cast<uint32_t>(PowerPolicyAction::AUTO_SUSPEND), &nActionAutoSuspend));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "AUTO_SUSPEND", nActionAutoSuspend));
    napi_value nActionForceSuspend;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_uint32(env, static_cast<uint32_t>(PowerPolicyAction::FORCE_SUSPEND), &nActionForceSuspend));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "FORCE_SUSPEND", nActionForceSuspend));
    napi_value nActionHibernate;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_uint32(env, static_cast<uint32_t>(PowerPolicyAction::HIBERNATE), &nActionHibernate));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "HIBERNATE", nActionHibernate));
    napi_value nActionShutDown;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_uint32(env, static_cast<uint32_t>(PowerPolicyAction::SHUTDOWN), &nActionShutDown));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "SHUTDOWN", nActionShutDown));
}

napi_value DeviceSettingsAddon::Init(napi_env env, napi_value exports)
{
    napi_value nTimeOut = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nTimeOut));
    CreatePowerSceneObject(env, nTimeOut);
    napi_value nPolicyAction = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nPolicyAction));
    CreatePowerPolicyActionObject(env, nPolicyAction);

    napi_property_descriptor property[] = {
        DECLARE_NAPI_FUNCTION("setScreenOffTime", SetScreenOffTime),
        DECLARE_NAPI_FUNCTION("getScreenOffTime", GetScreenOffTime),
        DECLARE_NAPI_FUNCTION("setPowerPolicy", SetPowerPolicy),
        DECLARE_NAPI_FUNCTION("getPowerPolicy", GetPowerPolicy),
        DECLARE_NAPI_FUNCTION("installUserCertificate", InstallUserCertificate),
        DECLARE_NAPI_FUNCTION("uninstallUserCertificate", UninstallUserCertificate),
        DECLARE_NAPI_PROPERTY("PowerScene", nTimeOut),
        DECLARE_NAPI_PROPERTY("PowerPolicyAction", nPolicyAction),
        DECLARE_NAPI_FUNCTION("setValue", SetValue),
        DECLARE_NAPI_FUNCTION("getValue", GetValue)
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(property) / sizeof(property[0]), property));
    return exports;
}

napi_value DeviceSettingsAddon::SetPowerPolicy(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_SetPowerPolicy called");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_THREE, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter admin error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ONE], napi_number), "parameter number error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_TWO], napi_object), "parameter object error");

    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    PowerScene powerScene;
    ASSERT_AND_THROW_PARAM_ERROR(env, JsObjToPowerScene(env, argv[ARR_INDEX_ONE], powerScene),
        "power scene param error");
    PowerPolicy powerPolicy;
    ASSERT_AND_THROW_PARAM_ERROR(env, JsObjToPowerPolicy(env, argv[ARR_INDEX_TWO], powerPolicy),
        "power policy param error");
    int32_t ret = DeviceSettingsProxy::GetDeviceSettingsProxy()->SetPowerPolicy(elementName, powerScene, powerPolicy);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        EDMLOGE("SetPowerPolicy failed!");
    }
    return nullptr;
}

napi_value DeviceSettingsAddon::GetPowerPolicy(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetPowerPolicy called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter admin error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ONE], napi_number), "parameter number error");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    PowerScene powerScene;
    ASSERT_AND_THROW_PARAM_ERROR(env, JsObjToPowerScene(env, argv[ARR_INDEX_ONE], powerScene),
        "power scene param error");
    PowerPolicy powerPolicy;
    int32_t ret = DeviceSettingsProxy::GetDeviceSettingsProxy()->GetPowerPolicy(elementName, powerScene, powerPolicy);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        EDMLOGE("SetPowerPolicy failed!");
        return nullptr;
    }
    napi_value result = ConvertPolicyPolicyToJs(env, powerPolicy);
    return result;
}

bool DeviceSettingsAddon::JsObjToPowerScene(napi_env env, napi_value object, PowerScene &powerScene)
{
    uint32_t powerInt = 0;
    if (ParseUint(env, powerInt, object) && powerInt == static_cast<uint32_t>(PowerScene::TIME_OUT)) {
        powerScene = PowerScene(powerInt);
        return true;
    }
    return false;
}

bool DeviceSettingsAddon::JsObjToPowerPolicy(napi_env env, napi_value object, PowerPolicy &powerPolicy)
{
    uint32_t action = 0;
    if (!JsObjectToUint(env, object, "powerPolicyAction", true, action)) {
        EDMLOGE("SetPowerPolicy powerPolicyAction parse error!");
        return false;
    }
    uint32_t delayTime = 0;
    if (!JsObjectToUint(env, object, "delayTime", true, delayTime)) {
        EDMLOGE("SetPowerPolicy delayTime parse error!");
        return false;
    }
    powerPolicy.SetDelayTime(delayTime);
    if (!powerPolicy.SetPowerPolicyAction(action)) {
        return false;
    }
    return true;
}

napi_value DeviceSettingsAddon::ConvertPolicyPolicyToJs(napi_env env, PowerPolicy &powerPolicy)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_object(env, &result));
    napi_value action = nullptr;
    NAPI_CALL(env, napi_create_uint32(env, static_cast<uint32_t>(powerPolicy.GetPowerPolicyAction()), &action));
    napi_value delayTime = nullptr;
    NAPI_CALL(env, napi_create_uint32(env, powerPolicy.GetDealyTime(), &delayTime));
    NAPI_CALL(env, napi_set_named_property(env, result, "powerPolicyAction", action));
    NAPI_CALL(env, napi_set_named_property(env, result, "delayTime", delayTime));
    return result;
}

napi_value DeviceSettingsAddon::SetScreenOffTime(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_SetScreenOffTime called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter admin error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ONE], napi_number), "parameter number error");

    auto asyncCallbackInfo = new (std::nothrow) AsyncScreenOffTimeCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncScreenOffTimeCallbackInfo> callbackPtr{asyncCallbackInfo};
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    EDMLOGD(
        "SetScreenOffTime: asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->abilityname:%{public}s",
        asyncCallbackInfo->elementName.GetBundleName().c_str(),
        asyncCallbackInfo->elementName.GetAbilityName().c_str());
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, asyncCallbackInfo->time, argv[ARR_INDEX_ONE]),
        "element name param error");
    EDMLOGD("SetScreenOffTime time = %{public}d", asyncCallbackInfo->time);
    asyncCallbackInfo->ret = DeviceSettingsProxy::GetDeviceSettingsProxy()->SetScreenOffTime(
        asyncCallbackInfo->elementName, asyncCallbackInfo->time);
    if (FAILED(asyncCallbackInfo->ret)) {
        napi_throw(env, CreateError(env, asyncCallbackInfo->ret));
        EDMLOGE("SetScreenOffTime failed!");
    }
    return nullptr;
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
    auto asyncCallbackInfo = new (std::nothrow) AsyncScreenOffTimeCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncScreenOffTimeCallbackInfo> callbackPtr{asyncCallbackInfo};
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
    AsyncScreenOffTimeCallbackInfo *asyncCallbackInfo = static_cast<AsyncScreenOffTimeCallbackInfo *>(data);
    asyncCallbackInfo->ret = DeviceSettingsProxy::GetDeviceSettingsProxy()->GetScreenOffTime(
        asyncCallbackInfo->elementName, asyncCallbackInfo->intRet);
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

napi_value DeviceSettingsAddon::SetValue(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_SetValue called");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = { nullptr };
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_THREE, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter admin error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ONE], napi_string), "parameter item error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_TWO], napi_string), "parameter value error");

    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    std::string item;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseString(env, item, argv[ARR_INDEX_ONE]), "param 'item' error");
    std::string value;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseString(env, value, argv[ARR_INDEX_TWO]), "param 'value' error");
    int32_t ret = ERR_OK;
    auto proxy = DeviceSettingsProxy::GetDeviceSettingsProxy();
    if (item == EdmConstants::DeviceSettings::SCREEN_OFF) {
        int32_t screenOffTime = 0;
        ASSERT_AND_THROW_PARAM_ERROR(env, ParseStringToInt(value, screenOffTime), "param 'screenOffTime' error");
        ret = proxy->SetScreenOffTime(elementName, screenOffTime);
    } else if (item == EdmConstants::DeviceSettings::POWER_POLICY) {
        PowerScene powerScene;
        ASSERT_AND_THROW_PARAM_ERROR(env, JsStrToPowerScene(env, value, powerScene), "param 'powerScene' error");
        PowerPolicy powerPolicy;
        ASSERT_AND_THROW_PARAM_ERROR(env, JsStrToPowerPolicy(env, value, powerPolicy), "param 'powerPolicy' error");
        ret = proxy->SetPowerPolicy(elementName, powerScene, powerPolicy);
    } else if (item == EdmConstants::DeviceSettings::DATE_TIME) {
        int64_t dateTime = 0;
        ASSERT_AND_THROW_PARAM_ERROR(env, ParseStringToLong(value, dateTime), "param 'dateTime' error");
        ret = DatetimeManagerProxy::GetDatetimeManagerProxy()->SetDateTime(elementName, dateTime);
    } else {
        ret = EdmReturnErrCode::INTERFACE_UNSUPPORTED;
    }
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        EDMLOGE("SetValue failed! item is %{public}s", item.c_str());
    }
    return nullptr;
}

napi_value DeviceSettingsAddon::GetValue(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetValue called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter admin error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ONE], napi_string), "parameter item error");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    std::string item;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseString(env, item, argv[ARR_INDEX_ONE]), "param 'item' error");
    int32_t ret = ERR_OK;
    std::string stringRet;
    auto proxy = DeviceSettingsProxy::GetDeviceSettingsProxy();
    if (item == EdmConstants::DeviceSettings::SCREEN_OFF) {
        int32_t screenOffTime;
        ret = proxy->GetScreenOffTime(elementName, screenOffTime);
        stringRet = std::to_string(screenOffTime);
    } else if (item == EdmConstants::DeviceSettings::POWER_POLICY) {
        PowerScene powerScene = PowerScene::TIME_OUT;
        PowerPolicy powerPolicy;
        ret = proxy->GetPowerPolicy(elementName, powerScene, powerPolicy);
        if (SUCCEEDED(ret)) {
            ret = ConvertPowerPolicyToJsStr(env, powerScene, powerPolicy, stringRet);
        }
    } else {
        ret = EdmReturnErrCode::INTERFACE_UNSUPPORTED;
    }
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        EDMLOGE("GetValue failed! item is %{public}s", item.c_str());
        return nullptr;
    }
    napi_value result;
    napi_create_string_utf8(env, stringRet.c_str(), stringRet.size(), &result);
    return result;
}

bool DeviceSettingsAddon::JsStrToPowerScene(napi_env env, std::string jsStr, PowerScene &powerScene)
{
    cJSON *json = cJSON_Parse(jsStr.c_str());
    if (json == nullptr) {
        return false;
    }
    cJSON *itemPowerScene = cJSON_GetObjectItem(json, "powerScene");
    if (!cJSON_IsNumber(itemPowerScene)) {
        cJSON_Delete(json);
        return false;
    }
    powerScene = PowerScene(itemPowerScene->valueint);
    cJSON_Delete(json);
    return true;
}

bool DeviceSettingsAddon::JsStrToPowerPolicy(napi_env env, std::string jsStr, PowerPolicy &powerPolicy)
{
    cJSON *json = cJSON_Parse(jsStr.c_str());
    if (json == nullptr) {
        return false;
    }
    cJSON *itemPowerPolicy = cJSON_GetObjectItem(json, "powerPolicy");
    if (!cJSON_IsObject(itemPowerPolicy)) {
        cJSON_Delete(json);
        return false;
    }
    cJSON *delayTime = cJSON_GetObjectItem(itemPowerPolicy, "delayTime");
    if (!cJSON_IsNumber(delayTime)) {
        cJSON_Delete(json);
        return false;
    }
    powerPolicy.SetDelayTime(delayTime->valueint);
    cJSON *powerPolicyAction = cJSON_GetObjectItem(itemPowerPolicy, "powerPolicyAction");
    if (!cJSON_IsNumber(powerPolicyAction)) {
        cJSON_Delete(json);
        return false;
    }
    bool setActionRet = powerPolicy.SetPowerPolicyAction(powerPolicyAction->valueint);
    cJSON_Delete(json);
    return setActionRet;
}

int32_t DeviceSettingsAddon::ConvertPowerPolicyToJsStr(napi_env env, PowerScene &powerScene, PowerPolicy &powerPolicy,
    std::string &info)
{
    cJSON *json = cJSON_CreateObject();
    if (json == nullptr) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    cJSON *powerPoilcyJs = cJSON_CreateObject();
    if (powerPoilcyJs == nullptr) {
        cJSON_Delete(json);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    cJSON_AddNumberToObject(powerPoilcyJs, "powerPolicyAction",
        static_cast<uint32_t>(powerPolicy.GetPowerPolicyAction()));
    cJSON_AddNumberToObject(powerPoilcyJs, "delayTime", powerPolicy.GetDealyTime());
    cJSON_AddItemToObject(json, std::to_string(static_cast<uint32_t>(powerScene)).c_str(), powerPoilcyJs);
    char *jsonStr = cJSON_PrintUnformatted(json);
    if (jsonStr == nullptr) {
        cJSON_Delete(json);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    info = std::string(jsonStr);
    cJSON_Delete(json);
    cJSON_free(jsonStr);
    return ERR_OK;
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