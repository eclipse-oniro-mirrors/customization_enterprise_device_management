/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
    EDMLOGI("NAPI_SetDateTime called");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    bool matchFlag = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object) &&
        MatchValueType(env, argv[ARR_INDEX_ONE], napi_number);
    if (argc > ARGS_SIZE_TWO) {
        matchFlag = matchFlag && MatchValueType(env, argv[ARR_INDEX_TWO], napi_function);
    }
    ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter type error");
    auto asyncCallbackInfo = new (std::nothrow) AsyncSetDateTimeCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncSetDateTimeCallbackInfo> callbackPtr {asyncCallbackInfo};
    bool ret = ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]);
    ASSERT_AND_THROW_PARAM_ERROR(env, ret, "element name param error");
    EDMLOGD("SetDateTime: asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->abilityname:%{public}s",
        asyncCallbackInfo->elementName.GetBundleName().c_str(),
        asyncCallbackInfo->elementName.GetAbilityName().c_str());
    ret = ParseLong(env, asyncCallbackInfo->time, argv[ARR_INDEX_ONE]);
    ASSERT_AND_THROW_PARAM_ERROR(env, ret, "time param error");
    if (argc > ARGS_SIZE_TWO) {
        EDMLOGD("NAPI_SetDateTime argc == ARGS_SIZE_THREE");
        napi_create_reference(env, argv[ARR_INDEX_TWO], NAPI_RETURN_ONE, &asyncCallbackInfo->callback);
    }

    napi_value asyncWorkReturn = HandleAsyncWork(env, asyncCallbackInfo, "SetDateTime",
        NativeSetDateTime, NativeVoidCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

void DatetimeManagerAddon::NativeSetDateTime(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeSetDateTime called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncSetDateTimeCallbackInfo *asyncCallbackInfo = static_cast<AsyncSetDateTimeCallbackInfo *>(data);
    auto dateTimeManagerProxy = DatetimeManagerProxy::GetDatetimeManagerProxy();
    if (dateTimeManagerProxy == nullptr) {
        EDMLOGE("can not get DatetimeManagerProxy");
        return;
    }
    asyncCallbackInfo->ret = dateTimeManagerProxy->SetDateTime(asyncCallbackInfo->elementName,
        asyncCallbackInfo->time);
}

napi_value DatetimeManagerAddon::DisallowModifyDateTime(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_DisallowModifyDateTime called");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    bool matchFlag = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object) &&
        MatchValueType(env, argv[ARR_INDEX_ONE], napi_boolean);
    if (argc > ARGS_SIZE_TWO) {
        matchFlag = matchFlag && MatchValueType(env, argv[ARR_INDEX_TWO], napi_function);
    }
    ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter type error");
    auto asyncCallbackInfo = new (std::nothrow) AsyncDisallowModifyDateTimeCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncDisallowModifyDateTimeCallbackInfo> callbackPtr {asyncCallbackInfo};
    bool ret = ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]);
    ASSERT_AND_THROW_PARAM_ERROR(env, ret, "element name param error");
    EDMLOGD("DisallowModifyDateTime: asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->abilityname:%{public}s",
        asyncCallbackInfo->elementName.GetBundleName().c_str(),
        asyncCallbackInfo->elementName.GetAbilityName().c_str());
    ret = ParseBool(env, asyncCallbackInfo->disallow, argv[ARR_INDEX_ONE]);
    ASSERT_AND_THROW_PARAM_ERROR(env, ret, "disallow param error");
    if (argc > ARGS_SIZE_TWO) {
        EDMLOGD("NAPI_DisallowModifyDateTime argc == ARGS_SIZE_THREE");
        napi_create_reference(env, argv[ARR_INDEX_TWO], NAPI_RETURN_ONE, &asyncCallbackInfo->callback);
    }

    napi_value asyncWorkReturn = HandleAsyncWork(env, asyncCallbackInfo, "DisallowModifyDateTime",
        NativeDisallowModifyDateTime, NativeVoidCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

void DatetimeManagerAddon::NativeDisallowModifyDateTime(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeDisallowModifyDateTime called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncDisallowModifyDateTimeCallbackInfo *asyncCallbackInfo =
        static_cast<AsyncDisallowModifyDateTimeCallbackInfo *>(data);
    auto dateTimeManagerProxy = DatetimeManagerProxy::GetDatetimeManagerProxy();
    if (dateTimeManagerProxy == nullptr) {
        EDMLOGE("can not get DatetimeManagerProxy");
        return;
    }
    asyncCallbackInfo->ret = dateTimeManagerProxy->DisallowModifyDateTime(asyncCallbackInfo->elementName,
        asyncCallbackInfo->disallow);
}

napi_value DatetimeManagerAddon::IsModifyDateTimeDisallowed(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_IsModifyDateTimeDisallowed called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    auto asyncCallbackInfo = new (std::nothrow) AsyncDisallowModifyDateTimeCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncDisallowModifyDateTimeCallbackInfo> callbackPtr {asyncCallbackInfo};
    bool matchFlag = false;
    if (MatchValueType(env, argv[ARR_INDEX_ZERO], napi_null)) {
        asyncCallbackInfo->hasAdmin = false;
        matchFlag = true;
    } else if (MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object)) {
        matchFlag = true;
        asyncCallbackInfo->hasAdmin = true;
        bool ret = ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]);
        ASSERT_AND_THROW_PARAM_ERROR(env, ret, "element name param error");
        EDMLOGD("IsModifyDateTimeDisallowed: asyncCallbackInfo->elementName.bundlename %{public}s, "
            "asyncCallbackInfo->abilityname:%{public}s",
            asyncCallbackInfo->elementName.GetBundleName().c_str(),
            asyncCallbackInfo->elementName.GetAbilityName().c_str());
    }
    if (argc > ARGS_SIZE_ONE) {
        matchFlag = matchFlag && MatchValueType(env, argv[ARR_INDEX_ONE], napi_function);
    }
    ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter type error");
    if (argc > ARGS_SIZE_ONE) {
        EDMLOGD("NAPI_IsModifyDateTimeDisallowed argc == ARGS_SIZE_TWO");
        napi_create_reference(env, argv[ARR_INDEX_ONE], NAPI_RETURN_ONE, &asyncCallbackInfo->callback);
    }
    napi_value asyncWorkReturn = HandleAsyncWork(env, asyncCallbackInfo, "IsModifyDateTimeDisallowed",
        NativeIsModifyDateTimeDisallowed, NativeBoolCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

void DatetimeManagerAddon::NativeIsModifyDateTimeDisallowed(napi_env env, void *data)
{
    EDMLOGI("NativeIsModifyDateTimeDisallowed called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncDisallowModifyDateTimeCallbackInfo *asyncCallbackInfo =
        static_cast<AsyncDisallowModifyDateTimeCallbackInfo *>(data);
    auto dateTimeManagerProxy = DatetimeManagerProxy::GetDatetimeManagerProxy();
    if (dateTimeManagerProxy == nullptr) {
        EDMLOGE("can not get DatetimeManagerProxy");
        return;
    }
    if (asyncCallbackInfo->hasAdmin) {
        asyncCallbackInfo->ret = dateTimeManagerProxy->IsModifyDateTimeDisallowed(&(asyncCallbackInfo->elementName),
            asyncCallbackInfo->boolRet);
    } else {
        asyncCallbackInfo->ret = dateTimeManagerProxy->IsModifyDateTimeDisallowed(nullptr, asyncCallbackInfo->boolRet);
    }
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