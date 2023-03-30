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

#include "napi_edm_common.h"

#include "edm_errors.h"
#include "edm_log.h"
#include "js_native_api.h"
#include "js_native_api_types.h"
#include "napi_edm_error.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace EDM {
bool MatchValueType(napi_env env, napi_value value, napi_valuetype targetType)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, value, &valueType);
    return valueType == targetType;
}

bool ParseElementName(napi_env env, AppExecFwk::ElementName &elementName, napi_value args)
{
    napi_valuetype valueType;
    NAPI_CALL_BASE(env, napi_typeof(env, args, &valueType), false);
    if (valueType != napi_object) {
        EDMLOGE("Parameter element valueType error");
        return false;
    }
    std::string bundleName;
    std::string abilityName;
    napi_value prop = nullptr;
    if (napi_get_named_property(env, args, "bundleName", &prop) != napi_ok ||
        !GetStringFromNAPI(env, prop, bundleName)) {
        EDMLOGE("Parameter element bundleName error");
        return false;
    }
    EDMLOGD("ParseElementName bundleName %{public}s ", bundleName.c_str());

    prop = nullptr;
    if (napi_get_named_property(env, args, "abilityName", &prop) != napi_ok ||
        !GetStringFromNAPI(env, prop, abilityName)) {
        EDMLOGE("Parameter abilityname error");
        return false;
    }
    EDMLOGD("ParseElementName abilityname %{public}s", abilityName.c_str());

    elementName.SetBundleName(bundleName);
    elementName.SetAbilityName(abilityName);
    return true;
}

bool ParseLong(napi_env env, int64_t &param, napi_value args)
{
    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, args, &valueType)!= napi_ok ||
        valueType != napi_number || napi_get_value_int64(env, args, &param) != napi_ok) {
        EDMLOGE("Wrong argument type. int64 expected.");
        return false;
    }
    return true;
}

bool ParseInt(napi_env env, int32_t &param, napi_value args)
{
    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, args, &valueType)!= napi_ok ||
        valueType != napi_number || napi_get_value_int32(env, args, &param) != napi_ok) {
        EDMLOGE("Wrong argument type. int32 expected.");
        return false;
    }
    return true;
}

bool ParseBool(napi_env env, bool &param, napi_value args)
{
    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, args, &valueType)!= napi_ok ||
        valueType != napi_boolean || napi_get_value_bool(env, args, &param) != napi_ok) {
        EDMLOGE("Wrong argument type. bool expected.");
        return false;
    }
    return true;
}

bool ParseString(napi_env env, std::string &param, napi_value args)
{
    napi_valuetype valuetype;
    if (napi_typeof(env, args, &valuetype) != napi_ok || valuetype != napi_string ||
        !GetStringFromNAPI(env, args, param)) {
        EDMLOGE("can not get string value");
        return false;
    }
    EDMLOGD("ParseString param = %{public}s.", param.c_str());
    return true;
}

bool GetStringFromNAPI(napi_env env, napi_value value, std::string &resultStr)
{
    std::string result;
    size_t size = 0;

    if (napi_get_value_string_utf8(env, value, nullptr, NAPI_RETURN_ZERO, &size) != napi_ok) {
        EDMLOGE("can not get string size");
        return false;
    }
    result.reserve(size + NAPI_RETURN_ONE);
    result.resize(size);
    if (napi_get_value_string_utf8(env, value, result.data(), (size + NAPI_RETURN_ONE), &size) != napi_ok) {
        EDMLOGE("can not get string value");
        return false;
    }
    resultStr = result;
    return true;
}

napi_value ParseStringArray(napi_env env, std::vector<std::string> &stringArray, napi_value args)
{
    EDMLOGD("begin to parse string array");
    bool isArray = false;
    NAPI_CALL(env, napi_is_array(env, args, &isArray));
    if (!isArray) {
        return nullptr;
    }
    uint32_t arrayLength = 0;
    NAPI_CALL(env, napi_get_array_length(env, args, &arrayLength));
    EDMLOGD("length=%{public}ud", arrayLength);
    for (uint32_t j = 0; j < arrayLength; j++) {
        napi_value value = nullptr;
        NAPI_CALL(env, napi_get_element(env, args, j, &value));
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, value, &valueType));
        if (valueType != napi_string) {
            stringArray.clear();
            return nullptr;
        }
        std::string str;
        GetStringFromNAPI(env, value, str);
        stringArray.push_back(str);
    }
    // create result code
    napi_value result;
    napi_status status = napi_create_int32(env, NAPI_RETURN_ONE, &result);
    if (status != napi_ok) {
        return nullptr;
    }
    return result;
}

void NativeVoidCallbackComplete(napi_env env, napi_status status, void *data)
{
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncCallbackInfo *asyncCallbackInfo = static_cast<AsyncCallbackInfo *>(data);
    napi_value error = nullptr;
    if (asyncCallbackInfo->callback == nullptr) {
        EDMLOGD("asyncCallbackInfo->deferred != nullptr");
        if (asyncCallbackInfo->ret == ERR_OK) {
            napi_get_null(env, &error);
            napi_resolve_deferred(env, asyncCallbackInfo->deferred, error);
        } else {
            napi_reject_deferred(env, asyncCallbackInfo->deferred, CreateError(env, asyncCallbackInfo->ret));
        }
    } else {
        if (asyncCallbackInfo->ret == ERR_OK) {
            napi_get_null(env, &error);
        } else {
            error = CreateError(env, asyncCallbackInfo->ret);
        }
        napi_value callback = nullptr;
        napi_value result = nullptr;
        napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
        napi_call_function(env, nullptr, callback, ARGS_SIZE_ONE, &error, &result);
        napi_delete_reference(env, asyncCallbackInfo->callback);
    }
    napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
    delete asyncCallbackInfo;
}

napi_value HandleAsyncWork(napi_env env, AsyncCallbackInfo *context, const std::string &workName,
    napi_async_execute_callback execute, napi_async_complete_callback complete)
{
    napi_value result = nullptr;
    if (context->callback == nullptr) {
        napi_create_promise(env, &context->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }
    napi_value resource = nullptr;
    napi_get_undefined(env, &resource);
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, workName.data(), NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(env, resource, resourceName, execute, complete,
        static_cast<void *>(context), &context->asyncWork);
    napi_queue_async_work(env, context->asyncWork);
    return result;
}

void NativeBoolCallbackComplete(napi_env env, napi_status status, void *data)
{
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncCallbackInfo *asyncCallbackInfo = static_cast<AsyncCallbackInfo *>(data);
    if (asyncCallbackInfo->deferred != nullptr) {
        EDMLOGD("asyncCallbackInfo->deferred != nullptr");
        if (asyncCallbackInfo->ret == ERR_OK) {
            EDMLOGD("asyncCallbackInfo->boolRet = %{public}d", asyncCallbackInfo->boolRet);
            napi_value result = nullptr;
            napi_get_boolean(env, asyncCallbackInfo->boolRet, &result);
            napi_resolve_deferred(env, asyncCallbackInfo->deferred, result);
        } else {
            napi_reject_deferred(env, asyncCallbackInfo->deferred, CreateError(env, asyncCallbackInfo->ret));
        }
    } else {
        napi_value callbackValue[ARGS_SIZE_TWO] = { 0 };
        if (asyncCallbackInfo->ret == ERR_OK) {
            napi_get_null(env, &callbackValue[ARR_INDEX_ZERO]);
            EDMLOGD("asyncCallbackInfo->boolRet = %{public}d", asyncCallbackInfo->boolRet);
            napi_get_boolean(env, asyncCallbackInfo->boolRet, &callbackValue[ARR_INDEX_ONE]);
        } else {
            EDMLOGD("asyncCallbackInfo->first = %{public}u, second = %{public}s ",
                GetMessageFromReturncode(asyncCallbackInfo->ret).first,
                GetMessageFromReturncode(asyncCallbackInfo->ret).second.c_str());
            callbackValue[ARR_INDEX_ZERO] = CreateError(env, asyncCallbackInfo->ret);
            napi_get_null(env, &callbackValue[ARR_INDEX_ONE]);
        }
        napi_value callback = nullptr;
        napi_value result = nullptr;
        napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
        napi_call_function(env, nullptr, callback, std::size(callbackValue), callbackValue, &result);
        napi_delete_reference(env, asyncCallbackInfo->callback);
    }
    napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
    delete asyncCallbackInfo;
}

void NativeStringCallbackComplete(napi_env env, napi_status status, void *data)
{
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncCallbackInfo *asyncCallbackInfo = static_cast<AsyncCallbackInfo *>(data);
    if (asyncCallbackInfo->deferred != nullptr) {
        EDMLOGD("asyncCallbackInfo->deferred != nullptr");
        if (asyncCallbackInfo->ret == ERR_OK) {
            EDMLOGD("asyncCallbackInfo->stringRet = %{public}s", asyncCallbackInfo->stringRet.c_str());
            napi_value result = nullptr;
            napi_create_string_utf8(env, asyncCallbackInfo->stringRet.c_str(), NAPI_AUTO_LENGTH, &result);
            napi_resolve_deferred(env, asyncCallbackInfo->deferred, result);
        } else {
            napi_reject_deferred(env, asyncCallbackInfo->deferred, CreateError(env, asyncCallbackInfo->ret));
        }
    } else {
        napi_value callbackValue[ARGS_SIZE_TWO] = { 0 };
        if (asyncCallbackInfo->ret == ERR_OK) {
            napi_get_null(env, &callbackValue[ARR_INDEX_ZERO]);
            EDMLOGD("asyncCallbackInfo->stringRet = %{public}s", asyncCallbackInfo->stringRet.c_str());
            napi_create_string_utf8(env, asyncCallbackInfo->stringRet.c_str(), NAPI_AUTO_LENGTH,
                &callbackValue[ARR_INDEX_ONE]);
        } else {
            EDMLOGD("asyncCallbackInfo->first = %{public}u, second = %{public}s ",
                GetMessageFromReturncode(asyncCallbackInfo->ret).first,
                GetMessageFromReturncode(asyncCallbackInfo->ret).second.c_str());
            callbackValue[ARR_INDEX_ZERO] = CreateError(env, asyncCallbackInfo->ret);
            napi_get_null(env, &callbackValue[ARR_INDEX_ONE]);
        }
        napi_value callback = nullptr;
        napi_value result = nullptr;
        napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
        napi_call_function(env, nullptr, callback, std::size(callbackValue), callbackValue, &result);
        napi_delete_reference(env, asyncCallbackInfo->callback);
    }
    napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
    delete asyncCallbackInfo;
}

void NativeArrayStringCallbackComplete(napi_env env, napi_status status, void *data)
{
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncCallbackInfo *asyncCallbackInfo = static_cast<AsyncCallbackInfo *>(data);
    if (asyncCallbackInfo->deferred != nullptr) {
        EDMLOGD("asyncCallbackInfo->deferred != nullptr");
        if (asyncCallbackInfo->ret == ERR_OK) {
            napi_value result = nullptr;
            napi_create_array(env, &result);
            ConvertStringVectorToJS(env, asyncCallbackInfo->arrayStringRet, result);
            napi_resolve_deferred(env, asyncCallbackInfo->deferred, result);
        } else {
            napi_reject_deferred(env, asyncCallbackInfo->deferred, CreateError(env, asyncCallbackInfo->ret));
        }
    } else {
        napi_value callbackValue[ARGS_SIZE_TWO] = { 0 };
        if (asyncCallbackInfo->ret == ERR_OK) {
            napi_get_null(env, &callbackValue[ARR_INDEX_ZERO]);
            napi_create_array(env, &callbackValue[ARGS_SIZE_ONE]);
            ConvertStringVectorToJS(env, asyncCallbackInfo->arrayStringRet, callbackValue[ARGS_SIZE_ONE]);
        } else {
            EDMLOGD("asyncCallbackInfo->first = %{public}u, second = %{public}s ",
                GetMessageFromReturncode(asyncCallbackInfo->ret).first,
                GetMessageFromReturncode(asyncCallbackInfo->ret).second.c_str());
            callbackValue[ARR_INDEX_ZERO] = CreateError(env, asyncCallbackInfo->ret);
            napi_get_null(env, &callbackValue[ARR_INDEX_ONE]);
        }
        napi_value callback = nullptr;
        napi_value result = nullptr;
        napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
        napi_call_function(env, nullptr, callback, std::size(callbackValue), callbackValue, &result);
        napi_delete_reference(env, asyncCallbackInfo->callback);
    }
    napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
    delete asyncCallbackInfo;
}

void ConvertStringVectorToJS(napi_env env, const std::vector<std::string> &stringVector, napi_value result)
{
    EDMLOGD("vector size: %{public}zu", stringVector.size());
    size_t idx = 0;
    for (const auto &str : stringVector) {
        napi_value obj = nullptr;
        napi_create_string_utf8(env, str.c_str(), NAPI_AUTO_LENGTH, &obj);
        napi_set_element(env, result, idx, obj);
        idx++;
    }
}

bool CheckAdminWithUserIdParamType(napi_env env, size_t argc,
    napi_value* argv, bool &hasCallback, bool &hasUserId)
{
    if (!MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object)) {
        EDMLOGE("CheckAdminWithUserIdParamType admin type check failed");
        return false;
    }
    EDMLOGI("argc = %{public}zu", argc);
    if (argc == ARGS_SIZE_ONE) {
        hasCallback = false;
        hasUserId = false;
        EDMLOGI("hasCallback = false; hasUserId = false;");
        return true;
    }

    if (argc == ARGS_SIZE_TWO) {
        if (MatchValueType(env, argv[ARR_INDEX_ONE], napi_function)) {
            hasCallback = true;
            hasUserId = false;
            EDMLOGI("hasCallback = true; hasUserId = false;");
            return true;
        } else {
            hasCallback = false;
            hasUserId = true;
            EDMLOGI("hasCallback = false;  hasUserId = true;");
            return MatchValueType(env, argv[ARR_INDEX_ONE], napi_number);
        }
    }
    hasCallback = true;
    hasUserId = true;
    EDMLOGI("hasCallback = true; hasUserId = true;");
    return MatchValueType(env, argv[ARR_INDEX_ONE], napi_number) &&
        MatchValueType(env, argv[ARR_INDEX_TWO], napi_function);
}
} // namespace EDM
} // namespace OHOS