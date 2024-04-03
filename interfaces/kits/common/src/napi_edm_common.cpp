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

#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_log.h"
#include "js_native_api.h"
#include "js_native_api_types.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "napi_edm_error.h"

namespace OHOS {
namespace EDM {
static void NativeCallbackComplete(napi_env env, napi_status status, AsyncCallbackInfo *asyncCallbackInfo,
    napi_value result)
{
    EDMLOGD("NativeCallbackComplete asyncCallbackInfo->ret is %{public}d", asyncCallbackInfo->ret);
    if (asyncCallbackInfo->deferred != nullptr) {
        EDMLOGD("NativeCallbackComplete asyncCallbackInfo->deferred != nullptr");
        if (asyncCallbackInfo->ret == ERR_OK) {
            napi_resolve_deferred(env, asyncCallbackInfo->deferred, result);
        } else {
            if (asyncCallbackInfo->innerCodeMsg.empty()) {
                napi_reject_deferred(env, asyncCallbackInfo->deferred, CreateError(env, asyncCallbackInfo->ret));
            } else {
                napi_reject_deferred(env, asyncCallbackInfo->deferred,
                    CreateErrorWithInnerCode(env, asyncCallbackInfo->ret, asyncCallbackInfo->innerCodeMsg));
            }
        }
    } else {
        napi_value callbackValue[ARGS_SIZE_TWO] = {0};
        if (asyncCallbackInfo->ret == ERR_OK) {
            napi_get_null(env, &callbackValue[ARR_INDEX_ZERO]);
            callbackValue[ARR_INDEX_ONE] = result;
        } else {
            if (asyncCallbackInfo->innerCodeMsg.empty()) {
                callbackValue[ARR_INDEX_ZERO] = CreateError(env, asyncCallbackInfo->ret);
            } else {
                callbackValue[ARR_INDEX_ZERO] =
                    CreateErrorWithInnerCode(env, asyncCallbackInfo->ret, asyncCallbackInfo->innerCodeMsg);
            }
            napi_get_null(env, &callbackValue[ARR_INDEX_ONE]);
        }
        napi_value callback = nullptr;
        napi_value ret = nullptr;
        napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
        napi_call_function(env, nullptr, callback, std::size(callbackValue), callbackValue, &ret);
        napi_delete_reference(env, asyncCallbackInfo->callback);
    }
    napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
}

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
    if (!JsObjectToString(env, args, "bundleName", true, bundleName) ||
        !JsObjectToString(env, args, "abilityName", true, abilityName)) {
        EDMLOGE("Parameter element bundleName error");
        return false;
    }
    EDMLOGD("ParseElementName bundleName %{public}s ", bundleName.c_str());
    EDMLOGD("ParseElementName abilityname %{public}s", abilityName.c_str());

    elementName.SetBundleName(bundleName);
    elementName.SetAbilityName(abilityName);
    return true;
}

bool ParseLong(napi_env env, int64_t &param, napi_value args)
{
    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, args, &valueType) != napi_ok || valueType != napi_number ||
        napi_get_value_int64(env, args, &param) != napi_ok) {
        EDMLOGE("Wrong argument type. int64 expected.");
        return false;
    }
    return true;
}

bool ParseInt(napi_env env, int32_t &param, napi_value args)
{
    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, args, &valueType) != napi_ok || valueType != napi_number ||
        napi_get_value_int32(env, args, &param) != napi_ok) {
        EDMLOGE("Wrong argument type. int32 expected.");
        return false;
    }
    return true;
}

bool ParseCallback(napi_env env, napi_ref &param, napi_value args)
{
    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, args, &valueType) != napi_ok || valueType != napi_function ||
        napi_create_reference(env, args, NAPI_RETURN_ONE, &param) != napi_ok) {
        EDMLOGE("Wrong argument type. napi_function expected.");
        return false;
    }
    return true;
}

bool ParseUint(napi_env env, uint32_t &param, napi_value args)
{
    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, args, &valueType) != napi_ok || valueType != napi_number ||
        napi_get_value_uint32(env, args, &param) != napi_ok) {
        EDMLOGE("Wrong argument type. uint32 expected.");
        return false;
    }
    return true;
}

bool ParseBool(napi_env env, bool &param, napi_value args)
{
    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, args, &valueType) != napi_ok || valueType != napi_boolean ||
        napi_get_value_bool(env, args, &param) != napi_ok) {
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

bool ParseCharArray(napi_env env, napi_value args, size_t maxLength, char *param)
{
    napi_valuetype valuetype;
    if (napi_typeof(env, args, &valuetype) != napi_ok || valuetype != napi_string) {
        EDMLOGE("can not get string value");
        return false;
    }
    size_t size = 0;
    if (napi_get_value_string_utf8(env, args, nullptr, NAPI_RETURN_ZERO, &size) != napi_ok) {
        EDMLOGE("can not get string size");
        return false;
    }
    if (size >= maxLength) {
        EDMLOGE("string size too long");
        return false;
    }
    if (napi_get_value_string_utf8(env, args, param, (size + NAPI_RETURN_ONE), &size) != napi_ok) {
        EDMLOGE("can not get string value");
        return false;
    }
    return true;
}

napi_value ParseStringArray(napi_env env, std::vector<std::string> &stringArray, napi_value args)
{
    EDMLOGD("begin to parse string array");
    bool isArray = false;
    NAPI_CALL(env, napi_is_array(env, args, &isArray));
    if (!isArray) {
        EDMLOGE("napi object is not array.");
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

napi_value ParseElementArray(napi_env env, std::vector<AppExecFwk::ElementName> &elementArray, napi_value args)
{
    EDMLOGD("begin to parse element array");
    bool isArray = false;
    NAPI_CALL(env, napi_is_array(env, args, &isArray));
    if (!isArray) {
        EDMLOGE("napi object is not array.");
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
        if (valueType != napi_object) {
            elementArray.clear();
            return nullptr;
        }
        AppExecFwk::ElementName element;
        ParseElementName(env, element, value);
        elementArray.push_back(element);
    }
    // create result code
    napi_value result;
    napi_status status = napi_create_int32(env, NAPI_RETURN_ONE, &result);
    if (status != napi_ok) {
        return nullptr;
    }
    return result;
}

bool JsObjectToInt(napi_env env, napi_value object, const char *filedStr, bool isNecessaryProp, int32_t &result)
{
    bool hasProperty = false;
    if (napi_has_named_property(env, object, filedStr, &hasProperty) != napi_ok) {
        EDMLOGE("get js property failed.");
        return false;
    }
    if (isNecessaryProp && !hasProperty) {
        return false;
    }
    if (hasProperty) {
        napi_value prop = nullptr;
        return napi_get_named_property(env, object, filedStr, &prop) == napi_ok && ParseInt(env, result, prop);
    }
    return true;
}

bool JsObjectToUint(napi_env env, napi_value object, const char *filedStr, bool isNecessaryProp, uint32_t &result)
{
    bool hasProperty = false;
    if (napi_has_named_property(env, object, filedStr, &hasProperty) != napi_ok) {
        EDMLOGE("get js property failed.");
        return false;
    }
    if (isNecessaryProp && !hasProperty) {
        return false;
    }
    if (hasProperty) {
        napi_value prop = nullptr;
        return napi_get_named_property(env, object, filedStr, &prop) == napi_ok && ParseUint(env, result, prop);
    }
    return true;
}

bool JsObjectToBool(napi_env env, napi_value object, const char *filedStr, bool isNecessaryProp, bool &result)
{
    bool hasProperty = false;
    if (napi_has_named_property(env, object, filedStr, &hasProperty) != napi_ok) {
        EDMLOGE("get js property failed.");
        return false;
    }
    if (isNecessaryProp && !hasProperty) {
        return false;
    }
    if (hasProperty) {
        napi_value prop = nullptr;
        return napi_get_named_property(env, object, filedStr, &prop) == napi_ok && ParseBool(env, result, prop);
    }
    return true;
}

bool JsObjectToString(napi_env env, napi_value object, const char *filedStr, bool isNecessaryProp,
    std::string &resultStr)
{
    bool hasProperty = false;
    if (napi_has_named_property(env, object, filedStr, &hasProperty) != napi_ok) {
        EDMLOGE("get js property failed.");
        return false;
    }
    if (isNecessaryProp && !hasProperty) {
        return false;
    }
    if (hasProperty) {
        napi_value prop = nullptr;
        return napi_get_named_property(env, object, filedStr, &prop) == napi_ok && ParseString(env, resultStr, prop);
    }
    return true;
}

bool JsObjectToCharArray(napi_env env, napi_value object, const char *filedStr, std::tuple<int, bool> charArrayProp,
    char *result)
{
    bool hasProperty = false;
    if (napi_has_named_property(env, object, filedStr, &hasProperty) != napi_ok) {
        EDMLOGE("get js property failed.");
        return false;
    }
    int maxLength = 0;
    bool isNecessaryProp = false;
    std::tie(maxLength, isNecessaryProp) = charArrayProp;
    if (isNecessaryProp && !hasProperty) {
        return false;
    }
    if (hasProperty) {
        napi_value prop = nullptr;
        return napi_get_named_property(env, object, filedStr, &prop) == napi_ok &&
            ParseCharArray(env, prop, maxLength, result);
    }
    return true;
}

bool GetJsProperty(napi_env env, napi_value object, const char *filedStr, napi_value &result)
{
    bool hasProperty = false;
    if (napi_has_named_property(env, object, filedStr, &hasProperty) != napi_ok || !hasProperty ||
        napi_get_named_property(env, object, filedStr, &result) != napi_ok) {
        EDMLOGE("Js has no property");
        return false;
    }
    return true;
}

bool JsObjectToU8Vector(napi_env env, napi_value object, const char *fieldStr, std::vector<uint8_t> &certVector)
{
    napi_value certEntry;
    if (!GetJsProperty(env, object, fieldStr, certEntry)) {
        return false;
    }
    bool isTypedArray = false;
    if (napi_is_typedarray(env, certEntry, &isTypedArray) != napi_ok || !isTypedArray) {
        EDMLOGE("js property is not typedarray");
        return false;
    }
    size_t length = 0;
    size_t offset = 0;
    napi_typedarray_type type;
    napi_value buffer = nullptr;
    void *data = nullptr;
    if (napi_get_typedarray_info(env, certEntry, &type, &length, &data, &buffer, &offset) != napi_ok ||
        type != napi_uint8_array || buffer == nullptr) {
        EDMLOGE("js object type is not uint8 array");
        return false;
    }
    if (length > NAPI_MAX_DATA_LEN) {
        EDMLOGE("uint8 array range failed");
        return false;
    }
    if (data == nullptr) {
        EDMLOGE("uint8 array data failed");
        return false;
    }
    certVector.clear();
    certVector.assign(static_cast<uint8_t *>(data), (static_cast<uint8_t *>(data) + length));
    return true;
}

bool JsObjectToStringVector(napi_env env, napi_value object, const char *filedStr, bool isNecessaryProp,
    std::vector<std::string> &vec)
{
    bool hasProperty = false;
    if (napi_has_named_property(env, object, filedStr, &hasProperty) != napi_ok) {
        EDMLOGE("get js property failed.");
        return false;
    }
    if (isNecessaryProp && !hasProperty) {
        EDMLOGE("no yaobaohua hasProperty.");
        return false;
    }
    if (hasProperty) {
        napi_value prop = nullptr;
        return napi_get_named_property(env, object, filedStr, &prop) == napi_ok && ParseStringArray(env, vec, prop);
    }
    return true;
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
            if (asyncCallbackInfo->innerCodeMsg.empty()) {
                napi_reject_deferred(env, asyncCallbackInfo->deferred, CreateError(env, asyncCallbackInfo->ret));
            } else {
                napi_reject_deferred(env, asyncCallbackInfo->deferred,
                    CreateErrorWithInnerCode(env, asyncCallbackInfo->ret, asyncCallbackInfo->innerCodeMsg));
            }
        }
    } else {
        EDMLOGD("asyncCallbackInfo->callback != nullptr");
        if (asyncCallbackInfo->ret == ERR_OK) {
            napi_get_null(env, &error);
        } else {
            if (asyncCallbackInfo->innerCodeMsg.empty()) {
                error = CreateError(env, asyncCallbackInfo->ret);
            } else {
                error = CreateErrorWithInnerCode(env, asyncCallbackInfo->ret, asyncCallbackInfo->innerCodeMsg);
            }
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
    napi_create_async_work(env, resource, resourceName, execute, complete, static_cast<void *>(context),
        &context->asyncWork);
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
    napi_value result = nullptr;
    napi_get_boolean(env, asyncCallbackInfo->boolRet, &result);
    NativeCallbackComplete(env, status, asyncCallbackInfo, result);
    delete asyncCallbackInfo;
}

void NativeNumberCallbackComplete(napi_env env, napi_status status, void *data)
{
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncCallbackInfo *asyncCallbackInfo = static_cast<AsyncCallbackInfo *>(data);
    napi_value result = nullptr;
    napi_create_int32(env, asyncCallbackInfo->intRet, &result);
    NativeCallbackComplete(env, status, asyncCallbackInfo, result);
    delete asyncCallbackInfo;
}

void NativeStringCallbackComplete(napi_env env, napi_status status, void *data)
{
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncCallbackInfo *asyncCallbackInfo = static_cast<AsyncCallbackInfo *>(data);
    napi_value result = nullptr;
    napi_create_string_utf8(env, asyncCallbackInfo->stringRet.c_str(), NAPI_AUTO_LENGTH, &result);
    NativeCallbackComplete(env, status, asyncCallbackInfo, result);
    delete asyncCallbackInfo;
}

void NativeArrayStringCallbackComplete(napi_env env, napi_status status, void *data)
{
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncCallbackInfo *asyncCallbackInfo = static_cast<AsyncCallbackInfo *>(data);
    napi_value result = nullptr;
    napi_create_array(env, &result);
    ConvertStringVectorToJS(env, asyncCallbackInfo->arrayStringRet, result);
    NativeCallbackComplete(env, status, asyncCallbackInfo, result);
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

bool CheckAdminWithUserIdParamType(napi_env env, size_t argc, napi_value *argv, bool &hasCallback, bool &hasUserId)
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

bool CheckGetPolicyAdminParam(napi_env env, napi_value value, bool &hasAdmin,
    OHOS::AppExecFwk::ElementName &elementName)
{
    if (MatchValueType(env, value, napi_null)) {
        hasAdmin = false;
        return true;
    }
    if (MatchValueType(env, value, napi_object)) {
        hasAdmin = true;
        if (ParseElementName(env, elementName, value)) {
            return true;
        }
    }
    return false;
}

bool ParseStringToInt(const std::string &strValue, int32_t &result)
{
    int64_t temp = 0;
    if (!ParseStringToLong(strValue, temp)) {
        EDMLOGE("ParseStringToInt: parse str failed");
        return false;
    }
    if (temp < INT_MIN || temp > INT_MAX) {
        EDMLOGE("ParseStringToInt: parse failed, int32 expected.");
        return false;
    }
    result = temp;
    return true;
}

bool ParseStringToLong(const std::string &strValue, int64_t &result)
{
    char *end = nullptr;
    const char *p = strValue.c_str();
    errno = 0;
    result = strtoll(p, &end, EdmConstants::DECIMAL);
    if (errno == ERANGE || end == p || *end != '\0') {
        EDMLOGE("ParseStringToLong: parse str failed: %{public}s", p);
        return false;
    }
    return true;
}
} // namespace EDM
} // namespace OHOS