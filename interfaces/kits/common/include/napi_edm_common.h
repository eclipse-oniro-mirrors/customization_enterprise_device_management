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

#ifndef INTERFACES_KITS_COMMON_INCLUDE_NAPI_EDM_COMMON_ADDON_H
#define INTERFACES_KITS_COMMON_INCLUDE_NAPI_EDM_COMMON_ADDON_H

#include <string>

#include "napi/native_api.h"
#include "want.h"

namespace OHOS {
namespace EDM {
struct AsyncCallbackInfo {
    napi_env env;
    napi_async_work asyncWork;
    napi_deferred deferred;
    napi_ref callback = 0;
    ErrCode ret;
    bool boolRet = true;
    std::string stringRet;
    std::vector<std::string> arrayStringRet;
    int32_t intRet = 0;
    int32_t err = 0;
    uint32_t errCode = 0;
    std::string errMessage;
    int policyCode = 0;
    std::string innerCodeMsg;

    virtual ~AsyncCallbackInfo() {};
};

constexpr int32_t ARR_INDEX_ZERO = 0;
constexpr int32_t ARR_INDEX_ONE = 1;
constexpr int32_t ARR_INDEX_TWO = 2;
constexpr int32_t ARR_INDEX_THREE = 3;
constexpr int32_t ARR_INDEX_FOUR = 4;

constexpr size_t ARGS_SIZE_ONE = 1;
constexpr size_t ARGS_SIZE_TWO = 2;
constexpr size_t ARGS_SIZE_THREE = 3;
constexpr size_t ARGS_SIZE_FOUR = 4;
constexpr size_t ARGS_SIZE_FIVE = 5;

constexpr int32_t NAPI_RETURN_ZERO = 0;
constexpr int32_t NAPI_RETURN_ONE = 1;

constexpr int NAPI_MAX_DATA_LEN = 0x6400000;

bool MatchValueType(napi_env env, napi_value value, napi_valuetype targetType);
bool ParseElementName(napi_env env, AppExecFwk::ElementName &elementName, napi_value args);
bool ParseLong(napi_env env, int64_t &param, napi_value args);
bool ParseInt(napi_env env, int32_t &param, napi_value args);
bool ParseUint(napi_env env, uint32_t &param, napi_value args);
bool ParseBool(napi_env env, bool &param, napi_value args);
bool ParseString(napi_env env, std::string &param, napi_value args);
bool ParseCallback(napi_env env, napi_ref &param, napi_value args);
napi_value ParseStringArray(napi_env env, std::vector<std::string> &stringArray, napi_value args);
napi_value ParseElementArray(napi_env env, std::vector<AppExecFwk::ElementName> &elementArray, napi_value args);
bool ParseCharArray(napi_env env, napi_value args, size_t maxLength, char *param);
bool GetStringFromNAPI(napi_env env, napi_value value, std::string &resultStr);
bool JsObjectToInt(napi_env env, napi_value object, const char *filedStr, bool isNecessaryProp, int32_t &result);
bool JsObjectToUint(napi_env env, napi_value object, const char *filedStr, bool isNecessaryProp, uint32_t &result);
bool JsObjectToBool(napi_env env, napi_value object, const char *filedStr, bool isNecessaryProp, bool &result);
bool JsObjectToString(napi_env env, napi_value object, const char *filedStr, bool isNecessaryProp,
    std::string &resultStr);
bool JsObjectToCharArray(napi_env env, napi_value object, const char *filedStr, std::tuple<int, bool> charArrayProp,
    char *result);
bool GetJsProperty(napi_env env, napi_value object, const char *filedStr, napi_value &result);
bool JsObjectToU8Vector(napi_env env, napi_value object, const char *fieldStr,
    std::vector<uint8_t> &certVector);
bool JsObjectToStringVector(napi_env env, napi_value object, const char *fieldStr, bool isNecessaryProp,
    std::vector<std::string> &stringVector);
void NativeVoidCallbackComplete(napi_env env, napi_status status, void *data);
napi_value HandleAsyncWork(napi_env env, AsyncCallbackInfo *context, const std::string &workName,
    napi_async_execute_callback execute, napi_async_complete_callback complete);
void NativeBoolCallbackComplete(napi_env env, napi_status status, void *data);
void NativeStringCallbackComplete(napi_env env, napi_status status, void *data);
void NativeNumberCallbackComplete(napi_env env, napi_status status, void *data);
void NativeArrayStringCallbackComplete(napi_env env, napi_status status, void *data);
void ConvertStringVectorToJS(napi_env env, const std::vector<std::string> &stringVector, napi_value result);
bool CheckAdminWithUserIdParamType(napi_env env, size_t argc, napi_value *argv, bool &hasCallback, bool &hasUserId);
bool CheckGetPolicyAdminParam(napi_env env, napi_value value, bool &hasAdmin,
    OHOS::AppExecFwk::ElementName &elementName);
bool ParseStringToInt(const std::string &strValue, int32_t &result);
bool ParseStringToLong(const std::string &strValue, int64_t &result);
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_KITS_COMMON_INCLUDE_NAPI_EDM_COMMON_ADDON_H
