/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "napi_edm_adapter.h"

#include <sstream>

#include "edm_constants.h"
#include "edm_log.h"
#include "napi_edm_common.h"
#include "napi_edm_error.h"

namespace OHOS {
namespace EDM {
namespace {
constexpr int32_t HAS_ADMIN = 0;
constexpr int32_t WITHOUT_ADMIN = 1;
constexpr int32_t WITHOUT_USERID = 0;
constexpr int32_t HAS_USERID = 1;
const std::u16string DESCRIPTOR = u"ohos.edm.IEnterpriseDeviceMgr";
}

static bool ElementNullArgToData(napi_env env, napi_value argv, MessageParcel &data,
    const AddonMethodSign &methodSign)
{
    if (methodSign.methodAttribute == MethodAttribute::GET) {
        data.WriteString(methodSign.apiVersionTag);
    }
    OHOS::AppExecFwk::ElementName elementName;
    bool isElement = ParseElementName(env, elementName, argv);
    bool isNull = MatchValueType(env, argv, napi_null);
    if (!isElement && !isNull) {
        return false;
    }
    if (isNull) {
        data.WriteInt32(WITHOUT_ADMIN);
    } else {
        data.WriteInt32(HAS_ADMIN);
        data.WriteParcelable(&elementName);
    }
    if (methodSign.methodAttribute == MethodAttribute::HANDLE) {
        data.WriteString(methodSign.apiVersionTag);
    }
    return true;
}

static bool ElementArgToData(napi_env env, napi_value argv, MessageParcel &data, const AddonMethodSign &methodSign)
{
    if (methodSign.methodAttribute == MethodAttribute::GET) {
        data.WriteString(methodSign.apiVersionTag);
    }
    OHOS::AppExecFwk::ElementName elementName;
    bool isElement = ParseElementName(env, elementName, argv);
    if (!isElement) {
        return false;
    }
    if (methodSign.methodAttribute == MethodAttribute::GET) {
        data.WriteInt32(HAS_ADMIN);
    }
    data.WriteParcelable(&elementName);
    if (methodSign.methodAttribute == MethodAttribute::HANDLE) {
        data.WriteString(methodSign.apiVersionTag);
    }
    return true;
}

static bool Uint32ArgToData(napi_env env, napi_value argv, MessageParcel &data, const AddonMethodSign &methodSign)
{
    uint32_t uintValue = 0;
    bool isUint = ParseUint(env, uintValue, argv);
    if (!isUint) {
        return false;
    }
    data.WriteUint32(uintValue);
    return true;
}

static bool StringArgToData(napi_env env, napi_value argv, MessageParcel &data, const AddonMethodSign &methodSign)
{
    std::string strValue;
    bool isString = ParseString(env, strValue, argv);
    if (!isString) {
        return false;
    }
    data.WriteString(strValue);
    return true;
}

static bool ArrayStringArgToData(napi_env env, napi_value argv, MessageParcel &data,
    const AddonMethodSign &methodSign)
{
    std::vector<std::string> strArrValue;
    bool isStringArr = ParseStringArray(env, strArrValue, argv);
    if (!isStringArr) {
        return false;
    }
    data.WriteStringVector(strArrValue);
    return true;
}

static bool BooleanArgToData(napi_env env, napi_value argv, MessageParcel &data, const AddonMethodSign &methodSign)
{
    bool blValue = false;
    bool isBool = ParseBool(env, blValue, argv);
    if (!isBool) {
        return false;
    }
    data.WriteBool(blValue);
    return true;
}

static bool Int32ArgToData(napi_env env, napi_value argv, MessageParcel &data, const AddonMethodSign &methodSign)
{
    int32_t int32Value = 0;
    bool isUint = ParseInt(env, int32Value, argv);
    if (!isUint) {
        return false;
    }
    data.WriteInt32(int32Value);
    return true;
}

static bool Int64ArgToData(napi_env env, napi_value argv, MessageParcel &data, const AddonMethodSign &methodSign)
{
    int64_t int64Value = 0;
    bool isUint = ParseLong(env, int64Value, argv);
    if (!isUint) {
        return false;
    }
    data.WriteInt64(int64Value);
    return true;
}

static bool UserIdArgToData(napi_env env, napi_value *argv, const AddonMethodSign &methodSign,
    MessageParcel &data, std::string &errorStr)
{
    auto it = std::find(methodSign.argsType.begin(), methodSign.argsType.end(), EdmAddonCommonType::USERID);
    if (it != methodSign.argsType.end()) {
        size_t index = it - methodSign.argsType.begin();
        JsArgToData argConvert = methodSign.argsConvert[index];
        std::ostringstream errorMsg;
        errorMsg << "The " << index << "th parameter must be number.";
        if (argConvert == nullptr) {
            uint32_t userIdValue = 0;
            bool isUint = ParseUint(env, userIdValue, argv[index]);
            if (!isUint) {
                errorStr = errorMsg.str();
                return false;
            }
            data.WriteUint32(HAS_USERID);
            data.WriteUint32(userIdValue);
        } else {
            bool convertResult = argConvert(env, argv[index], data, methodSign);
            if (!convertResult) {
                errorStr = errorMsg.str();
                return false;
            }
        }
    } else {
        if (methodSign.methodAttribute != MethodAttribute::NO_OPERATION) {
            data.WriteUint32(WITHOUT_USERID);
        }
    }
    return true;
}

static std::string EdmAddonCommonType2String(EdmAddonCommonType argType)
{
    switch (argType) {
        case EdmAddonCommonType::ELEMENT_NULL:
            return "want or null";
        case EdmAddonCommonType::ELEMENT:
            return "want";
        case EdmAddonCommonType::UINT32:
            return "number";
        case EdmAddonCommonType::STRING:
            return "string";
        case EdmAddonCommonType::ARRAY_STRING:
            return "string array";
        case EdmAddonCommonType::BOOLEAN:
            return "bool";
        case EdmAddonCommonType::INT32:
            return "number";
        case EdmAddonCommonType::CUSTOM:
            /* use custom convert */
            [[fallthrough]];
        default:
            return "object";
    }
}

static napi_value JsParamsToData(napi_env env, napi_value *argv, size_t argc,
    const AddonMethodSign &methodSign, MessageParcel &data)
{
    std::map<EdmAddonCommonType, JsArgToData> funcMap = {
        {EdmAddonCommonType::ELEMENT_NULL, ElementNullArgToData},
        {EdmAddonCommonType::ELEMENT, ElementArgToData},
        {EdmAddonCommonType::UINT32, Uint32ArgToData},
        {EdmAddonCommonType::STRING, StringArgToData},
        {EdmAddonCommonType::ARRAY_STRING, ArrayStringArgToData},
        {EdmAddonCommonType::BOOLEAN, BooleanArgToData},
        {EdmAddonCommonType::INT32, Int32ArgToData},
        {EdmAddonCommonType::INT64, Int64ArgToData}
    };

    for (size_t i = 0; i < methodSign.argsType.size(); i++) {
        // The value cannot exceed the actual length. Default parameters may exist.
        if (i >= argc) {
            break;
        }
        EdmAddonCommonType argType = methodSign.argsType[i];
        JsArgToData argConvert = nullptr;
        if (methodSign.argsConvert.size() > 0) {
            argConvert = methodSign.argsConvert[i];
        }
        std::ostringstream errorMsg;
        errorMsg << "The " << i << "th parameter must be ";
        errorMsg << EdmAddonCommonType2String(argType) << ".";
        if (argConvert == nullptr) {
            auto it = funcMap.find(argType);
            if (it == funcMap.end()) {
                continue;
            }
            bool res = it->second(env, argv[i], data, methodSign);
            if (!res) {
                return CreateError(env, EdmReturnErrCode::PARAM_ERROR, errorMsg.str());
            }
        } else {
            bool result = argConvert(env, argv[i], data, methodSign);
            if (!result) {
                return CreateError(env, EdmReturnErrCode::PARAM_ERROR, errorMsg.str());
            }
        }
    }
    return nullptr;
}

napi_value JsObjectToData(napi_env env, napi_callback_info info, const AddonMethodSign &methodSign,
    AdapterAddonData *addonData)
{
    napi_status status;
    size_t argc = ARGS_SIZE_FIVE;
    napi_value argv[ARGS_SIZE_FIVE];
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    // The size can meet the minimum length
    size_t minSize = methodSign.argsType.size() - methodSign.defaultArgSize;
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= minSize, "parameter count error");
    EDMLOGI("AddonMethodAdapter JsObjectToData argc:%{public}zu.", argc);
    if (argc > methodSign.argsType.size()) {
        bool isCallBack = MatchValueType(env, argv[methodSign.argsType.size()], napi_function);
        std::ostringstream errorMsg;
        /* If a callback exists, there must be no default parameter.
		overloading of callback and default parameter types cannot be supported. */
        errorMsg << "The " << methodSign.argsType.size() << "th parameter must be callback";
        ASSERT_AND_THROW_PARAM_ERROR(env, isCallBack, errorMsg.str());
    }
    if (!methodSign.argsType.empty() && !methodSign.argsConvert.empty() &&
        methodSign.argsType.size() != methodSign.argsConvert.size()) {
        napi_throw(env, CreateError(env, EdmReturnErrCode::PARAM_ERROR));
        return nullptr;
    }
    addonData->data.WriteInterfaceToken(DESCRIPTOR);

    std::string errorStr;
    bool convertUserIdRes = UserIdArgToData(env, argv, methodSign, addonData->data, errorStr);
    if (!convertUserIdRes) {
        napi_throw(env, CreateError(env, EdmReturnErrCode::PARAM_ERROR, errorStr));
        return nullptr;
    }

    napi_value errorRes = JsParamsToData(env, argv, argc, methodSign, addonData->data);
    if (errorRes != nullptr) {
        napi_throw(env, errorRes);
        return nullptr;
    }

    if (argc > methodSign.argsType.size()) {
        // Assign a value to callback
        status = napi_create_reference(env, argv[methodSign.argsType.size()], NAPI_RETURN_ONE, &addonData->callback);
        std::ostringstream errorMsg;
        errorMsg << "The " << methodSign.argsType.size() << "th parameter must be callback.";
        ASSERT_AND_THROW_PARAM_ERROR(env, status == napi_ok, errorMsg.str());
    }
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    EDMLOGI("AddonMethodAdapter %{public}s JsObjectToData exec success.", methodSign.name.c_str());
    addonData->policyCode = methodSign.policyCode;
    return result;
}

napi_value AddonMethodAdapter(napi_env env, napi_callback_info info, const AddonMethodSign &methodSign,
    napi_async_execute_callback execute, napi_async_complete_callback complete)
{
    auto adapterAddonData = new (std::nothrow) AdapterAddonData();
    if (adapterAddonData == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AdapterAddonData> adapterAddonDataPtr {adapterAddonData};
    napi_value result = JsObjectToData(env, info, methodSign, adapterAddonData);
    if (result == nullptr) {
        EDMLOGE("AddonMethodAdapter JsObjectToData exec fail.");
        return nullptr;
    }
    napi_value asyncWorkReturn = HandleAsyncWork(env, adapterAddonData, methodSign.name,
        execute, complete);
    adapterAddonDataPtr.release();
    return asyncWorkReturn;
}
} // namespace EDM
} // namespace OHOS