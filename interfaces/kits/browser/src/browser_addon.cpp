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

#include "browser_addon.h"

#include "browser_proxy.h"
#include "cJSON.h"
#include "edm_constants.h"
#include "edm_log.h"
#include "napi_edm_adapter.h"
#include "securec.h"

using namespace OHOS::EDM;

napi_value BrowserAddon::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor property[] = {
        DECLARE_NAPI_FUNCTION("setPolicies", SetPolicies),
        DECLARE_NAPI_FUNCTION("getPolicies", GetPolicies),
        DECLARE_NAPI_FUNCTION("setPolicySync", SetPolicy),
        DECLARE_NAPI_FUNCTION("getPoliciesSync", GetPoliciesSync),
        DECLARE_NAPI_FUNCTION("setManagedBrowserPolicy", SetManagedBrowserPolicy),
        DECLARE_NAPI_FUNCTION("getManagedBrowserPolicy", GetManagedBrowserPolicy),
        DECLARE_NAPI_FUNCTION("getSelfManagedBrowserPolicyVersion", GetSelfManagedBrowserPolicyVersion),
        DECLARE_NAPI_FUNCTION("getSelfManagedBrowserPolicy", GetSelfManagedBrowserPolicy),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(property) / sizeof(property[0]), property));
    return exports;
}

napi_value BrowserAddon::SetPolicies(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_SetPolicies called");
    auto asyncCallbackInfo = new (std::nothrow) AsyncBrowserCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncBrowserCallbackInfo> callbackPtr{asyncCallbackInfo};
    napi_value ret = SetPolicyCommon(env, info, asyncCallbackInfo);
    int32_t errCode = -1;
    NAPI_CALL(env, napi_get_value_int32(env, ret, &errCode));
    if (ret == nullptr || errCode != ERR_OK) {
        return nullptr;
    }
    if (asyncCallbackInfo->value != nullptr) {
        ASSERT_AND_THROW_PARAM_ERROR(env,
            MatchValueType(env, asyncCallbackInfo->value, napi_function), "Parameter callback error");
        NAPI_CALL(env,
            napi_create_reference(env, asyncCallbackInfo->value, NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
    }
    napi_value asyncWorkReturn =
        HandleAsyncWork(env, asyncCallbackInfo, "setPolicies", NativeSetPolicies, NativeVoidCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

void BrowserAddon::NativeSetPolicies(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeSetPolicies called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    std::string empty;
    AsyncBrowserCallbackInfo *asyncCallbackInfo = static_cast<AsyncBrowserCallbackInfo *>(data);
    asyncCallbackInfo->ret = BrowserProxy::GetBrowserProxy()->SetPolicy(asyncCallbackInfo->elementName,
        asyncCallbackInfo->appId, empty, asyncCallbackInfo->policies);
}

napi_value BrowserAddon::GetPolicies(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetPolicies called");
    auto asyncCallbackInfo = new (std::nothrow) AsyncBrowserCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncBrowserCallbackInfo> callbackPtr{asyncCallbackInfo};
    napi_value ret = GetPoliciesCommon(env, info, asyncCallbackInfo);
    int32_t errCode = -1;
    NAPI_CALL(env, napi_get_value_int32(env, ret, &errCode));
    if (ret == nullptr || errCode != ERR_OK) {
        return nullptr;
    }
    if (asyncCallbackInfo->value != nullptr) {
        ASSERT_AND_THROW_PARAM_ERROR(env,
            MatchValueType(env, asyncCallbackInfo->value, napi_function), "Parameter callback error");
        NAPI_CALL(env,
            napi_create_reference(env, asyncCallbackInfo->value, NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
    }
    napi_value asyncWorkReturn =
        HandleAsyncWork(env, asyncCallbackInfo, "getPolicies", NativeGetPolicies, NativeStringCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

void BrowserAddon::NativeGetPolicies(napi_env env, void *data)
{
    EDMLOGI("NativeGetPolicies called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncBrowserCallbackInfo *asyncCallbackInfo = static_cast<AsyncBrowserCallbackInfo *>(data);
    asyncCallbackInfo->ret = BrowserProxy::GetBrowserProxy()->GetPolicies(asyncCallbackInfo->elementName,
        asyncCallbackInfo->appId, asyncCallbackInfo->stringRet);
}

napi_value BrowserAddon::SetPolicy(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_SetPolicy called");
    std::string policyValue;
    auto asyncCallbackInfo = new (std::nothrow) AsyncBrowserCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncBrowserCallbackInfo> callbackPtr{asyncCallbackInfo};
    napi_value ret = SetPolicyCommon(env, info, asyncCallbackInfo);
    int32_t errCode = -1;
    NAPI_CALL(env, napi_get_value_int32(env, ret, &errCode));
    if (ret == nullptr || errCode != ERR_OK) {
        return nullptr;
    }
    ASSERT_AND_THROW_PARAM_ERROR(env,
        ParseString(env, policyValue, asyncCallbackInfo->value), "Parameter policyValue error");

    int32_t retCode = BrowserProxy::GetBrowserProxy()->SetPolicy(asyncCallbackInfo->elementName,
        asyncCallbackInfo->appId, asyncCallbackInfo->policies, policyValue);
    if (FAILED(retCode)) {
        napi_throw(env, CreateError(env, retCode));
    }
    return nullptr;
}

napi_value BrowserAddon::GetPoliciesSync(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetPoliciesSync called");
    auto asyncCallbackInfo = new (std::nothrow) AsyncBrowserCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncBrowserCallbackInfo> callbackPtr{asyncCallbackInfo};
    napi_value ret = GetPoliciesCommon(env, info, asyncCallbackInfo);
    int32_t errCode = -1;
    NAPI_CALL(env, napi_get_value_int32(env, ret, &errCode));
    if (ret == nullptr || errCode != ERR_OK) {
        return nullptr;
    }
    std::string policies;
    int32_t retCode = BrowserProxy::GetBrowserProxy()->GetPolicies(asyncCallbackInfo->elementName,
        asyncCallbackInfo->appId, policies);
    if (FAILED(retCode)) {
        napi_throw(env, CreateError(env, retCode));
        return nullptr;
    }
    napi_value res;
    NAPI_CALL(env, napi_create_string_utf8(env, policies.c_str(), NAPI_AUTO_LENGTH, &res));
    return res;
}

napi_value BrowserAddon::SetManagedBrowserPolicy(napi_env env, napi_callback_info info)
{
    EDMLOGI("BrowserAddon::SetManagedBrowserPolicy start");
    auto convertPolicyValue = [](napi_env env, napi_value argv, MessageParcel &data,
        const AddonMethodSign &methodSign) {
        std::string policyValue;
        if (!ParseString(env, policyValue, argv)) {
            return false;
        }
        if (policyValue.empty()) {
            return true;
        }
        cJSON* root = cJSON_Parse(policyValue.c_str());
        if (root == nullptr) {
            return false;
        }
        cJSON_Delete(root);
        data.WriteString(policyValue);
        return true;
    };
    AddonMethodSign addonMethodSign;
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::STRING,
        EdmAddonCommonType::STRING, EdmAddonCommonType::CUSTOM};
    addonMethodSign.argsConvert = {nullptr, nullptr, nullptr, convertPolicyValue};
    addonMethodSign.methodAttribute = MethodAttribute::HANDLE;
    AdapterAddonData adapterAddonData{};
    if (JsObjectToData(env, info, addonMethodSign, &adapterAddonData) == nullptr) {
        napi_throw(env, CreateError(env, EdmReturnErrCode::SYSTEM_ABNORMALLY));
        return nullptr;
    }
    int32_t ret = BrowserProxy::GetBrowserProxy()->SetManagedBrowserPolicy(adapterAddonData.data);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
}

napi_value BrowserAddon::GetManagedBrowserPolicy(napi_env env, napi_callback_info info)
{
    EDMLOGI("BrowserAddon::GetManagedBrowserPolicy start");
    auto convertBundleNameWithType = [](napi_env env, napi_value argv, MessageParcel &data,
        const AddonMethodSign &methodSign) {
        std::string bundleName;
        if (!ParseString(env, bundleName, argv)) {
            return false;
        }
        data.WriteString(EdmConstants::Browser::GET_MANAGED_BROWSER_FILE_DATA);
        data.WriteString(bundleName);
        return true;
    };
    AddonMethodSign addonMethodSign;
    addonMethodSign.apiVersionTag = WITHOUT_PERMISSION_TAG;
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::CUSTOM};
    addonMethodSign.argsConvert = {nullptr, convertBundleNameWithType};
    AdapterAddonData adapterAddonData{};
    napi_value result = JsObjectToData(env, info, addonMethodSign, &adapterAddonData);
    if (result == nullptr) {
        napi_throw(env, CreateError(env, EdmReturnErrCode::SYSTEM_ABNORMALLY));
        return nullptr;
    }
    int32_t size = -1;
    void* data = nullptr;
    int32_t ret = BrowserProxy::GetBrowserProxy()->GetManagedBrowserPolicy(adapterAddonData.data, &data, size);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    return CreateArrayBuffer(env, data, size);
}

napi_value BrowserAddon::GetSelfManagedBrowserPolicyVersion(napi_env env, napi_callback_info info)
{
    EDMLOGI("BrowserAddon::GetManagedBrowserPolicy start");
    int32_t version = -1;
    int32_t ret = BrowserProxy::GetBrowserProxy()->GetSelfManagedBrowserPolicyVersion(version);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    if (version == -1) {
        napi_throw(env, CreateError(env, EdmReturnErrCode::SYSTEM_ABNORMALLY));
        return nullptr;
    }
    napi_value versionRet = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, std::to_string(version).c_str(), NAPI_AUTO_LENGTH, &versionRet));
    return versionRet;
}

napi_value BrowserAddon::GetSelfManagedBrowserPolicy(napi_env env, napi_callback_info info)
{
    EDMLOGI("BrowserAddon::GetSelfManagedBrowserPolicy start");
    int32_t size = -1;
    void* data = nullptr;
    int32_t ret = BrowserProxy::GetBrowserProxy()->GetSelfManagedBrowserPolicy(&data, size);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    return CreateArrayBuffer(env, data, size);
}

napi_value BrowserAddon::SetPolicyCommon(napi_env env, napi_callback_info info, AsyncBrowserCallbackInfo* callbackInfo)
{
    size_t argc = ARGS_SIZE_FOUR;
    napi_value argv[ARGS_SIZE_FOUR] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_THREE, "Parameter count error");
    bool matchFlag = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object) &&
        MatchValueType(env, argv[ARR_INDEX_ONE], napi_string) && MatchValueType(env, argv[ARR_INDEX_TWO], napi_string);

    ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter type error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, callbackInfo->elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseString(env, callbackInfo->appId, argv[ARR_INDEX_ONE]),
        "Parameter appId error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseString(env, callbackInfo->policies, argv[ARR_INDEX_TWO]),
        "Parameter policyName error");
    
    EDMLOGD(
        "setBrowserPolicy: elementName.bundlename %{public}s, "
        "elementName.abilityname:%{public}s",
        callbackInfo->elementName.GetBundleName().c_str(),
        callbackInfo->elementName.GetAbilityName().c_str());
    
    if (argc > ARGS_SIZE_THREE) {
        callbackInfo->value = argv[ARR_INDEX_THREE];
    }
    
    napi_value ret;
    NAPI_CALL(env, napi_create_int32(env, ERR_OK, &ret));
    return ret;
}

napi_value BrowserAddon::GetPoliciesCommon(napi_env env, napi_callback_info info,
    AsyncBrowserCallbackInfo* asyncCallbackInfo)
{
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "Parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "admin type error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ONE], napi_string), "appId type error");

    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]),
        "Parameter want error");
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseString(env, asyncCallbackInfo->appId, argv[ARR_INDEX_ONE]),
        "Parameter appId error");
    EDMLOGD(
        "GetPolicies::asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->abilityname:%{public}s",
        asyncCallbackInfo->elementName.GetBundleName().c_str(),
        asyncCallbackInfo->elementName.GetAbilityName().c_str());

    if (argc > ARGS_SIZE_TWO) {
        ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_TWO], napi_function),
            "callback type error");
        asyncCallbackInfo->value = argv[ARR_INDEX_TWO];
    }
    napi_value ret;
    NAPI_CALL(env, napi_create_int32(env, ERR_OK, &ret));
    return ret;
}

napi_value BrowserAddon::CreateArrayBuffer(napi_env env, void* data, int32_t size)
{
    if (data == nullptr) {
        EDMLOGE("BrowserAddon::CreateArrayBuffer data null");
        napi_throw(env, CreateError(env, EdmReturnErrCode::SYSTEM_ABNORMALLY));
        return nullptr;
    }
    if (size < 0 || size > MAX_POLICY_FILE_SIZE) {
        EDMLOGE("BrowserAddon::CreateArrayBuffer size error.size:%{public}d", size);
        napi_throw(env, CreateError(env, EdmReturnErrCode::SYSTEM_ABNORMALLY));
        return nullptr;
    }
    napi_value result = nullptr;
    void* arrayBufferData = nullptr;
    NAPI_CALL(env, napi_create_arraybuffer(env, size, &arrayBufferData, &result));
    if (arrayBufferData == nullptr) {
        EDMLOGE("BrowserAddon::CreateArrayBuffer arrayBufferData null");
        napi_throw(env, CreateError(env, EdmReturnErrCode::SYSTEM_ABNORMALLY));
        free(data);
        data = nullptr;
        return nullptr;
    }
    errno_t cpRet = memcpy_s(arrayBufferData, size, data, size);
    if (cpRet != EOK) {
        EDMLOGE("BrowserAddon::CreateArrayBuffer memcpy_s fail.errcode:%{public}d, size:%{public}d", cpRet, size);
        napi_throw(env, CreateError(env, EdmReturnErrCode::SYSTEM_ABNORMALLY));
        free(data);
        data = nullptr;
        return nullptr;
    }
    free(data);
    data = nullptr;
    return result;
}

static napi_module g_browserModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = BrowserAddon::Init,
    .nm_modname = "enterprise.browser",
    .nm_priv = ((void *)0),
    .reserved = {0},
};

extern "C" __attribute__((constructor)) void BrowserRegister()
{
    napi_module_register(&g_browserModule);
}