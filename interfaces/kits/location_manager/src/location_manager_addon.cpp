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

#include "location_manager_addon.h"

#include "edm_constants.h"
#include "edm_log.h"

using namespace OHOS::EDM;

napi_value LocationManagerAddon::Init(napi_env env, napi_value exports)
{
    napi_value nLocationPolicy = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nLocationPolicy));
    CreateLocationPolicyObject(env, nLocationPolicy);

    napi_property_descriptor property[] = {
        DECLARE_NAPI_FUNCTION("setLocationPolicy", SetLocationPolicy),
        DECLARE_NAPI_FUNCTION("getLocationPolicy", GetLocationPolicy),
        DECLARE_NAPI_PROPERTY("LocationPolicy", nLocationPolicy),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(property) / sizeof(property[0]), property));
    return exports;
}

napi_value LocationManagerAddon::SetLocationPolicy(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_SetLocationPolicy called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter admin error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ONE], napi_number), "parameter type error");
    auto asyncCallbackInfo = new (std::nothrow) AsyncLocationPolicyInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncLocationPolicyInfo> callbackPtr{asyncCallbackInfo};
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    EDMLOGD(
        "SetLocationPolicy: asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->elementName.abilityname:%{public}s",
        asyncCallbackInfo->elementName.GetBundleName().c_str(),
        asyncCallbackInfo->elementName.GetAbilityName().c_str());
    int32_t policyInt;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, policyInt, argv[ARR_INDEX_ONE]), "element name param error");
    ASSERT_AND_THROW_PARAM_ERROR(env, IntToLocationPolicy(env, asyncCallbackInfo->locationPolicy, policyInt),
        "element name param error");
    EDMLOGD("SetLocationPolicy locationPolicy = %{public}d", asyncCallbackInfo->locationPolicy);
    asyncCallbackInfo->ret = LocationManagerProxy::GetLocationManagerProxy()->SetLocationPolicy(
        asyncCallbackInfo->elementName, asyncCallbackInfo->locationPolicy);
    if (FAILED(asyncCallbackInfo->ret)) {
        napi_throw(env, CreateError(env, asyncCallbackInfo->ret));
        EDMLOGE("SetLocationPolicy failed!");
    }
    return nullptr;
}

napi_value LocationManagerAddon::GetLocationPolicy(napi_env env, napi_callback_info info)
{
{
    EDMLOGI("NAPI_GetLocationPolicy called");
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    bool hasAdmin = false;
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, CheckGetPolicyAdminParam(env, argv[ARR_INDEX_ZERO], hasAdmin, elementName),
        "param admin need be null or want");
    LocationPolicy res = LocationPolicy::DEFAULT_LOCATION_SERVICE;;
    auto locationManagerProxy = LocationManagerProxy::GetLocationManagerProxy();
    int32_t ret = ERR_OK;
    if (hasAdmin) {
        ret = locationManagerProxy->GetLocationPolicy(&elementName, res);
    } else {
        ret = locationManagerProxy->GetLocationPolicy(nullptr, res);
    }
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    napi_value locationPolicy;
    napi_create_int32(env, static_cast<int32_t>(res), &locationPolicy);
    return locationPolicy;
}
}

bool LocationManagerAddon::IntToLocationPolicy(napi_env env, LocationPolicy &param, int32_t policy)
{
    if (policy >= static_cast<int32_t>(LocationPolicy::DEFAULT_LOCATION_SERVICE) &&
        policy <= static_cast<int32_t>(LocationPolicy::FORCE_OPEN_LOCATION_SERVICE)) {
        param = LocationPolicy(policy);
        return true;
    }
    return false;
}

void LocationManagerAddon::CreateLocationPolicyObject(napi_env env, napi_value value)
{
    napi_value nDisallowedLocation;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env,
        static_cast<uint32_t>(LocationPolicy::DISALLOW_LOCATION_SERVICE), &nDisallowedLocation));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "DISALLOW_LOCATION_SERVICE", nDisallowedLocation));
    napi_value nForceOpenLocation;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env,
        static_cast<uint32_t>(LocationPolicy::FORCE_OPEN_LOCATION_SERVICE), &nForceOpenLocation));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "FORCE_OPEN_LOCATION_SERVICE", nForceOpenLocation));
    napi_value nDefaultLocation;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_uint32(env, static_cast<uint32_t>(LocationPolicy::DEFAULT_LOCATION_SERVICE), &nDefaultLocation));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "DEFAULT_LOCATION_SERVICE", nDefaultLocation));
}

static napi_module g_locationModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = LocationManagerAddon::Init,
    .nm_modname = "enterprise.locationManager",
    .nm_priv = ((void *)0),
    .reserved = {0},
};

extern "C" __attribute__((constructor)) void LocationManagerRegister()
{
    napi_module_register(&g_locationModule);
}
