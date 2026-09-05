/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "common_manager_addon.h"

#include "edm_log.h"
#include "napi_edm_adapter.h"
#include "managed_feature.h"
#include "managed_policy.h"
#include "result.h"
#include "startup_scene.h"

using namespace OHOS::EDM;

napi_value CommonManagerAddon::Init(napi_env env, napi_value exports)
{
    napi_value nManagedPolicy = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nManagedPolicy));
    CreateManagedPolicyTypeObject(env, nManagedPolicy);
    napi_value nResult = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nResult));
    CreateResultObject(env, nResult);
    napi_value nStartupScene = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nStartupScene));
    CreateStartupSceneObject(env, nStartupScene);
    napi_value nManagedFeature = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nManagedFeature));
    CreateManagedFeatureObject(env, nManagedFeature);

    napi_property_descriptor property[] = {
        DECLARE_NAPI_FUNCTION("isFeatureSupported", IsFeatureSupported),
        DECLARE_NAPI_PROPERTY("ManagedPolicy", nManagedPolicy),
        DECLARE_NAPI_PROPERTY("Result", nResult),
        DECLARE_NAPI_PROPERTY("StartupScene", nStartupScene),
        DECLARE_NAPI_PROPERTY("ManagedFeature", nManagedFeature),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(property) / sizeof(property[0]), property));
    return exports;
}

void CommonManagerAddon::CreateManagedPolicyTypeObject(napi_env env, napi_value value)
{
    napi_value nDisallow;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env,
        static_cast<uint32_t>(ManagedPolicy::DISALLOW), &nDisallow));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "DISALLOW", nDisallow));
    napi_value nForceOpen;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env,
        static_cast<uint32_t>(ManagedPolicy::FORCE_OPEN), &nForceOpen));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "FORCE_OPEN", nForceOpen));
    napi_value nDefault;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_uint32(env, static_cast<uint32_t>(ManagedPolicy::DEFAULT), &nDefault));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "DEFAULT", nDefault));
}

void CommonManagerAddon::CreateResultObject(napi_env env, napi_value value)
{
    napi_value nSuccess;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env,
        static_cast<int32_t>(Result::SUCCESS), &nSuccess));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "SUCCESS", nSuccess));
    napi_value nFail;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env,
        static_cast<int32_t>(Result::FAIL), &nFail));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "FAIL", nFail));
}

void CommonManagerAddon::CreateStartupSceneObject(napi_env env, napi_value value)
{
    napi_value nUserSetup;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env,
        static_cast<int32_t>(StartupScene::USER_SETUP), &nUserSetup));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "USER_SETUP", nUserSetup));
    napi_value nOta;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env,
        static_cast<int32_t>(StartupScene::OTA), &nOta));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "OTA", nOta));
    napi_value nDeviceProvision;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env,
        static_cast<int32_t>(StartupScene::DEVICE_PROVISION), &nDeviceProvision));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "DEVICE_PROVISION", nDeviceProvision));
}

void CommonManagerAddon::CreateManagedFeatureObject(napi_env env, napi_value value)
{
    napi_value nLocalHotaDomain;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env,
        static_cast<uint32_t>(ManagedFeature::LOCAL_HOTA_DOMAIN), &nLocalHotaDomain));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "LOCAL_HOTA_DOMAIN", nLocalHotaDomain));
    napi_value nUserExtendCredential;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env,
        static_cast<uint32_t>(ManagedFeature::USER_EXTEND_CREDENTIAL), &nUserExtendCredential));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "USER_EXTEND_CREDENTIAL", nUserExtendCredential));
    napi_value nDeviceSecurityLevel;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env,
        static_cast<uint32_t>(ManagedFeature::DEVICE_SECURITY_LEVEL), &nDeviceSecurityLevel));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "DEVICE_SECURITY_LEVEL", nDeviceSecurityLevel));
    napi_value nPrinterIpAddressPolicy;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env,
        static_cast<uint32_t>(ManagedFeature::PRINTER_IP_ADDRESS_POLICY), &nPrinterIpAddressPolicy));
    NAPI_CALL_RETURN_VOID(env,
        napi_set_named_property(env, value, "PRINTER_IP_ADDRESS_POLICY", nPrinterIpAddressPolicy));
}

napi_value CommonManagerAddon::IsFeatureSupported(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_IsFeatureSupported called");
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR_AFTER_API24(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR_AFTER_API24(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_number),
        "parameter feature error");
    int32_t featureNumber = -1;
    ASSERT_AND_THROW_PARAM_ERROR_AFTER_API24(env, ParseInt(env, featureNumber, argv[ARR_INDEX_ZERO]),
        "parameter feature parse error");
    bool supported = CommonManagerProxy::GetCommonManagerProxy()->IsFeatureSupported(featureNumber);
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, supported, &result));
    return result;
}

static napi_module g_commonManagerServiceModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = CommonManagerAddon::Init,
    .nm_modname = "enterprise.common",
    .nm_priv = ((void *)0),
    .reserved = {0},
};

extern "C" __attribute__((constructor)) void CommonManagerServiceRegister()
{
    napi_module_register(&g_commonManagerServiceModule);
}
