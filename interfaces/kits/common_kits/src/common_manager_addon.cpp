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
#include "managed_policy.h"

using namespace OHOS::EDM;

napi_value CommonManagerAddon::Init(napi_env env, napi_value exports)
{
    napi_value nManagedPolicy = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nManagedPolicy));
    CreateManagedPolicyTypeObject(env, nManagedPolicy);

    napi_property_descriptor property[] = {
        DECLARE_NAPI_PROPERTY("ManagedPolicy", nManagedPolicy),
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
