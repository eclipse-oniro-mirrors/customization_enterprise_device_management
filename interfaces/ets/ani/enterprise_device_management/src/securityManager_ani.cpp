/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "securityManager_ani.h"
#include "edm_ani_utils.h"
#include "edm_log.h"
#include "security_manager_proxy.h"

namespace OHOS {
namespace EDM {

static const char* NAMESPACE_NAME = "@ohos.enterprise.securityManager.securityManager";

ani_status SecurityManagerAni::Init(ani_env* env)
{
    ani_namespace ns;
    if (ANI_OK != env->FindNamespace(NAMESPACE_NAME, &ns)) {
        EDMLOGE("Not found namespace %{public}s.", NAMESPACE_NAME);
        return ANI_ERROR;
    }
    std::array methods = {
        ani_native_function { "getPasswordPolicy", nullptr, reinterpret_cast<void*>(GetPasswordPolicy) },
    };
    if (ANI_OK != env->Namespace_BindNativeFunctions(ns, methods.data(), methods.size())) {
        EDMLOGE("Cannot bind native methods to namespace[%{public}s]", NAMESPACE_NAME);
        return ANI_ERROR;
    };
    return ANI_OK;
}

ani_object SecurityManagerAni::GetPasswordPolicy(ani_env* env)
{
    EDMLOGI("ANI_GetPasswordPolicy called");
    PasswordPolicy policy;
    int32_t ret = SecurityManagerProxy::GetSecurityManagerProxy()->GetPasswordPolicy(policy);
    if (ret != ERR_OK) {
        EdmAniUtils::AniThrow(env, ret);
        EDMLOGE("GetPasswordPolicy fail errcode:%{public}d.", ret);
        return nullptr;
    }

    const char *className = "@ohos.enterprise.securityManager.securityManager.PasswordPolicyInner";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        EdmAniUtils::AniThrow(env, EdmReturnErrCode::PARAM_ERROR);
        EDMLOGE("Find class '%{public}s' failed", className);
        return nullptr;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", nullptr, &ctor)) {
        EdmAniUtils::AniThrow(env, EdmReturnErrCode::PARAM_ERROR);
        EDMLOGE("Find method '<ctor>' failed");
        return nullptr;
    }

    ani_object aniPasswordPolicy;
    if (ANI_OK != env->Object_New(cls, ctor, &aniPasswordPolicy)) {
        EDMLOGE("New object '%{public}s' failed", className);
        return nullptr;
    }

    if (ANI_OK != env->Object_SetPropertyByName_Ref(aniPasswordPolicy, "complexityRegex",
    EdmAniUtils::StringToAniStr(env, policy.complexityReg))) {
        EDMLOGW("Set property 'complexityRegex' failed");
    }

    if (!EdmAniUtils::SetNumberMember(env, aniPasswordPolicy, "validityPeriod", policy.validityPeriod)) {
        EDMLOGW("Set property 'validityPeriod' failed");
    }

    if (ANI_OK != env->Object_SetPropertyByName_Ref(aniPasswordPolicy, "additionalDescription",
    EdmAniUtils::StringToAniStr(env, policy.additionalDescription))) {
        EDMLOGW("Set property 'additionalDescription' failed");
    }
    return aniPasswordPolicy;
}
} // namespace EDM
} // namespace OHOS

ANI_EXPORT ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
{
    ani_env* env;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        EDMLOGE("Unsupported ANI_VERSION_1.");
        return (ani_status)ANI_ERROR;
    }

    auto status = OHOS::EDM::SecurityManagerAni::Init(env);
    if (status != ANI_OK) {
        return status;
    }
    *result = ANI_VERSION_1;
    return ANI_OK;
}
