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

#include "adminManager_ani.h"
#include "edm_ani_utils.h"
#include "edm_log.h"
#include "enterprise_device_mgr_proxy.h"

namespace OHOS {
namespace EDM {

static const char* NAMESPACE_NAME = "@ohos.enterprise.adminManager.adminManager";

ani_status AdminManagerAni::Init(ani_env* env)
{
    ani_namespace ns;
    if (ANI_OK != env->FindNamespace(NAMESPACE_NAME, &ns)) {
        EDMLOGE("Not found namespace %{public}s.", NAMESPACE_NAME);
        return ANI_ERROR;
    }
    std::array methods = {
        ani_native_function { "getEnterpriseInfoSync", nullptr, reinterpret_cast<void*>(GetEnterpriseInfoSync) },
        ani_native_function { "getSuperAdminSync", nullptr, reinterpret_cast<void*>(GetSuperAdminSync) },
    };
    if (ANI_OK != env->Namespace_BindNativeFunctions(ns, methods.data(), methods.size())) {
        EDMLOGE("Cannot bind native methods to namespace[%{public}s]", NAMESPACE_NAME);
        return ANI_ERROR;
    };
    return ANI_OK;
}

ani_object AdminManagerAni::GetEnterpriseInfoSync(ani_env* env, ani_object aniAdmin)
{
    EDMLOGI("ANI_GetEnterpriseInfoSync called");
    AppExecFwk::ElementName admin;
    if (!EdmAniUtils::UnWrapAdmin(env, aniAdmin, admin)) {
        EdmAniUtils::AniThrow(env, EdmReturnErrCode::PARAM_ERROR, "The admin parameter is invalid.");
        return nullptr;
    }

    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    EntInfo entInfo;
    ErrCode ret = proxy->GetEnterpriseInfo(admin, entInfo);
    if (ret != ERR_OK) {
        EdmAniUtils::AniThrow(env, ret);
        EDMLOGE("GetEnterpriseInfo fail errcode:%{public}d", ret);
        return nullptr;
    }

    const char *className = "@ohos.enterprise.adminManager.adminManager.EnterpriseInfoInner";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        EdmAniUtils::AniThrow(env, EdmReturnErrCode::PARAM_ERROR);
        EDMLOGE("Find class '%{public}s' failed", className);
        return nullptr;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", "C{std.core.String}C{std.core.String}:", &ctor)) {
        EdmAniUtils::AniThrow(env, EdmReturnErrCode::PARAM_ERROR);
        EDMLOGE("Find method '<ctor>' failed");
        return nullptr;
    }

    ani_object aniEntInfo;
    if (ANI_OK != env->Object_New(cls, ctor, &aniEntInfo, EdmAniUtils::StringToAniStr(env, entInfo.enterpriseName),
    EdmAniUtils::StringToAniStr(env, entInfo.description))) {
        EDMLOGE("New object '%{public}s' failed", className);
        return nullptr;
    }
    return aniEntInfo;
}

ani_object AdminManagerAni::GetSuperAdminSync(ani_env* env)
{
    EDMLOGI("ANI_GetSuperAdminSync called");

    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    EntInfo entInfo;
    std::string bundleName;
    std::string abilityName;
    ErrCode ret = proxy->GetSuperAdmin(bundleName, abilityName);
    if (ret != ERR_OK) {
        EdmAniUtils::AniThrow(env, ret);
        EDMLOGE("GetSuperAdminSync fail errcode:%{public}d", ret);
        return nullptr;
    }

    const char *className = "@ohos.app.ability.Want.Want";
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

    ani_object aniWant;
    if (ANI_OK != env->Object_New(cls, ctor, &aniWant)) {
        EDMLOGE("New object '%{public}s' failed", className);
        return nullptr;
    }

    if (ANI_OK != env->Object_SetPropertyByName_Ref(aniWant, "bundleName",
    EdmAniUtils::StringToAniStr(env, bundleName))) {
        EDMLOGE("Set property 'bundleName' failed");
        return nullptr;
    }

    if (ANI_OK != env->Object_SetPropertyByName_Ref(aniWant, "abilityName",
    EdmAniUtils::StringToAniStr(env, abilityName))) {
        EDMLOGE("Set property 'abilityName' failed");
        return nullptr;
    }
    return aniWant;
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

    auto status = OHOS::EDM::AdminManagerAni::Init(env);
    if (status != ANI_OK) {
        return status;
    }
    *result = ANI_VERSION_1;
    return ANI_OK;
}
