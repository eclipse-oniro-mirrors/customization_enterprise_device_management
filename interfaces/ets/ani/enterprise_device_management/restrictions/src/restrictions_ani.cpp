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

#include "restrictions_ani.h"
#include "edm_ani_utils.h"
#include "edm_log.h"
#include "restrictions_proxy.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"

namespace OHOS {
namespace EDM {

std::unordered_map<std::string, uint32_t> RestrictionsAni::labelCodeMapForAccount = {
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_FINGER_PRINT, EdmInterfaceCode::FINGERPRINT_AUTH},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_MTP_CLIENT, EdmInterfaceCode::DISABLE_USER_MTP_CLIENT},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_SUDO, EdmInterfaceCode::DISALLOWED_SUDO},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_DISTRIBUTED_TRANSMISSION,
        EdmInterfaceCode::DISALLOWED_DISTRIBUTED_TRANSMISSION},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_EXPORT_RECOVERY_KEY,
        EdmInterfaceCode::DISALLOWED_EXPORT_RECOVERY_KEY},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_USB_STORAGE_DEVICE_WRITE,
        EdmInterfaceCode::DISALLOWED_USB_STORAGE_DEVICE_WRITE},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_PRINT, EdmInterfaceCode::DISABLED_PRINT},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_OPEN_FILE_BOOST, EdmInterfaceCode::DISALLOWED_FILEBOOST_OPEN},
};

static const char* NAMESPACE_NAME = "@ohos.enterprise.restrictions.restrictions";

ani_status RestrictionsAni::Init(ani_env* env)
{
    ani_namespace ns;
    if (ANI_OK != env->FindNamespace(NAMESPACE_NAME, &ns)) {
        EDMLOGE("Not found namespace %{public}s.", NAMESPACE_NAME);
        return ANI_ERROR;
    }
    std::array methods = {
        ani_native_function { "setDisallowedPolicyForAccount", nullptr,
            reinterpret_cast<void*>(SetDisallowedPolicyForAccount) },
        ani_native_function { "getDisallowedPolicyForAccount", nullptr,
            reinterpret_cast<void*>(GetDisallowedPolicyForAccount) },
    };
    if (ANI_OK != env->Namespace_BindNativeFunctions(ns, methods.data(), methods.size())) {
        EDMLOGE("Cannot bind native methods to namespace[%{public}s]", NAMESPACE_NAME);
        return ANI_ERROR;
    };
    return ANI_OK;
}

void RestrictionsAni::SetDisallowedPolicyForAccount(ani_env* env, ani_object aniAdmin,
    ani_string feature, ani_boolean disallow, ani_double accountId)
{
    EDMLOGI("ANI_SetDisallowedPolicyForAccount called");
    AppExecFwk::ElementName admin;
    if (!EdmAniUtils::UnWrapAdmin(env, aniAdmin, admin)) {
        EdmAniUtils::AniThrow(env, EdmReturnErrCode::PARAM_ERROR, "The admin parameter is invalid.");
        return;
    }
    std::string featureStr;
    if (!EdmAniUtils::AniStringToString(env, feature, featureStr) || featureStr.empty()) {
        EdmAniUtils::AniThrow(env, EdmReturnErrCode::PARAM_ERROR, "The feature is empty.");
        return;
    }
    if (accountId < 0) {
        EdmAniUtils::AniThrow(env, EdmReturnErrCode::PARAM_ERROR, "The accountId is invalid.");
        return;
    }

    auto proxy = RestrictionsProxy::GetRestrictionsProxy();
    if (proxy == nullptr) {
        EdmAniUtils::AniThrow(env, EdmReturnErrCode::SYSTEM_ABNORMALLY, "GetRestrictionsProxy failed.");
        return;
    }
    auto labelCode = labelCodeMapForAccount.find(featureStr);
    if (labelCode == labelCodeMapForAccount.end()) {
        EdmAniUtils::AniThrow(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED, "The feature is invalid.");
        return;
    }

    std::uint32_t ipcCode = labelCode->second;
    std::string permissionTag = WITHOUT_PERMISSION_TAG;
    ErrCode ret = 0;

    if (ipcCode == EdmInterfaceCode::FINGERPRINT_AUTH) {
        ret = proxy->SetFingerprintAuthDisallowedPolicyForAccount(admin, disallow, ipcCode, permissionTag, accountId);
    } else {
        ret = proxy->SetDisallowedPolicyForAccount(admin, disallow, ipcCode, permissionTag, accountId);
    }

    if (FAILED(ret)) {
        EdmAniUtils::AniThrow(env, ret);
        EDMLOGE("SetDisallowedPolicyForAccount fail errcode:%{public}d", ret);
        return;
    }
}

ani_boolean RestrictionsAni::GetDisallowedPolicyForAccount(ani_env* env, ani_object aniAdmin,
    ani_string feature, ani_double accountId)
{
    EDMLOGI("ANI_GetDisallowedPolicyForAccount called");
    bool hasAdmin = false;
    AppExecFwk::ElementName admin;
    if (!EdmAniUtils::UnWrapAdmin(env, aniAdmin, admin, hasAdmin)) {
        EdmAniUtils::AniThrow(env, EdmReturnErrCode::PARAM_ERROR, "The admin parameter is invalid.");
        return false;
    }
    std::string featureStr;
    if (!EdmAniUtils::AniStringToString(env, feature, featureStr) || featureStr.empty()) {
        EdmAniUtils::AniThrow(env, EdmReturnErrCode::PARAM_ERROR, "The feature is empty.");
        return false;
    }
    if (accountId < 0) {
        EdmAniUtils::AniThrow(env, EdmReturnErrCode::PARAM_ERROR, "The accountId is invalid.");
        return false;
    }

    auto labelCode = labelCodeMapForAccount.find(featureStr);
    if (labelCode == labelCodeMapForAccount.end()) {
        EdmAniUtils::AniThrow(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED, "The feature is invalid.");
        return false;
    }
    std::uint32_t ipcCode = labelCode->second;
    bool disallow = false;
    ErrCode ret = NativeGetDisallowedPolicyForAccount(hasAdmin, admin, ipcCode, accountId, disallow);
    if (FAILED(ret)) {
        EdmAniUtils::AniThrow(env, ret);
        EDMLOGE("GetDisallowedPolicyForAccount fail errcode:%{public}d", ret);
        return false;
    }
    bool result = disallow ? ANI_TRUE : ANI_FALSE;
    return result;
}

OHOS::ErrCode RestrictionsAni::NativeGetDisallowedPolicyForAccount(bool hasAdmin,
    AppExecFwk::ElementName &elementName, std::uint32_t ipcCode, int32_t accountId, bool &disallow)
{
    std::string permissionTag = WITHOUT_PERMISSION_TAG;
    auto proxy = RestrictionsProxy::GetRestrictionsProxy();
    if (proxy == nullptr) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (ipcCode == EdmInterfaceCode::FINGERPRINT_AUTH) {
        if (hasAdmin) {
            return proxy->GetFingerprintAuthDisallowedPolicyForAccount(&elementName, ipcCode,
                disallow, permissionTag, accountId);
        } else {
            return proxy->GetFingerprintAuthDisallowedPolicyForAccount(nullptr, ipcCode,
                disallow, permissionTag, accountId);
        }
    } else {
        if (!hasAdmin) {
            return EdmReturnErrCode::PARAM_ERROR;
        }
        return proxy->GetDisallowedPolicyForAccount(elementName, ipcCode, disallow, permissionTag, accountId);
    }
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

    auto status = OHOS::EDM::RestrictionsAni::Init(env);
    if (status != ANI_OK) {
        return status;
    }
    *result = ANI_VERSION_1;
    return ANI_OK;
}
