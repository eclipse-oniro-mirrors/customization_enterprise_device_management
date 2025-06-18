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

#include <unordered_map>
#include "edm_ani_utils.h"
#include "edm_errors.h"
#include "edm_log.h"

using namespace OHOS;
using namespace EDM;

const std::unordered_map<int32_t, std::string> EdmAniUtils::errMessageMap = {
    {EdmReturnErrCode::PERMISSION_DENIED,
        "Permission verification failed. The application does not have the permission required to call the API."},
    {EdmReturnErrCode::SYSTEM_ABNORMALLY, "The system ability works abnormally."},
    {EdmReturnErrCode::ENABLE_ADMIN_FAILED, "Failed to activate the administrator application of the device."},
    {EdmReturnErrCode::COMPONENT_INVALID, "The administrator ability component is invalid."},
    {EdmReturnErrCode::ADMIN_INACTIVE, "The application is not an administrator application of the device."},
    {EdmReturnErrCode::DISABLE_ADMIN_FAILED, "Failed to deactivate the administrator application of the device."},
    {EdmReturnErrCode::UID_INVALID, "The specified user ID is invalid."},
    {EdmReturnErrCode::INTERFACE_UNSUPPORTED,
        "Capability not supported. Failed to call the API due to limited device capabilities."},
    {EdmReturnErrCode::PARAM_ERROR, "Parameter error."},
    {EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED,
        "The administrator application does not have permission to manage the device."},
    {EdmReturnErrCode::MANAGED_EVENTS_INVALID, "The specified system event is invalid."},
    {EdmReturnErrCode::SYSTEM_API_DENIED,
        "Permission verification failed. A non-system application calls a system API."},
    {EdmReturnErrCode::MANAGED_CERTIFICATE_FAILED, "Failed to manage the certificate. $."},
    {EdmReturnErrCode::AUTHORIZE_PERMISSION_FAILED, "Failed to grant the permission to the application."},
    {EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED, "A conflict policy has been configured."},
    {EdmReturnErrCode::APPLICATION_INSTALL_FAILED, "Failed to install the application. $."},
    {EdmReturnErrCode::ADD_OS_ACCOUNT_FAILED, "Failed to add an OS account."},
    {EdmReturnErrCode::UPGRADE_PACKAGES_ANALYZE_FAILED, "the upgrade packages do not exist or analyzing failed, $."},
    {EdmReturnErrCode::ADD_KEEP_ALIVE_APP_FAILED, "Add keep alive applications failed. $."},
    {EdmReturnErrCode::REPLACE_ADMIN_FAILED, "Replace admin failed. $."},
};

std::string EdmAniUtils::FindErrMsg(int32_t errCode)
{
    auto iter = errMessageMap.find(errCode);
    std::string errMsg = iter != errMessageMap.end() ? iter->second : "";
    return errMsg;
}

ani_object EdmAniUtils::WrapError(ani_env *env, const std::string &msg)
{
    ani_class cls {};
    ani_method method {};
    ani_object obj = nullptr;
    ani_status status = ANI_ERROR;
    if (env == nullptr) {
        EDMLOGE("null env");
        return nullptr;
    }

    ani_string aniMsg = nullptr;
    if ((status = env->String_NewUTF8(msg.c_str(), msg.size(), &aniMsg)) != ANI_OK) {
        EDMLOGE("String_NewUTF8 failed %{public}d", status);
        return nullptr;
    }

    ani_ref undefRef;
    if ((status = env->GetUndefined(&undefRef)) != ANI_OK) {
        EDMLOGE("GetUndefined failed %{public}d", status);
        return nullptr;
    }

    if ((status = env->FindClass("Lescompat/Error;", &cls)) != ANI_OK) {
        EDMLOGE("FindClass failed %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", "Lstd/core/String;Lescompat/ErrorOptions;:V", &method)) !=
        ANI_OK) {
        EDMLOGE("Class_FindMethod failed %{public}d", status);
        return nullptr;
    }

    if ((status = env->Object_New(cls, method, &obj, aniMsg, undefRef)) != ANI_OK) {
        EDMLOGE("Object_New failed %{public}d", status);
        return nullptr;
    }
    return obj;
}

ani_object EdmAniUtils::CreateError(ani_env *env, ani_int code, const std::string &msg)
{
    ani_class cls {};
    ani_method method {};
    ani_object obj = nullptr;
    ani_status status = ANI_ERROR;
    if (env == nullptr) {
        EDMLOGE("null env");
        return nullptr;
    }
    if ((status = env->FindClass("L@ohos/base/BusinessError;", &cls)) != ANI_OK) {
        EDMLOGE("FindClass failed %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", "DLescompat/Error;:V", &method)) != ANI_OK) {
        EDMLOGE("Class_FindMethod failed %{public}d", status);
        return nullptr;
    }
    ani_object error = WrapError(env, msg);
    if (error == nullptr) {
        EDMLOGE("error null");
        return nullptr;
    }
    ani_double dCode(code);
    if ((status = env->Object_New(cls, method, &obj, dCode, error)) != ANI_OK) {
        EDMLOGE("Object_New failed %{public}d", status);
        return nullptr;
    }
    return obj;
}

void EdmAniUtils::AniThrow(ani_env *env, int32_t errCode)
{
    std::string errMsg = FindErrMsg(errCode);
    if (errMsg != "") {
        AniThrow(env, errCode, errMsg);
    }
}

void EdmAniUtils::AniThrow(ani_env *env, int32_t errCode, std::string errMsg)
{
    ani_object error = CreateError(env, errCode, errMsg);
    env->ThrowError(static_cast<ani_error>(error));
}

std::string EdmAniUtils::AniStrToString(ani_env *env, ani_ref aniStr)
{
    ani_string str = static_cast<ani_string>(aniStr);
    ani_size size = 0;
    env->String_GetUTF8Size(str, &size);

    std::string result;
    result.resize(size);
    ani_size written;
    env->String_GetUTF8(str, result.data(), size + 1, &written);
    return result;
}

ani_string EdmAniUtils::StringToAniStr(ani_env *env, const std::string &str)
{
    ani_string ret;
    if (ANI_OK != env->String_NewUTF8(str.c_str(), str.size(), &ret)) {
        EDMLOGE("Create ani string failed");
        return nullptr;
    }
    return ret;
}

bool EdmAniUtils::GetStringProperty(ani_env *env,  ani_object aniAdmin, const std::string &propertyName,
    std::string &property)
{
    ani_ref ret;
    if (ANI_OK != env->Object_GetPropertyByName_Ref(aniAdmin, propertyName.c_str(), &ret)) {
        EDMLOGE("Get property [%{public}s] failed", propertyName.c_str());
        return false;
    }
    if (ret == nullptr) {
        EDMLOGE("property [%{public}s] not set", propertyName.c_str());
        return false;
    }
    property = AniStrToString(env, static_cast<ani_string>(ret));
    return true;
}

bool EdmAniUtils::UnWrapAdmin(ani_env *env, ani_object aniAdmin, AppExecFwk::ElementName &admin)
{
    ani_boolean isUndefined;
    env->Reference_IsUndefined(aniAdmin, &isUndefined);
    if (isUndefined) {
        EDMLOGE("admin is undefined");
        return false;
    }
    std::string bundlName;
    if (!GetStringProperty(env, aniAdmin, "bundleName", bundlName)) {
        EDMLOGE("bundleName is null");
        return false;
    }
    std::string abilityName;
    if (!GetStringProperty(env, aniAdmin, "abilityName", abilityName)) {
        EDMLOGE("abilityName is null");
        return false;
    }
    admin.SetBundleName(bundlName);
    admin.SetAbilityName(abilityName);
    return true;
}

bool EdmAniUtils::SetNumberMember(ani_env *env, ani_object obj, const std::string &name, const ani_double value)
{
    static const char *className = "Lstd/core/Double;";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        EDMLOGE("Find class '%{public}s' failed", className);
        return false;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", "D:V", &ctor)) {
        EDMLOGE("Find method '<ctor>' failed");
        return false;
    }

    ani_object numberObj;
    if (ANI_OK != env->Object_New(cls, ctor, &numberObj, value)) {
        EDMLOGE("New object '%{public}s' failed", className);
        return false;
    }

    if (ANI_OK != env->Object_SetPropertyByName_Ref(obj, name.c_str(), numberObj)) {
        EDMLOGE("Set property '%{public}s' failed", name.c_str());
        return false;
    }
    return true;
}