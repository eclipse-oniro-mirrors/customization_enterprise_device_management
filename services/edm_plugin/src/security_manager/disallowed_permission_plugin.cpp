/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "disallowed_permission_plugin.h"

#include "accesstoken_kit.h"
#include "access_token_error.h"
#include "allowed_permission_bundle_serializer.h"
#include "array_string_serializer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "func_code_utils.h"
#include "iplugin_manager.h"
#include "ipolicy_manager.h"
#include "permission_def.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT =
    IPluginManager::GetInstance()->AddPlugin(DisallowedPermissionPlugin::GetPlugin());

void DisallowedPermissionPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<DisallowedPermissionPlugin, std::vector<std::string>>> ptr)
{
    EDMLOGI("DisallowedPermissionPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::DISALLOWED_PERMISSION, PolicyName::POLICY_DISALLOWED_PERMISSION,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(ArrayStringSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisallowedPermissionPlugin::OnBasicSetPolicy, FuncOperateType::SET);
    ptr->SetOnHandlePolicyListener(&DisallowedPermissionPlugin::OnBasicRemovePolicy, FuncOperateType::REMOVE);
    ptr->SetOnAdminRemoveListener(&DisallowedPermissionPlugin::OnBasicAdminRemove);
    maxListSize_ = EdmConstants::APPID_MAX_SIZE;
    overMaxReturnErrCode_ = EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
}

ErrCode DisallowedPermissionPlugin::SetOtherModulePolicy(const std::vector<std::string> &data, int32_t userId,
    std::vector<std::string> &failedData)
{
    EDMLOGI("DisallowedPermissionPlugin SetOtherModulePolicy");
    return AddOrRemoveAccessTokenPolicy(data, userId, true);
}

ErrCode DisallowedPermissionPlugin::RemoveOtherModulePolicy(const std::vector<std::string> &data, int32_t userId,
    std::vector<std::string> &failedData)
{
    EDMLOGI("DisallowedPermissionPlugin RemoveOtherModulePolicy");
    ErrCode rel = AddOrRemoveAccessTokenPolicy(data, userId, false);
    if (FAILED(rel)) {
        EDMLOGE("DisallowedPermissionPlugin AddOrRemoveAccessTokenPolicy failed.");
        return rel;
    }
    for (const std::string &permissionName : data) {
        EDMLOGI("DisallowedPermissionPlugin RemoveOtherModulePolicy clean %{public}s whitelist",
            permissionName.c_str());
        std::string combinePolicy = GetCombinedPolicy(permissionName, userId);
        ErrCode retAdmin = CleanAdminAllowedPermissionBundle(permissionName, userId, combinePolicy);
        if (FAILED(retAdmin)) {
            EDMLOGE("DisallowedPermissionPlugin CleanAllowedPermissionBundle %{public}s failed",
                permissionName.c_str());
        }
    }
    return ERR_OK;
}

ErrCode DisallowedPermissionPlugin::AddOrRemoveAccessTokenPolicy(const std::vector<std::string> &data,
    int32_t userId, bool isAdd)
{
    if (data.size() != 1) {
        EDMLOGI("DisallowedPermissionPlugin AddOrRemoveAccessTokenPolicy input param size error");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    std::string permission = data[0];
    if (permission.empty()) {
        EDMLOGI("DisallowedPermissionPlugin AddOrRemoveAccessTokenPolicy permission empty error");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    Security::AccessToken::PermissionDef permissionDef;
    ErrCode perReturn = Security::AccessToken::AccessTokenKit::GetDefPermission(permission, permissionDef);
    if (FAILED(perReturn)) {
        EDMLOGI("DisallowedPermissionPlugin AddOrRemoveAccessTokenPolicy get permission def error");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    if (permissionDef.availableLevel != Security::AccessToken::TypeATokenAplEnum::APL_SYSTEM_BASIC
        && permissionDef.availableLevel != Security::AccessToken::TypeATokenAplEnum::APL_NORMAL) {
        EDMLOGI("DisallowedPermissionPlugin AddOrRemoveAccessTokenPolicy invalide permission apl level");
        return EdmReturnErrCode::CANNOT_DISALLOW_PERMISSION;
    }
    Security::AccessToken::UserPolicy userPolicy;
    userPolicy.userId = userId;
    userPolicy.isRestricted = isAdd;

    Security::AccessToken::UserPermissionPolicy userPermissionPolicy;
    userPermissionPolicy.permissionName = permission;
    userPermissionPolicy.isPersist = true;
    userPermissionPolicy.userPolicyList.emplace_back(userPolicy);

    std::vector<Security::AccessToken::UserPermissionPolicy> userPermissionPolicys;
    userPermissionPolicys.emplace_back(userPermissionPolicy);
    ErrCode setRet = Security::AccessToken::AccessTokenKit::SetUserPolicy(userPermissionPolicys);
    if (FAILED(setRet)) {
        EDMLOGI("DisallowedPermissionPlugin SetUserPolicy failed ret %{public}d", setRet);
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    return ERR_OK;
}

std::string DisallowedPermissionPlugin::GetCombinedPolicy(const std::string &permissionName, int32_t userId)
{
    std::string allowedPolicy;
    IPolicyManager::GetInstance()->GetPolicy("", PolicyName::POLICY_ALLOWED_PERMISSION_BUNDLE,
        allowedPolicy, userId);
    if (allowedPolicy.empty()) {
        EDMLOGI("DisallowedPermissionPlugin CleanAllowedPermissionBundle policy is empty");
        return "";
    }

    std::map<std::string, std::vector<ApplicationInstance>> policyMap;
    AllowedPermissionBundleSerializer::GetInstance()->Deserialize(allowedPolicy, policyMap);

    auto it = policyMap.find(permissionName);
    if (it == policyMap.end()) {
        EDMLOGI("DisallowedPermissionPlugin CleanAllowedPermissionBundle %{public}s not in whitelist",
            permissionName.c_str());
    } else {
        policyMap.erase(it);
    }
    std::string updatedPolicy;
    AllowedPermissionBundleSerializer::GetInstance()->Serialize(policyMap, updatedPolicy);
    return updatedPolicy;
}

ErrCode DisallowedPermissionPlugin::CleanAdminAllowedPermissionBundle(const std::string &permissionName,
    int32_t userId, const std::string &combinePolicy)
{
    EDMLOGI("DisallowedPermissionPlugin CleanAllowedPermissionBundle permissionName=%{public}s userId=%{public}d",
        permissionName.c_str(), userId);
    auto policyManager = IPolicyManager::GetInstance();
    // key = admin name, vlaue = admin value
    std::unordered_map<std::string, std::string> adminListMap;
    ErrCode ret = policyManager->GetAdminByPolicyName(PolicyName::POLICY_ALLOWED_PERMISSION_BUNDLE,
        adminListMap, userId);
    if (ret != ERR_OK || adminListMap.empty()) {
        EDMLOGI("DisallowedPermissionPlugin CleanAllowedPermissionBundle no admin policy to clear");
        return ERR_OK;
    }
    for (const auto &admin : adminListMap) {
        std::string adminPolicy = admin.second;
        if (adminPolicy.empty()) {
            continue;
        }
        std::map<std::string, std::vector<ApplicationInstance>> policyMap;
        AllowedPermissionBundleSerializer::GetInstance()->Deserialize(adminPolicy, policyMap);
        auto it = policyMap.find(permissionName);
        if (it == policyMap.end()) {
            continue;
        }
        policyMap.erase(it);
        std::string updatedPolicy;
        AllowedPermissionBundleSerializer::GetInstance()->Serialize(policyMap, updatedPolicy);
        EDMLOGI("DisallowedPermissionPlugin CleanAllowedPermissionBundle clear admin=%{public}s permission=%{public}s",
            admin.first.c_str(), permissionName.c_str());
        ErrCode retSet = policyManager->SetPolicy(admin.first, PolicyName::POLICY_ALLOWED_PERMISSION_BUNDLE,
            updatedPolicy, combinePolicy, userId);
        if (FAILED(retSet)) {
            EDMLOGW("DisallowedPermissionPlugin clear admin policyfailed: %{public}d %{public}s",
                retSet, admin.first.c_str());
        }
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS