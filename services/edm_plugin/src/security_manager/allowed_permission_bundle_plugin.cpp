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

#include "allowed_permission_bundle_plugin.h"

#include "accesstoken_kit.h"
#include "access_token_error.h"
#include "allowed_permission_bundle_serializer.h"
#include "array_string_serializer.h"
#include "edm_access_token_manager_impl.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "func_code_utils.h"
#include "iplugin_manager.h"
#include "ipolicy_manager.h"

namespace OHOS {
namespace EDM {

const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(
    std::make_shared<AllowedPermissionBundlePlugin>());

AllowedPermissionBundlePlugin::AllowedPermissionBundlePlugin()
{
    policyCode_ = EdmInterfaceCode::ALLOWED_PERMISSION_BUNDLE;
    policyName_ = PolicyName::POLICY_ALLOWED_PERMISSION_BUNDLE;
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY);
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = true;
}

ErrCode AllowedPermissionBundlePlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data,
    MessageParcel &reply, HandlePolicyData &policyData, int32_t userId)
{
    EDMLOGI("AllowedPermissionBundlePlugin OnHandlePolicy");

    PolicyOperationParams params;
    ErrCode ret = ReadParameters(data, params, funcCode);
    if (FAILED(ret)) {
        reply.WriteInt32(ret);
        return ret;
    }
    std::map<std::string, std::vector<ApplicationInstance>> currentData;
    std::map<std::string, std::vector<ApplicationInstance>> mergeData;
    ret = PreparePolicyData(policyData.policyData, policyData.mergePolicyData, params.type, currentData, mergeData);
    if (FAILED(ret)) {
        reply.WriteInt32(ret);
        return ret;
    }

    std::string mergePolicyStr;
    IPolicyManager::GetInstance()->GetPolicy("", GetPolicyName(), mergePolicyStr, userId);

    ret = ExecutePolicyOperation(params, currentData, mergeData);
    if (FAILED(ret)) {
        reply.WriteInt32(ret);
        return ret;
    }

    reply.WriteInt32(ERR_OK);
    UpdatePolicyResult(policyData, currentData, mergeData, mergePolicyStr);
    return ERR_OK;
}

ErrCode AllowedPermissionBundlePlugin::ReadParameters(MessageParcel &data, PolicyOperationParams &params,
    std::uint32_t funcCode)
{
    uint32_t typeCode = FUNC_TO_OPERATE(funcCode);
    params.type = FuncCodeUtils::ConvertOperateType(typeCode);

    std::string sceneTag;
    if (!data.ReadString(sceneTag)) {
        EDMLOGE("AllowedPermissionBundlePlugin ReadParameters read sceneTag failed");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    if (sceneTag == EdmConstants::SCENE_APP_UNINSTALL) {
        params.scene = PolicyScene::APP_UNINSTALL;
        EDMLOGI("AllowedPermissionBundlePlugin ReadParameters scene=APP_UNINSTALL");
    } else {
        params.scene = (params.type == FuncOperateType::SET) ? PolicyScene::POLICY_ADD : PolicyScene::POLICY_REMOVE;
    }

    if (!data.ReadString(params.permission)) {
        EDMLOGE("AllowedPermissionBundlePlugin ReadParameters read permission failed");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }

    if (!ApplicationInstanceHandle::ReadApplicationInstance(data, params.appInstance)) {
        EDMLOGE("AllowedPermissionBundlePlugin ReadParameters read ApplicationInstance failed");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }

    if (params.permission.empty() || params.appInstance.appIdentifier.empty()) {
        EDMLOGE("AllowedPermissionBundlePlugin ReadParameters invalid parameter");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }

    if (params.type == FuncOperateType::SET && params.scene != PolicyScene::APP_UNINSTALL) {
        if (!ApplicationInstanceHandle::GetBundleNameByAppId(params.appInstance)) {
            EDMLOGW("AllowedPermissionBundlePlugin ReadParameters GetBundleNameByAppId failed for %{public}s",
                params.appInstance.appIdentifier.c_str());
            return EdmReturnErrCode::DOCK_APP_NOT_INSTALLED;
        }
    }

    return ERR_OK;
}

ErrCode AllowedPermissionBundlePlugin::PreparePolicyData(const std::string &policyDataStr,
    const std::string &mergePolicyDataStr, FuncOperateType type,
    std::map<std::string, std::vector<ApplicationInstance>> &currentData,
    std::map<std::string, std::vector<ApplicationInstance>> &mergeData)
{
    auto serializer = AllowedPermissionBundleSerializer::GetInstance();
    serializer->Deserialize(policyDataStr, currentData);
    serializer->Deserialize(mergePolicyDataStr, mergeData);
    if (type == FuncOperateType::SET) {
        mergeData = serializer->SetUnionPolicyData(currentData, mergeData);
    }
    return ERR_OK;
}

ErrCode AllowedPermissionBundlePlugin::ExecutePolicyOperation(PolicyOperationParams &params,
    std::map<std::string, std::vector<ApplicationInstance>> &currentData,
    std::map<std::string, std::vector<ApplicationInstance>> &mergeData)
{
    if (params.type == FuncOperateType::SET) {
        return OnSetPolicy(params.permission, params.appInstance, currentData, mergeData);
    } else if (params.type == FuncOperateType::REMOVE) {
        return OnRemovePolicy(params.permission, params.appInstance, currentData, mergeData, params.scene);
    }
    return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
}

void AllowedPermissionBundlePlugin::UpdatePolicyResult(HandlePolicyData &policyData,
    const std::map<std::string, std::vector<ApplicationInstance>> &currentData,
    const std::map<std::string, std::vector<ApplicationInstance>> &mergeData,
    const std::string &mergePolicyStr)
{
    auto serializer = AllowedPermissionBundleSerializer::GetInstance();
    std::string afterHandle;
    std::string afterMerge;
    serializer->Serialize(currentData, afterHandle);
    serializer->Serialize(mergeData, afterMerge);

    policyData.isChanged = (policyData.policyData != afterHandle || mergePolicyStr != afterMerge);
    policyData.policyData = afterHandle;
    policyData.mergePolicyData = afterMerge;
}

ErrCode AllowedPermissionBundlePlugin::OnSetPolicy(const std::string &permission,
    const ApplicationInstance &appInstance,
    std::map<std::string, std::vector<ApplicationInstance>> &currentData,
    std::map<std::string, std::vector<ApplicationInstance>> &mergeData)
{
    EDMLOGI("AllowedPermissionBundlePlugin OnSetPolicy permission=%{public}s appIdentifier=%{public}s",
        permission.c_str(), appInstance.appIdentifier.c_str());
    ErrCode ret = CheckPermissionDisallowed(permission, appInstance.accountId);
    if (FAILED(ret)) {
        EDMLOGE("AllowedPermissionBundlePlugin OnSetPolicy permission not disallowed");
        return ret;
    }
    auto serializer = AllowedPermissionBundleSerializer::GetInstance();
    std::map<std::string, std::vector<ApplicationInstance>> newData;
    newData[permission] = {appInstance};
    std::map<std::string, std::vector<ApplicationInstance>> afterHandle =
        serializer->SetUnionPolicyData(newData, currentData);
    std::map<std::string, std::vector<ApplicationInstance>> afterMerge =
        serializer->SetUnionPolicyData(newData, mergeData);
    std::map<std::string, std::vector<ApplicationInstance>> needToAddPolicy;
    if (mergeData.find(permission) == mergeData.end()) {
        needToAddPolicy = newData;
    } else {
        std::vector<ApplicationInstance> existingApps = mergeData[permission];
        std::vector<ApplicationInstance> addedApps;
        for (const ApplicationInstance& newApp : newData[permission]) {
            if (!serializer->IsAppInList(newApp, existingApps)) {
                addedApps.push_back(newApp);
            }
        }
        if (!addedApps.empty()) {
            needToAddPolicy[permission] = addedApps;
        }
    }
    if (!needToAddPolicy.empty()) {
        ret = SetOtherModulePolicy(needToAddPolicy);
        if (FAILED(ret)) {
            EDMLOGE("AllowedPermissionBundlePlugin OnSetPolicy SetOtherModulePolicy fail");
            return ret;
        }
    }
    currentData = afterHandle;
    mergeData = afterMerge;
    return ERR_OK;
}

ErrCode AllowedPermissionBundlePlugin::CheckPermissionDisallowed(const std::string &permissionName, int32_t userId)
{
    std::string disallowedPolicy;
    IPolicyManager::GetInstance()->GetPolicy("", PolicyName::POLICY_DISALLOWED_PERMISSION,
        disallowedPolicy, userId);
    std::vector<std::string> disallowedPermissions;
    ArrayStringSerializer::GetInstance()->Deserialize(disallowedPolicy, disallowedPermissions);
    if (std::find(disallowedPermissions.begin(), disallowedPermissions.end(), permissionName) ==
        disallowedPermissions.end()) {
        EDMLOGE("AllowedPermissionBundlePlugin CheckPermissionDisallowed %{public}s not in disallowed list",
            permissionName.c_str());
        return EdmReturnErrCode::CANNOT_SET_ALLOWED_PERMISSION_BUNDLE;
    }
    return ERR_OK;
}

ErrCode AllowedPermissionBundlePlugin::OnRemovePolicy(const std::string &permission,
    const ApplicationInstance &appInstance,
    std::map<std::string, std::vector<ApplicationInstance>> &currentData,
    std::map<std::string, std::vector<ApplicationInstance>> &mergeData, PolicyScene scene)
{
    EDMLOGI("AllowedPermissionBundlePlugin RemovePolicy perm=%{public}s appIdentifier=%{public}s scene=%{public}d",
        permission.c_str(), appInstance.appIdentifier.c_str(), static_cast<int>(scene));
    ErrCode checkRet = CheckPermissionDisallowed(permission, appInstance.accountId);
    if (FAILED(checkRet)) {
        EDMLOGE("AllowedPermissionBundlePlugin OnSetPolicy permission not disallowed");
        return checkRet;
    }
    auto serializer = AllowedPermissionBundleSerializer::GetInstance();
    std::map<std::string, std::vector<ApplicationInstance>> dataToRemove;
    dataToRemove[permission] = {appInstance};
    std::map<std::string, std::vector<ApplicationInstance>> needRemovePolicy =
        serializer->SetIntersectionPolicyData(dataToRemove, currentData);

    if (needRemovePolicy.find(permission) == needRemovePolicy.end() ||
        needRemovePolicy[permission].empty()) {
        EDMLOGE("AllowedPermissionBundlePlugin OnRemovePolicy app not in current data");
        return ERR_OK;
    }

    std::map<std::string, std::vector<ApplicationInstance>> needRemoveMergePolicy =
        serializer->SetNeedRemoveMergePolicyData(mergeData, needRemovePolicy);
    std::map<std::string, std::vector<ApplicationInstance>> needResetPolicy =
        serializer->SetDifferencePolicyData(dataToRemove, currentData);
    if (!needRemoveMergePolicy.empty()) {
        ErrCode ret = RemoveOtherModulePolicy(needRemoveMergePolicy, scene);
        if (FAILED(ret)) {
            EDMLOGE("AllowedPermissionBundlePlugin OnRemovePolicy RemoveOtherModulePolicy fail");
            return ret;
        }
    }
    currentData = needResetPolicy;
    mergeData = serializer->SetUnionPolicyData(currentData, mergeData);
    return ERR_OK;
}

ErrCode AllowedPermissionBundlePlugin::SetOtherModulePolicy(
    const std::map<std::string, std::vector<ApplicationInstance>> &policyData)
{
    EDMLOGI("AllowedPermissionBundlePlugin SetOtherModulePolicy");
    ErrCode ret = UpdatePolicyWhiteList(policyData, PolicyScene::POLICY_ADD);
    if (ret == Security::AccessToken::AccessTokenError::ERR_PERM_POLICY_NOT_SET) {
        return EdmReturnErrCode::CANNOT_SET_ALLOWED_PERMISSION_BUNDLE;
    } else if (ret == Security::AccessToken::AccessTokenError::ERR_TOKENID_ALREADY_IN_POLICY_WHITELIST) {
        return ERR_OK;
    } else if (FAILED(ret)) {
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    return ERR_OK;
}

ErrCode AllowedPermissionBundlePlugin::RemoveOtherModulePolicy(
    const std::map<std::string, std::vector<ApplicationInstance>> &needRemovePolicy,
    PolicyScene policyScene)
{
    EDMLOGI("AllowedPermissionBundlePlugin RemoveOtherModulePolicy scene=%{public}d", static_cast<int>(policyScene));
    ErrCode ret = UpdatePolicyWhiteList(needRemovePolicy, policyScene);
    if (policyScene == PolicyScene::ADMIN_REMOVE || policyScene == PolicyScene::APP_UNINSTALL) {
        return ERR_OK;
    }
    if (ret == Security::AccessToken::AccessTokenError::ERR_PERM_POLICY_NOT_SET) {
        return EdmReturnErrCode::CANNOT_SET_ALLOWED_PERMISSION_BUNDLE;
    } else if (ret == Security::AccessToken::AccessTokenError::ERR_TOKENID_NOT_IN_POLICY_WHITELIST) {
        return ERR_OK;
    } else if (FAILED(ret)) {
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    return ERR_OK;
}

ErrCode AllowedPermissionBundlePlugin::UpdatePolicyWhiteList(
    const std::map<std::string, std::vector<ApplicationInstance>> &policyData, PolicyScene policyScene)
{
    Security::AccessToken::UpdateWhiteListType type = Security::AccessToken::UpdateWhiteListType::ADD;
    if (policyScene == PolicyScene::POLICY_REMOVE || policyScene == PolicyScene::ADMIN_REMOVE ||
        policyScene == PolicyScene::APP_UNINSTALL) {
        type = Security::AccessToken::UpdateWhiteListType::DELETE;
    }
    for (const auto& permissionPair : policyData) {
        const std::string& permissionName = permissionPair.first;
        const std::vector<ApplicationInstance>& appList = permissionPair.second;
        for (const ApplicationInstance& item : appList) {
            Security::AccessToken::AccessTokenID accessTokenId = 0;
            EdmAccessTokenManagerImpl edmAccessTokenManagerImpl;
            bool getTokenSuccess = edmAccessTokenManagerImpl.GetAccessTokenId(item.accountId, item.appIdentifier,
                item.appIndex, accessTokenId);

            if (!getTokenSuccess && policyScene != PolicyScene::ADMIN_REMOVE &&
                policyScene != PolicyScene::APP_UNINSTALL) {
                EDMLOGE("UpdatePolicyWhiteList GetAccessTokenId failed.");
                return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
            }

            if (!getTokenSuccess && policyScene == PolicyScene::APP_UNINSTALL) {
                EDMLOGI("UpdatePolicyWhiteList skip app (uninstalled): %{public}s", item.appIdentifier.c_str());
                continue;
            }

            ErrCode atReturn = Security::AccessToken::AccessTokenKit::UpdatePolicyWhiteList(
                accessTokenId, permissionName, type);
            if (policyScene != PolicyScene::ADMIN_REMOVE && policyScene != PolicyScene::APP_UNINSTALL &&
                FAILED(atReturn)) {
                return atReturn;
            }
            if (FAILED(atReturn) && policyScene == PolicyScene::APP_UNINSTALL) {
                EDMLOGI("UpdatePolicyWhiteList AccessTokenKit returned %{public}d for uninstalled app, skip",
                    atReturn);
            }
        }
    }
    return ERR_OK;
}

ErrCode AllowedPermissionBundlePlugin::OnAdminRemove(const std::string &adminName,
    const std::string &currentJsonData, const std::string &mergeJsonData, int32_t userId)
{
    EDMLOGI("AllowedPermissionBundlePlugin OnAdminRemove admin=%{public}s", adminName.c_str());
    auto serializer = AllowedPermissionBundleSerializer::GetInstance();
    std::map<std::string, std::vector<ApplicationInstance>> currentData;
    serializer->Deserialize(currentJsonData, currentData);
    std::map<std::string, std::vector<ApplicationInstance>> mergeData;
    serializer->Deserialize(mergeJsonData, mergeData);
    std::map<std::string, std::vector<ApplicationInstance>> needRemovePolicy =
        serializer->SetDifferencePolicyData(mergeData, currentData);
    RemoveOtherModulePolicy(needRemovePolicy, PolicyScene::ADMIN_REMOVE);
    return ERR_OK;
}

ErrCode AllowedPermissionBundlePlugin::OnGetPolicy(std::string &policyData, MessageParcel &data,
    MessageParcel &reply, int32_t userId)
{
    EDMLOGI("AllowedPermissionBundlePlugin OnGetPolicy");
    return ERR_OK;
}

ErrCode AllowedPermissionBundlePlugin::GetOthersMergePolicyData(const std::string &adminName, int32_t userId,
    std::string &othersMergePolicyData)
{
    std::unordered_map<std::string, std::string> adminValues;
    IPolicyManager::GetInstance()->GetAdminByPolicyName(GetPolicyName(), adminValues, userId);
    EDMLOGI("AllowedPermissionBundlePlugin::GetOthersMergePolicyData %{public}s value size %{public}d.",
        GetPolicyName().c_str(), (uint32_t)adminValues.size());
    if (adminValues.empty()) {
        return ERR_OK;
    }
    auto entry = adminValues.find(adminName);
    if (entry != adminValues.end()) {
        adminValues.erase(entry);
    }
    if (adminValues.empty()) {
        return ERR_OK;
    }
    auto serializer = AllowedPermissionBundleSerializer::GetInstance();
    std::vector<std::map<std::string, std::vector<ApplicationInstance>>> data;
    for (const auto &item : adminValues) {
        std::map<std::string, std::vector<ApplicationInstance>> dataItem;
        if (!item.second.empty()) {
            if (!serializer->Deserialize(item.second, dataItem)) {
                return ERR_EDM_OPERATE_JSON;
            }
            data.push_back(dataItem);
        }
    }
    std::map<std::string, std::vector<ApplicationInstance>> result;
    if (!serializer->MergePolicy(data, result)) {
        return ERR_EDM_OPERATE_JSON;
    }
    if (!serializer->Serialize(result, othersMergePolicyData)) {
        return ERR_EDM_OPERATE_JSON;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS