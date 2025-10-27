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

#include "manage_user_non_stop_apps_plugin.h"

#include <algorithm>

#include "app_control/app_control_proxy.h"
#include <bundle_info.h>
#include <bundle_mgr_interface.h>
#include <system_ability_definition.h>

#include "ability_auto_startup_client.h"
#include "manage_user_non_stop_apps_serializer.h"
#include "manage_user_non_stop_apps_info.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_sys_manager.h"
#include "element_name.h"
#include "iplugin_manager.h"
#include "ipolicy_manager.h"
#include "func_code_utils.h"
#include "edm_bundle_manager_impl.h"
#include "edm_data_ability_utils.h"
#include "wm_common.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<ManageUserNonStopAppsPlugin>());
const std::string SETTINGS_KEY = "com.enterprise.enterprise_user_non_stop_apps";

ManageUserNonStopAppsPlugin::ManageUserNonStopAppsPlugin()
{
    policyCode_ = EdmInterfaceCode::MANAGE_USER_NON_STOP_APPS;
    policyName_ = PolicyName::POLICY_MANAGE_USER_NON_STOP_APPS;
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION);
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = true;
    maxListSize_ = EdmConstants::USER_NON_STOP_APPS_MAX_SIZE;
}

ErrCode ManageUserNonStopAppsPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    EDMLOGI("ManageUserNonStopAppsPlugin OnHandlePolicy.");
    uint32_t typeCode = FUNC_TO_OPERATE(funcCode);
    FuncOperateType type = FuncCodeUtils::ConvertOperateType(typeCode);
    std::vector<ApplicationMsg> userNonStopApps;
    ApplicationInstanceHandle::ReadApplicationInstanceVector(data, userNonStopApps);
    std::vector<ManageUserNonStopAppInfo> currentData;
    ManageUserNonStopAppsSerializer::GetInstance()->Deserialize(policyData.policyData, currentData);
    std::vector<ManageUserNonStopAppInfo> mergeData;
    ManageUserNonStopAppsSerializer::GetInstance()->Deserialize(policyData.mergePolicyData, mergeData);
    std::string mergePolicyStr;
    IPolicyManager::GetInstance()->GetPolicy("", GetPolicyName(), mergePolicyStr, userId);
    ErrCode res = EdmReturnErrCode::PARAM_ERROR;
    std::string errMessage;
    if (type == FuncOperateType::SET) {
        res = OnSetPolicy(userNonStopApps, currentData, mergeData);
    } else if (type == FuncOperateType::REMOVE) {
        res = OnRemovePolicy(userNonStopApps, currentData, mergeData);
    }
    if (res != ERR_OK) {
        reply.WriteInt32(res);
        reply.WriteString(errMessage);
        return res;
    }
    reply.WriteInt32(ERR_OK);
    std::string afterHandle;
    std::string afterMerge;
    ManageUserNonStopAppsSerializer::GetInstance()->Serialize(currentData, afterHandle);
    ManageUserNonStopAppsSerializer::GetInstance()->Serialize(mergeData, afterMerge);
    policyData.isChanged = (policyData.policyData != afterHandle || mergePolicyStr != afterMerge);
    policyData.policyData = afterHandle;
    policyData.mergePolicyData = afterMerge;
    return ERR_OK;
}

ErrCode ManageUserNonStopAppsPlugin::OnSetPolicy(std::vector<ApplicationMsg> &data,
    std::vector<ManageUserNonStopAppInfo> &currentData, std::vector<ManageUserNonStopAppInfo> &mergeData)
{
    if (data.empty()) {
        EDMLOGW("ManageUserNonStopAppsPlugin OnSetPolicy data is empty.");
        return ERR_OK;
    }
    if (data.size() > maxListSize_) {
        EDMLOGE("ManageUserNonStopAppsPlugin OnSetPolicy input data is too large.");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::vector<ManageUserNonStopAppInfo> tmpData;
    for (const auto &item : data) {
        ManageUserNonStopAppInfo appInfo;
        appInfo.SetBundleName(item.bundleName);
        appInfo.SetAccountId(item.accountId);
        appInfo.SetAppIndex(item.appIndex);
        tmpData.push_back(appInfo);
    }

    std::vector<ManageUserNonStopAppInfo> addData =
        ManageUserNonStopAppsSerializer::GetInstance()->SetDifferencePolicyData(currentData, tmpData);
    std::vector<ManageUserNonStopAppInfo> unInstalledData;
    FilterUninstalledBundle(addData, unInstalledData);
    if (!unInstalledData.empty()) {
        EDMLOGE("ManageUserNonStopAppsPlugin OnSetPolicy bundle uninstall.");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    addData = ManageUserNonStopAppsSerializer::GetInstance()->SetDifferencePolicyData(unInstalledData, addData);
    std::vector<ManageUserNonStopAppInfo> needAddMergeData =
        ManageUserNonStopAppsSerializer::GetInstance()->SetDifferencePolicyData(mergeData, addData);
    std::vector<ManageUserNonStopAppInfo> afterHandle =
        ManageUserNonStopAppsSerializer::GetInstance()->SetUnionPolicyData(currentData, addData);
    std::vector<ManageUserNonStopAppInfo> afterMerge =
        ManageUserNonStopAppsSerializer::GetInstance()->SetUnionPolicyData(mergeData, afterHandle);
    if (afterMerge.size() > maxListSize_) {
        EDMLOGE("ManageUserNonStopAppsPlugin OnSetPolicy merge data is too large.");
        return EdmReturnErrCode::PARAM_ERROR;
    }

    if (!needAddMergeData.empty()) {
        ErrCode ret = SetOtherModulePolicy(afterHandle);
        if (FAILED(ret)) {
            return ret;
        }
    }

    currentData = afterHandle;
    mergeData = afterMerge;
    return ERR_OK;
}

ErrCode ManageUserNonStopAppsPlugin::OnRemovePolicy(std::vector<ApplicationMsg> &data,
    std::vector<ManageUserNonStopAppInfo> &currentData, std::vector<ManageUserNonStopAppInfo> &mergeData)
{
    if (data.empty()) {
        EDMLOGW("BasicArrayStringPlugin OnRemovePolicy data is empty.");
        return ERR_OK;
    }
    if (data.size() > maxListSize_) {
        EDMLOGE("BasicArrayStringPlugin OnRemovePolicy input data is too large.");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::vector<ManageUserNonStopAppInfo> needRemovePolicy =
        ManageUserNonStopAppsSerializer::GetInstance()->SetIntersectionPolicyData(data, currentData);
    std::vector<ManageUserNonStopAppInfo> needRemoveMergePolicy =
        ManageUserNonStopAppsSerializer::GetInstance()->SetNeedRemoveMergePolicyData(mergeData, needRemovePolicy);
    std::vector<ManageUserNonStopAppInfo> needResetPolicy =
    ManageUserNonStopAppsSerializer::GetInstance()->SetDifferencePolicyData(needRemovePolicy, currentData);

    if (!needRemoveMergePolicy.empty()) {
        ErrCode ret = RemoveOtherModulePolicy(needResetPolicy, needRemoveMergePolicy);
        if (FAILED(ret)) {
            EDMLOGE("BasicArrayStringPlugin RemoveOtherModulePolicy fail.");
            return ret;
        }
    }
    currentData =needResetPolicy;
    mergeData = ManageUserNonStopAppsSerializer::GetInstance()->SetUnionPolicyData(currentData, mergeData);
    return ERR_OK;
}

ErrCode ManageUserNonStopAppsPlugin::SetOtherModulePolicy(const std::vector<ManageUserNonStopAppInfo> &userNonStopApps)
{
    EDMLOGI("ManageUserNonStopAppsPlugin SetOtherModulePolicy");
    std::vector<std::string> settingData;

    for (const ManageUserNonStopAppInfo &item : userNonStopApps) {
        std::string appPolicyJsonStr;
        ConvertAppPolicyToJsonStr(item, appPolicyJsonStr);
        settingData.push_back(appPolicyJsonStr);
    }
    std::string result = std::accumulate(settingData.begin(), settingData.end(), std::string(),
                                        [](const std::string &a, const std::string &b) {
                                            return a.empty() ? b : a + "," + b;
                                        });
    result = "[" + result + "]";
    EdmDataAbilityUtils::UpdateSettingsData(SETTINGS_KEY, result);
    ReportLockSession(userNonStopApps, true);
    return ERR_OK;
}

ErrCode ManageUserNonStopAppsPlugin::ConvertAppPolicyToJsonStr(const ManageUserNonStopAppInfo &userNonStopApp,
    std::string &AppPolicyJsonStr)
{
    cJSON *json = nullptr;
    CJSON_CREATE_OBJECT_AND_CHECK(json, false);

    if (cJSON_AddStringToObject(json, "bundleName", userNonStopApp.GetBundleName().c_str()) == NULL) {
        cJSON_Delete(json);
        return false;
    }
    if (cJSON_AddNumberToObject(json, "appIndex", userNonStopApp.GetAppIndex()) == NULL) {
        cJSON_Delete(json);
        return false;
    }
    if (cJSON_AddNumberToObject(json, "uid", userNonStopApp.GetAccountId()) == NULL) {
        cJSON_Delete(json);
        return false;
    }

    char *jsonStrTemp = cJSON_PrintUnformatted(json);
    if (jsonStrTemp == nullptr) {
        cJSON_Delete(json);
        return false;
    }
    AppPolicyJsonStr = std::string(jsonStrTemp);
    cJSON_Delete(json);
    cJSON_free(jsonStrTemp);
    return true;
}

ErrCode ManageUserNonStopAppsPlugin::RemoveOtherModulePolicy(
    const std::vector<ManageUserNonStopAppInfo> &needResetPolicy,
    const std::vector<ManageUserNonStopAppInfo> &needRemovePolicy)
{
    EDMLOGI("ManageUserNonStopAppsPlugin RemoveuserNonStopApps");
    std::vector<std::string> settingData;

    for (const ManageUserNonStopAppInfo &item : needResetPolicy) {
        std::string appPolicyJsonStr;
        ConvertAppPolicyToJsonStr(item, appPolicyJsonStr);
        settingData.push_back(appPolicyJsonStr);
    }
    std::string result = std::accumulate(settingData.begin(), settingData.end(), std::string(),
                                        [](const std::string &a, const std::string &b) {
                                            return a.empty() ? b : a + "," + b;
                                        });
    result = "[" + result + "]";
    EdmDataAbilityUtils::UpdateSettingsData(SETTINGS_KEY, result);
    ReportLockSession(needRemovePolicy, false);
    return ERR_OK;
}

ErrCode ManageUserNonStopAppsPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data,
    MessageParcel &reply, int32_t userId)
{
    EDMLOGI("ManageUserNonStopAppsPlugin OnGetPolicy.");
    std::string type = data.ReadString();
    std::vector<ManageUserNonStopAppInfo> appInfos;
    ManageUserNonStopAppsSerializer::GetInstance()->Deserialize(policyData, appInfos);
    std::vector<ApplicationMsg> policies;
    for (const ManageUserNonStopAppInfo &item : appInfos) {
        policies.push_back({item.GetBundleName(),
            item.GetAccountId(),
            item.GetAppIndex()});
    }
    reply.WriteInt32(ERR_OK);
    if (!ApplicationInstanceHandle::WriteApplicationMsgVector(reply, policies)) {
        EDMLOGE("ManageUserNonStopAppsPlugin write application instance vector fail.");
    }
    return ERR_OK;
}

ErrCode ManageUserNonStopAppsPlugin::OnAdminRemove(const std::string &adminName, const std::string &currentJsonData,
    const std::string &mergeJsonData, int32_t userId)
{
    EDMLOGI("ManageUserNonStopAppsPlugin OnAdminRemoveDone");
    
    std::vector<ManageUserNonStopAppInfo> currentData;
    ManageUserNonStopAppsSerializer::GetInstance()->Deserialize(currentJsonData, currentData);
    std::vector<ManageUserNonStopAppInfo> mergeData;
    ManageUserNonStopAppsSerializer::GetInstance()->Deserialize(mergeJsonData, mergeData);
    std::vector<ManageUserNonStopAppInfo> needRemoveMergePolicy =
        ManageUserNonStopAppsSerializer::GetInstance()->SetNeedRemoveMergePolicyData(mergeData, currentData);
    std::vector<ManageUserNonStopAppInfo> needResetMergePolicy =
        ManageUserNonStopAppsSerializer::GetInstance()->SetDifferencePolicyData(needRemoveMergePolicy, mergeData);

    return RemoveOtherModulePolicy(needResetMergePolicy, currentData);
}

ErrCode ManageUserNonStopAppsPlugin::GetOthersMergePolicyData(const std::string &adminName, int32_t userId,
    std::string &othersMergePolicyData)
{
    EDMLOGI("ManageUserNonStopAppsPlugin GetOthersMergePolicyData");
    std::unordered_map<std::string, std::string> adminValues;
    IPolicyManager::GetInstance()->GetAdminByPolicyName(GetPolicyName(), adminValues, userId);
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
    auto serializer = ManageUserNonStopAppsSerializer::GetInstance();
    std::vector<std::vector<ManageUserNonStopAppInfo>> data;
    for (const auto &item : adminValues) {
        std::vector<ManageUserNonStopAppInfo> dataItem;
        if (!item.second.empty()) {
            if (!serializer->Deserialize(item.second, dataItem)) {
                return ERR_EDM_OPERATE_JSON;
            }
            data.push_back(dataItem);
        }
    }
    std::vector<ManageUserNonStopAppInfo> result;
    if (!serializer->MergePolicy(data, result)) {
        return ERR_EDM_OPERATE_JSON;
    }

    std::string mergePolicyStr;
    IPolicyManager::GetInstance()->GetPolicy("", GetPolicyName(), mergePolicyStr, userId);
    std::vector<ManageUserNonStopAppInfo> mergePolicyData;
    if (!serializer->Deserialize(mergePolicyStr, mergePolicyData)) {
        return ERR_EDM_OPERATE_JSON;
    }

    if (!serializer->Serialize(result, othersMergePolicyData)) {
        return ERR_EDM_OPERATE_JSON;
    }

    return ERR_OK;
}

void ManageUserNonStopAppsPlugin::ReportLockSession(const std::vector<ManageUserNonStopAppInfo> &userNonStopAppInfos,
    bool isLocked)
{
    EDMLOGI("ManageUserNonStopAppsPlugin ReportLockSession");
    auto sceneSessionManager = Rosen::SessionManagerLite::GetInstance().GetSceneSessionManagerLiteProxy();
    if (sceneSessionManager == nullptr) {
        EDMLOGE("ManageUserNonStopAppsPlugin get sceneSession manager fail");
    }
    Rosen::WMError ret = Rosen::WMError::WM_OK;
    for (const auto &item :userNonStopAppInfos) {
        std::vector<Rosen::AbilityInfoBase> abilityInfos;
        GetSessionParam(item, abilityInfos);
        for (const auto &eachAbilityInfo : abilityInfos) {
            ret = sceneSessionManager->LockSessionByAbilityInfo(eachAbilityInfo, isLocked);
            if (ret != Rosen::WMError::WM_OK) {
                EDMLOGE("ManageUserNonStopAppsPlugin lock session fail");
            }
        }
    }
}

ErrCode ManageUserNonStopAppsPlugin::FilterUninstalledBundle(
    std::vector<ManageUserNonStopAppInfo> &data, std::vector<ManageUserNonStopAppInfo> &UninstalledApp)
{
    auto bundleMgr = std::make_shared<EdmBundleManagerImpl>();
    for (const ManageUserNonStopAppInfo &appInfo : data) {
        std::string bundleName = appInfo.GetBundleName();
        int32_t accountId = appInfo.GetAccountId();
        int32_t appIndex = appInfo.GetAppIndex();
        if (!bundleMgr->IsBundleInstalled(bundleName, accountId, appIndex)) {
            UninstalledApp.push_back(appInfo);
        }
    }
    return ERR_OK;
}

void ManageUserNonStopAppsPlugin::GetSessionParam(const ManageUserNonStopAppInfo &userNonStopAppInfos,
    std::vector<Rosen::AbilityInfoBase> &infoBaseList)
{
    auto bundleMgr = std::make_shared<EdmBundleManagerImpl>();
    std::string bundleName = userNonStopAppInfos.GetBundleName();
    int32_t accountId = userNonStopAppInfos.GetAccountId();
    int32_t appIndex = userNonStopAppInfos.GetAppIndex();
    BundleInfo bundleInfo;
    bundleMgr->GetBundleInfo(bundleName, GET_BUNDLE_DEFAULT, bundleInfo, accountId);
    for (const auto &item : bundleInfo.hapModuleInfos) {
        for (const auto &abilityInfoItem : item.abilityInfos) {
            Rosen::AbilityInfoBase infoBase;
            infoBase.moduleName = bundleInfo.entryModuleName;
            infoBase.bundleName = bundleName;
            infoBase.appIndex = appIndex;
            infoBase.abilityName = abilityInfoItem.name;
            infoBaseList.push_back(infoBase);
        }
    }
}
void ManageUserNonStopAppsPlugin::OnOtherServiceStart(int32_t systemAbilityId)
{
    EDMLOGI("ManageUserNonStopAppsPlugin OnOtherServiceStart");
    std::vector<ManageUserNonStopAppInfo> result;
    std::string mergePolicyStr;
    IPolicyManager::GetInstance()->GetPolicy("", GetPolicyName(), mergePolicyStr, EdmConstants::DEFAULT_USER_ID);
    std::vector<ManageUserNonStopAppInfo> mergePolicyData;
    auto serializer = ManageUserNonStopAppsSerializer::GetInstance();
    serializer->Deserialize(mergePolicyStr, mergePolicyData);
    ErrCode ret = SetOtherModulePolicy(mergePolicyData);
    if (FAILED(ret)) {
        EDMLOGE("ManageUserNonStopAppsPlugin OnOtherServiceStart fail res: %{public}d", ret);
    }
}
} // namespace EDM
} // namespace OHOS