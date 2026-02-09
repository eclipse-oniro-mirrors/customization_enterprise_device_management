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
#include "manage_apps_serializer.h"
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
#include "edm_os_account_manager_impl.h"

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
    maxListSize_ = EdmConstants::MANAGE_APPS_MAX_SIZE;
}

ErrCode ManageUserNonStopAppsPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    EDMLOGI("ManageUserNonStopAppsPlugin OnHandlePolicy");
    uint32_t typeCode = FUNC_TO_OPERATE(funcCode);
    FuncOperateType type = FuncCodeUtils::ConvertOperateType(typeCode);
    std::vector<ApplicationInstance> userNonStopApps;
    std::vector<ApplicationInstance> currentData;
    std::vector<ApplicationInstance> mergeData;
    auto serializer = ManageAppsSerializer::GetInstance();
    ApplicationInstanceHandle::ReadApplicationInstanceVector(data, userNonStopApps);
    if (userNonStopApps.empty() || userNonStopApps.size() > maxListSize_) {
        EDMLOGE("ManageUserNonStopAppsPlugin OnHandlePolicy userNonStopApps is empty or too large");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    serializer->Deserialize(policyData.policyData, currentData);
    serializer->Deserialize(policyData.mergePolicyData, mergeData);
    std::string mergePolicyStr;
    IPolicyManager::GetInstance()->GetPolicy("", GetPolicyName(), mergePolicyStr, userId);
    ErrCode res;
    for (ApplicationInstance &appInstance : userNonStopApps) {
        if (appInstance.bundleName.empty()) {
            ApplicationInstanceHandle::GetBundleNameByAppId(appInstance);
        }
    }
    if (type == FuncOperateType::SET) {
        res = OnSetPolicy(userNonStopApps, currentData, mergeData);
    } else if (type == FuncOperateType::REMOVE) {
        res = OnRemovePolicy(userNonStopApps, currentData, mergeData);
    } else {
        res = EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (res != ERR_OK) {
        reply.WriteInt32(res);
        return res;
    }
    reply.WriteInt32(ERR_OK);
    std::string afterHandle;
    std::string afterMerge;
    serializer->Serialize(currentData, afterHandle);
    serializer->Serialize(mergeData, afterMerge);
    policyData.isChanged = (policyData.policyData != afterHandle || mergePolicyStr != afterMerge);
    policyData.policyData = afterHandle;
    policyData.mergePolicyData = afterMerge;
    return ERR_OK;
}

ErrCode ManageUserNonStopAppsPlugin::OnSetPolicy(std::vector<ApplicationInstance> &userNonStopApps,
    std::vector<ApplicationInstance> &currentData, std::vector<ApplicationInstance> &mergeData)
{
    EDMLOGI("ManageUserNonStopAppsPlugin OnSetPolicy");
    auto serializer = ManageAppsSerializer::GetInstance();
    std::vector<ApplicationInstance> addData = serializer->SetDifferencePolicyData(currentData, userNonStopApps);
    std::vector<ApplicationInstance> unInstalledData;
    FilterUninstalledBundle(addData, unInstalledData);
    if (!unInstalledData.empty()) {
        EDMLOGE("ManageUserNonStopAppsPlugin OnSetPolicy bundle uninstall.");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    addData = serializer->SetDifferencePolicyData(unInstalledData, addData);
    std::vector<ApplicationInstance> needAddMergeData = serializer->SetDifferencePolicyData(mergeData, addData);
    std::vector<ApplicationInstance> afterHandle = serializer->SetUnionPolicyData(currentData, addData);
    std::vector<ApplicationInstance> afterMerge = serializer->SetUnionPolicyData(mergeData, afterHandle);
    if (afterMerge.size() > maxListSize_) {
        EDMLOGE("ManageUserNonStopAppsPlugin OnSetPolicy merge userNonStopApps is too large.");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }

    if (!needAddMergeData.empty()) {
        ErrCode ret = SetOtherModulePolicy(afterHandle);
        if (FAILED(ret)) {
            EDMLOGE("ManageUserNonStopAppsPlugin OnSetPolicy SetOtherModulePolicy fail");
            return ret;
        }
    }

    currentData = afterHandle;
    mergeData = afterMerge;
    return ERR_OK;
}

ErrCode ManageUserNonStopAppsPlugin::OnRemovePolicy(std::vector<ApplicationInstance> &data,
    std::vector<ApplicationInstance> &currentData, std::vector<ApplicationInstance> &mergeData)
{
    EDMLOGI("ManageUserNonStopAppsPlugin OnRemovePolicy");
    auto serializer = ManageAppsSerializer::GetInstance();
    std::vector<ApplicationInstance> needRemovePolicy;
    std::vector<ApplicationInstance> needRemoveMergePolicy;
    std::vector<ApplicationInstance> needResetPolicy;
    needRemovePolicy = serializer->SetIntersectionPolicyData(data, currentData);
    needRemoveMergePolicy = serializer->SetNeedRemoveMergePolicyData(mergeData, needRemovePolicy);
    needResetPolicy = serializer->SetDifferencePolicyData(needRemovePolicy, currentData);

    std::vector<ApplicationInstance> failedApps = serializer->SetNeedRemoveMergePolicyData(needRemoveMergePolicy, data);
    if (!failedApps.empty()) {
        EDMLOGE("OnRemovePolicy userNonStopApps has apps do not belong to current data");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }

    if (!needRemoveMergePolicy.empty()) {
        ErrCode ret = RemoveOtherModulePolicy(needResetPolicy, needRemoveMergePolicy);
        if (FAILED(ret)) {
            EDMLOGE("BasicArrayStringPlugin RemoveOtherModulePolicy fail.");
            return ret;
        }
    }
    currentData = needResetPolicy;
    mergeData = serializer->SetUnionPolicyData(currentData, mergeData);
    return ERR_OK;
}

ErrCode ManageUserNonStopAppsPlugin::SetOtherModulePolicy(const std::vector<ApplicationInstance> &userNonStopApps)
{
    EDMLOGI("ManageUserNonStopAppsPlugin SetOtherModulePolicy");
    std::vector<std::string> settingData;

    for (const ApplicationInstance &item : userNonStopApps) {
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
    ErrCode res = ReportLockSession(userNonStopApps, true);
    if (res != ERR_OK) {
        EDMLOGE("ManageUserNonStopAppsPlugin SetOtherModulePolicy ReportLockSession fail, res = %{public}d", res);
        return res;
    }
    auto bundleMgr = std::make_shared<EdmBundleManagerImpl>();
    for (const ApplicationInstance &appInstance : userNonStopApps) {
        if (!bundleMgr->SetApplicationDisableForbidden(appInstance.bundleName,
            appInstance.accountId, appInstance.appIndex, true)) {
            EDMLOGE("ManageUserNonStopAppsPlugin SetOtherModulePolicy SetApplicationDisableForbidden::%{public}s fail.",
                appInstance.bundleName.c_str());
        }
    }
    return ERR_OK;
}

ErrCode ManageUserNonStopAppsPlugin::ConvertAppPolicyToJsonStr(const ApplicationInstance &userNonStopApp,
    std::string &appPolicyJsonStr)
{
    cJSON *json = nullptr;
    CJSON_CREATE_OBJECT_AND_CHECK(json, false);

    if (cJSON_AddStringToObject(json, "bundleName", userNonStopApp.bundleName.c_str()) == NULL) {
        cJSON_Delete(json);
        return false;
    }
    if (cJSON_AddNumberToObject(json, "appIndex", userNonStopApp.appIndex) == NULL) {
        cJSON_Delete(json);
        return false;
    }
    if (cJSON_AddNumberToObject(json, "uid", userNonStopApp.accountId) == NULL) {
        cJSON_Delete(json);
        return false;
    }

    char *jsonStrTemp = cJSON_PrintUnformatted(json);
    if (jsonStrTemp == nullptr) {
        cJSON_Delete(json);
        return false;
    }
    appPolicyJsonStr = std::string(jsonStrTemp);
    cJSON_Delete(json);
    cJSON_free(jsonStrTemp);
    return true;
}

ErrCode ManageUserNonStopAppsPlugin::RemoveOtherModulePolicy(const std::vector<ApplicationInstance> needResetPolicy,
    const std::vector<ApplicationInstance> needRemovePolicy)
{
    EDMLOGI("ManageUserNonStopAppsPlugin RemoveOtherModulePolicy");
    std::vector<std::string> settingData;

    for (const ApplicationInstance &item : needResetPolicy) {
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
    ErrCode res = ReportLockSession(needRemovePolicy, false);
    if (res != ERR_OK) {
        EDMLOGE("ManageUserNonStopAppsPlugin RemoveOtherModulePolicy ReportLockSession fail, res = %{public}d", res);
        return res;
    }
    auto bundleMgr = std::make_shared<EdmBundleManagerImpl>();
    for (const ApplicationInstance &appInstance : needRemovePolicy) {
        if (!bundleMgr->SetApplicationDisableForbidden(appInstance.bundleName,
            appInstance.accountId, appInstance.appIndex, false)) {
            EDMLOGE(
                "ManageUserNonStopAppsPlugin RemoveOtherModulePolicy SetApplicationDisableForbidden::%{public}s fail.",
                appInstance.bundleName.c_str());
        }
    }
    return ERR_OK;
}

ErrCode ManageUserNonStopAppsPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data,
    MessageParcel &reply, int32_t userId)
{
    EDMLOGI("ManageUserNonStopAppsPlugin OnGetPolicy");
    std::vector<ApplicationInstance> appInfos;
    ManageAppsSerializer::GetInstance()->Deserialize(policyData, appInfos);
    reply.WriteInt32(ERR_OK);
    if (!ApplicationInstanceHandle::WriteApplicationInstanceVector(reply, appInfos)) {
        EDMLOGE("ManageUserNonStopAppsPlugin write application instance vector fail.");
    }
    return ERR_OK;
}

ErrCode ManageUserNonStopAppsPlugin::OnAdminRemove(const std::string &adminName, const std::string &currentJsonData,
    const std::string &mergeJsonData, int32_t userId)
{
    EDMLOGI("ManageUserNonStopAppsPlugin OnAdminRemove");
    auto serializer = ManageAppsSerializer::GetInstance();
    std::vector<ApplicationInstance> currentData;
    std::vector<ApplicationInstance> mergeData;
    serializer->Deserialize(currentJsonData, currentData);
    serializer->Deserialize(mergeJsonData, mergeData);
    std::vector<ApplicationInstance> needRemoveMergePolicy;
    std::vector<ApplicationInstance> needResetMergePolicy;
    needRemoveMergePolicy = serializer->SetNeedRemoveMergePolicyData(mergeData, currentData);
    needResetMergePolicy = serializer->SetDifferencePolicyData(needRemoveMergePolicy, mergeData);

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
    auto serializer = ManageAppsSerializer::GetInstance();
    std::vector<std::vector<ApplicationInstance>> data;
    for (const auto &item : adminValues) {
        std::vector<ApplicationInstance> dataItem;
        if (!item.second.empty()) {
            if (!serializer->Deserialize(item.second, dataItem)) {
                return ERR_EDM_OPERATE_JSON;
            }
            data.push_back(dataItem);
        }
    }
    std::vector<ApplicationInstance> result;
    if (!serializer->MergePolicy(data, result)) {
        return ERR_EDM_OPERATE_JSON;
    }

    std::string mergePolicyStr;
    IPolicyManager::GetInstance()->GetPolicy("", GetPolicyName(), mergePolicyStr, userId);
    std::vector<ApplicationInstance> mergePolicyData;
    if (!serializer->Deserialize(mergePolicyStr, mergePolicyData)) {
        return ERR_EDM_OPERATE_JSON;
    }

    if (!serializer->Serialize(result, othersMergePolicyData)) {
        return ERR_EDM_OPERATE_JSON;
    }

    return ERR_OK;
}

ErrCode ManageUserNonStopAppsPlugin::ReportLockSession(const std::vector<ApplicationInstance> &userNonStopAppInfos,
    bool isLocked)
{
    EDMLOGI("ManageUserNonStopAppsPlugin ReportLockSession");
    auto sceneSessionManager = Rosen::SessionManagerLite::GetInstance().GetSceneSessionManagerLiteProxy();
    if (sceneSessionManager == nullptr) {
        EDMLOGE("ManageUserNonStopAppsPlugin get sceneSession manager fail");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    Rosen::WMError ret;
    for (const auto &item :userNonStopAppInfos) {
        std::vector<Rosen::AbilityInfoBase> abilityInfos;
        GetSessionParam(item, abilityInfos);
        for (const auto &eachAbilityInfo : abilityInfos) {
            ret = sceneSessionManager->LockSessionByAbilityInfo(eachAbilityInfo, isLocked);
            if (ret != Rosen::WMError::WM_OK) {
                EDMLOGE("ManageUserNonStopAppsPlugin lock session fail, ret = %{public}d", ret);
                return EdmReturnErrCode::SYSTEM_ABNORMALLY;
            }
        }
    }
    return ERR_OK;
}

ErrCode ManageUserNonStopAppsPlugin::FilterUninstalledBundle(std::vector<ApplicationInstance> &data,
    std::vector<ApplicationInstance> &uninstalledApp)
{
    EDMLOGI("ManageUserNonStopAppsPlugin FilterUninstalledBundle");
    auto bundleMgr = std::make_shared<EdmBundleManagerImpl>();
    for (const ApplicationInstance &appInfo : data) {
        if (!bundleMgr->IsBundleInstalled(appInfo.bundleName, appInfo.accountId, appInfo.appIndex)) {
            uninstalledApp.push_back(appInfo);
        }
    }
    return ERR_OK;
}

void ManageUserNonStopAppsPlugin::GetSessionParam(const ApplicationInstance &userNonStopAppInfos,
    std::vector<Rosen::AbilityInfoBase> &infoBaseList)
{
    EDMLOGI("ManageUserNonStopAppsPlugin GetSessionParam");
    auto bundleMgr = std::make_shared<EdmBundleManagerImpl>();
    std::string bundleName = userNonStopAppInfos.bundleName;
    int32_t accountId = userNonStopAppInfos.accountId;
    int32_t appIndex = userNonStopAppInfos.appIndex;
    BundleInfo bundleInfo;
    int32_t currentUserId = GetCurrentUserId();
    if (currentUserId != accountId) {
        EDMLOGI("ManageUserNonStopAppsPlugin the user is not current user");
        return;
    }
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

int32_t ManageUserNonStopAppsPlugin::GetCurrentUserId()
{
    std::vector<int32_t> ids;
    ErrCode ret = std::make_shared<EdmOsAccountManagerImpl>()->QueryActiveOsAccountIds(ids);
    if (FAILED(ret) || ids.empty()) {
        EDMLOGE("ManageUserNonStopAppsPlugin GetCurrentUserId failed");
        return -1;
    }
    EDMLOGD("ManageUserNonStopAppsPlugin GetCurrentUserId");
    return (ids.at(0));
}

void ManageUserNonStopAppsPlugin::OnOtherServiceStart(int32_t systemAbilityId)
{
    EDMLOGI("ManageUserNonStopAppsPlugin OnOtherServiceStart");
    std::string mergePolicyStr;
    IPolicyManager::GetInstance()->GetPolicy("", GetPolicyName(), mergePolicyStr, EdmConstants::DEFAULT_USER_ID);
    std::vector<ApplicationInstance> mergePolicyData;
    ManageAppsSerializer::GetInstance()->Deserialize(mergePolicyStr, mergePolicyData);
    ErrCode ret = SetOtherModulePolicy(mergePolicyData);
    if (FAILED(ret)) {
        EDMLOGE("ManageUserNonStopAppsPlugin OnOtherServiceStart fail res: %{public}d", ret);
    }
}
} // namespace EDM
} // namespace OHOS