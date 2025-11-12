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

#include "manage_freeze_exempted_apps_plugin.h"

#include <algorithm>

#include "app_control/app_control_proxy.h"
#include <bundle_info.h>
#include <bundle_mgr_interface.h>
#include <system_ability_definition.h>
#include "edm_bundle_manager_impl.h"
#include "ability_auto_startup_client.h"
#include "manage_freeze_exempted_apps_serializer.h"
#include "manage_freeze_exempted_apps_info.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_sys_manager.h"
#include "element_name.h"
#include "iplugin_manager.h"
#include "ipolicy_manager.h"
#include "func_code_utils.h"
#include "res_type.h"
#include "res_sched_client.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT =
    IPluginManager::GetInstance()->AddPlugin(std::make_shared<ManageFreezeExemptedAppsPlugin>());
const std::string PAYLOAD_RESOURCE = "EDM Control Policy";

ManageFreezeExemptedAppsPlugin::ManageFreezeExemptedAppsPlugin()
{
    policyCode_ = EdmInterfaceCode::MANAGE_FREEZE_EXEMPTED_APPS;
    policyName_ = PolicyName::POLICY_MANAGE_FREEZE_EXEMPTED_APPS;
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION);
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = true;
    maxListSize_ = EdmConstants::FREEZE_EXEMPTED_APPS_MAX_SIZE;
}

ErrCode ManageFreezeExemptedAppsPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data,
    MessageParcel &reply, HandlePolicyData &policyData, int32_t userId)
{
    EDMLOGI("ManageFreezeExemptedAppsPlugin OnHandlePolicy.");
    uint32_t typeCode = FUNC_TO_OPERATE(funcCode);
    FuncOperateType type = FuncCodeUtils::ConvertOperateType(typeCode);
    std::vector<ApplicationMsg> freezeExemptedApps;
    ApplicationInstanceHandle::ReadApplicationInstanceVector(data, freezeExemptedApps);
    std::vector<ManageFreezeExemptedAppInfo> currentData;
    ManageFreezeExemptedAppsSerializer::GetInstance()->Deserialize(policyData.policyData, currentData);
    std::vector<ManageFreezeExemptedAppInfo> mergeData;
    ManageFreezeExemptedAppsSerializer::GetInstance()->Deserialize(policyData.mergePolicyData, mergeData);
    std::string mergePolicyStr;
    IPolicyManager::GetInstance()->GetPolicy("", GetPolicyName(), mergePolicyStr, userId);
    ErrCode res = EdmReturnErrCode::PARAM_ERROR;
    if (type == FuncOperateType::SET) {
        res = OnSetPolicy(freezeExemptedApps, currentData, mergeData);
    } else if (type == FuncOperateType::REMOVE) {
        res = OnRemovePolicy(freezeExemptedApps, currentData, mergeData);
    }
    if (res != ERR_OK) {
        reply.WriteInt32(res);
        return res;
    }
    reply.WriteInt32(ERR_OK);
    std::string afterHandle;
    std::string afterMerge;
    ManageFreezeExemptedAppsSerializer::GetInstance()->Serialize(currentData, afterHandle);
    ManageFreezeExemptedAppsSerializer::GetInstance()->Serialize(mergeData, afterMerge);
    policyData.isChanged = (policyData.policyData != afterHandle || mergePolicyStr != afterMerge);
    policyData.policyData = afterHandle;
    policyData.mergePolicyData = afterMerge;
    return ERR_OK;
}

ErrCode ManageFreezeExemptedAppsPlugin::OnSetPolicy(std::vector<ApplicationMsg> &freezeExemptedApps,
    std::vector<ManageFreezeExemptedAppInfo> &currentData, std::vector<ManageFreezeExemptedAppInfo> &mergeData)
{
    EDMLOGI("ManageFreezeExemptedAppsPlugin OnSetPolicy");
    if (freezeExemptedApps.size() > maxListSize_) {
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::vector<ManageFreezeExemptedAppInfo> tmpData;
    for (const auto &item : freezeExemptedApps) {
        ManageFreezeExemptedAppInfo appInfo;
        appInfo.SetBundleName(item.bundleName);
        appInfo.SetAccountId(item.accountId);
        appInfo.SetAppIndex(item.appIndex);
        tmpData.push_back(appInfo);
    }
    std::vector<ManageFreezeExemptedAppInfo> addData =
        ManageFreezeExemptedAppsSerializer::GetInstance()->SetDifferencePolicyData(currentData, tmpData);
    std::vector<ManageFreezeExemptedAppInfo> UninstalledData = FilterUninstalledBundle(addData);
    if (!UninstalledData.empty()) {
        EDMLOGE("ManageFreezeExemptedAppsPlugin OnSetPolicy has uninstalled app");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    addData = ManageFreezeExemptedAppsSerializer::GetInstance()->SetDifferencePolicyData(UninstalledData, addData);
    std::vector<ManageFreezeExemptedAppInfo> needAddMergeData =
        ManageFreezeExemptedAppsSerializer::GetInstance()->SetDifferencePolicyData(mergeData, addData);
    std::vector<ManageFreezeExemptedAppInfo> afterHandle =
        ManageFreezeExemptedAppsSerializer::GetInstance()->SetUnionPolicyData(currentData, addData);
    std::vector<ManageFreezeExemptedAppInfo> afterMerge =
        ManageFreezeExemptedAppsSerializer::GetInstance()->SetUnionPolicyData(mergeData, afterHandle);
    if (afterMerge.size() > maxListSize_) {
        return EdmReturnErrCode::PARAM_ERROR;
    }
    if (!afterMerge.empty()) {
        std::vector<ApplicationMsg> afterMergeApps;
        for (const ManageFreezeExemptedAppInfo &appInfo : afterMerge) {
            ApplicationMsg instance;
            instance.bundleName = appInfo.GetBundleName();
            instance.accountId = appInfo.GetAccountId();
            instance.appIndex = appInfo.GetAppIndex();
            afterMergeApps.push_back(instance);
        }
        ErrCode ret = SetOtherModulePolicy(afterMergeApps);
        if (FAILED(ret)) {
            return ret;
        }
    }
    currentData = afterHandle;
    mergeData = afterMerge;
    return ERR_OK;
}

ErrCode ManageFreezeExemptedAppsPlugin::OnRemovePolicy(std::vector<ApplicationMsg> &freezeExemptedApps,
    std::vector<ManageFreezeExemptedAppInfo> &currentData, std::vector<ManageFreezeExemptedAppInfo> &mergeData)
{
    EDMLOGI("ManageFreezeExemptedAppsPlugin::OnRemovePolicy");
    if (freezeExemptedApps.empty()) {
        EDMLOGW("ManageFreezeExemptedAppsPlugin OnRemovePolicy freezeExemptedApps is empty.");
        return ERR_OK;
    }
    if (freezeExemptedApps.size() > maxListSize_) {
        EDMLOGE("ManageFreezeExemptedAppsPlugin OnRemovePolicy input freezeExemptedApps is too large.");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::vector<ManageFreezeExemptedAppInfo> needRemovePolicy =
        ManageFreezeExemptedAppsSerializer::GetInstance()->SetIntersectionPolicyData(freezeExemptedApps, currentData);
    std::vector<ApplicationMsg> needRemoveApp;
    std::vector<ManageFreezeExemptedAppInfo> needRemoveMergePolicy =
        ManageFreezeExemptedAppsSerializer::GetInstance()->SetNeedRemoveMergePolicyData(mergeData,
        needRemovePolicy, needRemoveApp);
    std::vector<ApplicationMsg> needSetApp;
    std::vector<ManageFreezeExemptedAppInfo> needSetPolicy =
        ManageFreezeExemptedAppsSerializer::GetInstance()->SetNeedRemoveMergePolicyData(needRemoveMergePolicy,
        currentData, needSetApp);
    std::string freezeExemptedStr = SerializeApplicationInstanceVectorToJson(freezeExemptedApps);
    std::vector<ManageFreezeExemptedAppInfo> freezeExemptedData;
    ManageFreezeExemptedAppsSerializer::GetInstance()->Deserialize(freezeExemptedStr, freezeExemptedData);
    std::vector<ApplicationMsg> failedApps;
    std::vector<ManageFreezeExemptedAppInfo> failedData =
        ManageFreezeExemptedAppsSerializer::GetInstance()->SetNeedRemoveMergePolicyData(needRemoveMergePolicy,
        freezeExemptedData, failedApps);
    if (!failedApps.empty()) {
        EDMLOGE("OnRemovePolicy freezeExemptedApps has apps do not belong to current data");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    if (!needRemoveMergePolicy.empty()) {
        ErrCode ret = SetOtherModulePolicy(needSetApp);
        if (FAILED(ret)) {
            return ret;
        }
    }
    currentData = ManageFreezeExemptedAppsSerializer::GetInstance()->SetDifferencePolicyData(needRemovePolicy,
        currentData);
    mergeData = ManageFreezeExemptedAppsSerializer::GetInstance()->SetUnionPolicyData(currentData, mergeData);
    return ERR_OK;
}

ErrCode ManageFreezeExemptedAppsPlugin::SetOtherModulePolicy(const std::vector<ApplicationMsg> &freezeExemptedApps)
{
    EDMLOGI("ManageFreezeExemptedAppsPlugin SetOtherModulePolicy");
    uint32_t resType = ResourceSchedule::ResType::RES_TYPE_DYNAMICALLY_SET_SUSPEND_EXEMPT;
    int64_t value = 0;
    std::unordered_map<std::string, std::string> payload;
    payload["sources"] = PAYLOAD_RESOURCE;
    payload["size"] = std::to_string(freezeExemptedApps.size());
    auto bundleMgr = std::make_shared<EdmBundleManagerImpl>();
    for (size_t i = 0; i < freezeExemptedApps.size(); ++i) {
        std::string uidKey = "uid" + std::to_string(i + 1);
        std::string bundleNameKey = "bundleName" + std::to_string(i + 1);
        payload[uidKey] = std::to_string(bundleMgr->GetApplicationUid(freezeExemptedApps[i].bundleName,
        freezeExemptedApps[i].accountId, freezeExemptedApps[i].appIndex));
        payload[bundleNameKey] = freezeExemptedApps[i].bundleName;
    }
    std::unordered_map<std::string, std::string> reply;
    int32_t res = ResourceSchedule::ResSchedClient::GetInstance().ReportSyncEvent(resType, value, payload, reply);
    if (res != ERR_OK) {
        EDMLOGE("ManageFreezeExemptedAppsPlugin ResSchedClient ReportSyncEvent failed, res = %{public}d", res);
        return res;
    }
    return ERR_OK;
}

ErrCode ManageFreezeExemptedAppsPlugin::RemoveOtherModulePolicy()
{
    EDMLOGI("ManageFreezeExemptedAppsPlugin RemoveOtherModulePolicy");
    uint32_t resType = ResourceSchedule::ResType::RES_TYPE_DYNAMICALLY_SET_SUSPEND_EXEMPT;
    int64_t value = 0;
    std::unordered_map<std::string, std::string> payload;
    payload["sources"] = PAYLOAD_RESOURCE;
    payload["size"] = "0";
    std::unordered_map<std::string, std::string> reply;
    int32_t res = ResourceSchedule::ResSchedClient::GetInstance().ReportSyncEvent(resType, value, payload, reply);
    if (res != ERR_OK) {
        EDMLOGE("ManageFreezeExemptedAppsPlugin ResSchedClient ReportSyncEvent failed, res = %{public}d", res);
        return res;
    }
    return ERR_OK;
}

ErrCode ManageFreezeExemptedAppsPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data,
    MessageParcel &reply, int32_t userId)
{
    EDMLOGI("ManageFreezeExemptedAppsPlugin OnGetPolicy");
    std::string type = data.ReadString();
    std::vector<ManageFreezeExemptedAppInfo> appInfo;
    ManageFreezeExemptedAppsSerializer::GetInstance()->Deserialize(policyData, appInfo);
    std::vector<ApplicationMsg> policy;
    for (const ManageFreezeExemptedAppInfo &item : appInfo) {
        ApplicationMsg instance;
        instance.bundleName = item.GetBundleName();
        instance.accountId = item.GetAccountId();
        instance.appIndex = item.GetAppIndex();
        policy.emplace_back(std::move(instance));
    }
    reply.WriteInt32(ERR_OK);
    ApplicationInstanceHandle::WriteApplicationMsgVector(reply, policy);
    return ERR_OK;
}

ErrCode ManageFreezeExemptedAppsPlugin::OnAdminRemove(const std::string &adminName, const std::string &currentJsonData,
    const std::string &mergeJsonData, int32_t userId)
{
    EDMLOGI("ManageFreezeExemptedAppsPlugin OnAdminRemove");
    std::vector<ManageFreezeExemptedAppInfo> currentData;
    ManageFreezeExemptedAppsSerializer::GetInstance()->Deserialize(currentJsonData, currentData);
    std::vector<ManageFreezeExemptedAppInfo> mergeData;
    ManageFreezeExemptedAppsSerializer::GetInstance()->Deserialize(mergeJsonData, mergeData);
    std::vector<ApplicationMsg> freezeExemptedApps;
    std::vector<ManageFreezeExemptedAppInfo> needRemoveMergePolicy =
        ManageFreezeExemptedAppsSerializer::GetInstance()->SetNeedRemoveMergePolicyData(mergeData, currentData,
        freezeExemptedApps);
    return RemoveOtherModulePolicy();
}

ErrCode ManageFreezeExemptedAppsPlugin::GetOthersMergePolicyData(const std::string &adminName, int32_t userId,
    std::string &othersMergePolicyData)
{
    std::unordered_map<std::string, std::string> adminValues;
    IPolicyManager::GetInstance()->GetAdminByPolicyName(GetPolicyName(), adminValues, userId);
    EDMLOGI("IPolicyManager::GetOthersMergePolicyData %{public}s value size %{public}d", GetPolicyName().c_str(),
        (uint32_t)adminValues.size());
    if (adminValues.empty()) {
        return ERR_OK;
    }
    auto entry = adminValues.find(adminName);
    if (entry != adminValues.end()) {
        adminValues.erase(entry);
    }
    auto serializer = ManageFreezeExemptedAppsSerializer::GetInstance();
    std::vector<std::vector<ManageFreezeExemptedAppInfo>> data;
    for (const auto &item : adminValues) {
        std::vector<ManageFreezeExemptedAppInfo> dataItem;
        if (!item.second.empty()) {
            if (!serializer->Deserialize(item.second, dataItem)) {
                return ERR_EDM_OPERATE_JSON;
            }
            data.push_back(dataItem);
        }
    }
    std::vector<ManageFreezeExemptedAppInfo> result;
    if (!serializer->MergePolicy(data, result)) {
        return ERR_EDM_OPERATE_JSON;
    }

    std::string mergePolicyStr;
    IPolicyManager::GetInstance()->GetPolicy("", GetPolicyName(), mergePolicyStr, userId);
    std::vector<ManageFreezeExemptedAppInfo> mergePolicyData;
    if (!serializer->Deserialize(mergePolicyStr, mergePolicyData)) {
        return ERR_EDM_OPERATE_JSON;
    }

    if (!serializer->Serialize(result, othersMergePolicyData)) {
        return ERR_EDM_OPERATE_JSON;
    }

    return ERR_OK;
}

void ManageFreezeExemptedAppsPlugin::OnOtherServiceStart(int32_t systemAbilityId)
{
    EDMLOGI("ManageFreezeExemptedAppsPlugin::OnOtherServiceStart start");
    std::string mergePolicyStr;
    IPolicyManager::GetInstance()->GetPolicy("", GetPolicyName(), mergePolicyStr, EdmConstants::DEFAULT_USER_ID);
    std::vector<ManageFreezeExemptedAppInfo> mergePolicyData;
    auto serializer = ManageFreezeExemptedAppsSerializer::GetInstance();
    serializer->Deserialize(mergePolicyStr, mergePolicyData);
    std::vector<ApplicationMsg> freezeExemptedApps;
    for (const ManageFreezeExemptedAppInfo &appInfo : mergePolicyData) {
        ApplicationMsg instance;
        instance.bundleName = appInfo.GetBundleName();
        instance.accountId = appInfo.GetAccountId();
        instance.appIndex = appInfo.GetAppIndex();
        freezeExemptedApps.push_back(instance);
    }
    ErrCode ret = SetOtherModulePolicy(freezeExemptedApps);
    if (FAILED(ret)) {
        EDMLOGE("ManageFreezeExemptedAppsPlugin::OnOtherServiceStart failed ret: %{public}d", ret);
    }
}

std::vector<ManageFreezeExemptedAppInfo> ManageFreezeExemptedAppsPlugin::FilterUninstalledBundle(
    std::vector<ManageFreezeExemptedAppInfo> &data)
{
    auto bundleMgr = std::make_shared<EdmBundleManagerImpl>();
    std::vector<ManageFreezeExemptedAppInfo> uninstalledApp;
    for (const ManageFreezeExemptedAppInfo &appInfo : data) {
        std::string bundleName = appInfo.GetBundleName();
        int32_t accountId = appInfo.GetAccountId();
        int32_t appIndex = appInfo.GetAppIndex();
        if (!bundleMgr->IsBundleInstalled(bundleName, accountId, appIndex)) {
            uninstalledApp.push_back(appInfo);
        }
    }
    return uninstalledApp;
}

std::string ManageFreezeExemptedAppsPlugin::SerializeApplicationInstanceVectorToJson(
    const std::vector<ApplicationMsg> &apps)
{
    cJSON *root = cJSON_CreateArray();

    for (const auto &app : apps) {
        cJSON *appObj = cJSON_CreateObject();
        cJSON_AddStringToObject(appObj, "bundleName", app.bundleName.c_str());
        cJSON_AddNumberToObject(appObj, "accountId", app.accountId);
        cJSON_AddNumberToObject(appObj, "appIndex", app.appIndex);
        if (!cJSON_AddItemToArray(root, appObj)) {
            cJSON_Delete(appObj);
            cJSON_Delete(root);
            return "";
        }
    }

    char *jsonStr = cJSON_PrintUnformatted(root);
    std::string result(jsonStr);

    cJSON_Delete(root);
    free(jsonStr);

    return result;
}
} // namespace EDM
} // namespace OHOS