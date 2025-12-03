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
#include "manage_apps_serializer.h"
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
    maxListSize_ = EdmConstants::MANAGE_APPS_MAX_SIZE;
}

ErrCode ManageFreezeExemptedAppsPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data,
    MessageParcel &reply, HandlePolicyData &policyData, int32_t userId)
{
    EDMLOGI("ManageFreezeExemptedAppsPlugin OnHandlePolicy");
    uint32_t typeCode = FUNC_TO_OPERATE(funcCode);
    FuncOperateType type = FuncCodeUtils::ConvertOperateType(typeCode);
    std::vector<ApplicationInstance> freezeExemptedApps;
    ApplicationInstanceHandle::ReadApplicationInstanceVector(data, freezeExemptedApps);
    if (freezeExemptedApps.empty() || freezeExemptedApps.size() > maxListSize_) {
        EDMLOGE("ManageFreezeExemptedAppsPlugin OnHandlePolicy freezeExemptedApps is empty or too large");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    auto serializer = ManageAppsSerializer::GetInstance();
    std::vector<ApplicationInstance> currentData;
    std::vector<ApplicationInstance> mergeData;
    serializer->Deserialize(policyData.policyData, currentData);
    serializer->Deserialize(policyData.mergePolicyData, mergeData);
    std::string mergePolicyStr;
    IPolicyManager::GetInstance()->GetPolicy("", GetPolicyName(), mergePolicyStr, userId);
    ErrCode res;
    for (ApplicationInstance &appInstance : freezeExemptedApps) {
        if (appInstance.bundleName.empty()) {
            ApplicationInstanceHandle::GetBundleNameByAppId(appInstance);
        }
    }
    if (type == FuncOperateType::SET) {
        res = OnSetPolicy(freezeExemptedApps, currentData, mergeData);
    } else if (type == FuncOperateType::REMOVE) {
        res = OnRemovePolicy(freezeExemptedApps, currentData, mergeData);
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

ErrCode ManageFreezeExemptedAppsPlugin::OnSetPolicy(std::vector<ApplicationInstance> &freezeExemptedApps,
    std::vector<ApplicationInstance> &currentData, std::vector<ApplicationInstance> &mergeData)
{
    EDMLOGI("ManageFreezeExemptedAppsPlugin OnSetPolicy");
    auto serializer = ManageAppsSerializer::GetInstance();
    std::vector<ApplicationInstance> addData = serializer->SetDifferencePolicyData(currentData, freezeExemptedApps);
    std::vector<ApplicationInstance> UninstalledData = FilterUninstalledBundle(addData);
    if (!UninstalledData.empty()) {
        EDMLOGE("ManageFreezeExemptedAppsPlugin OnSetPolicy have uninstalled app");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    addData = serializer->SetDifferencePolicyData(UninstalledData, addData);
    std::vector<ApplicationInstance> needAddMergeData = serializer->SetDifferencePolicyData(mergeData, addData);
    std::vector<ApplicationInstance> afterHandle = serializer->SetUnionPolicyData(currentData, addData);
    std::vector<ApplicationInstance> afterMerge = serializer->SetUnionPolicyData(mergeData, afterHandle);
    if (afterMerge.size() > maxListSize_) {
        EDMLOGE("ManageFreezeExemptedAppsPlugin OnSetPolicy merge freezeExemptedApps is too large");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    if (!afterMerge.empty()) {
        ErrCode ret = SetOtherModulePolicy(afterMerge);
        if (FAILED(ret)) {
            EDMLOGE("ManageFreezeExemptedAppsPlugin OnSetPolicy SetOtherModulePolicy fail");
            return ret;
        }
    }
    currentData = afterHandle;
    mergeData = afterMerge;
    return ERR_OK;
}

ErrCode ManageFreezeExemptedAppsPlugin::OnRemovePolicy(std::vector<ApplicationInstance> &freezeExemptedApps,
    std::vector<ApplicationInstance> &currentData, std::vector<ApplicationInstance> &mergeData)
{
    EDMLOGI("ManageFreezeExemptedAppsPlugin OnRemovePolicy");
    auto serializer = ManageAppsSerializer::GetInstance();
    std::vector<ApplicationInstance> needRemovePolicy;
    std::vector<ApplicationInstance> needRemoveMergePolicy;
    std::vector<ApplicationInstance> needSetPolicy;
    needRemovePolicy = serializer->SetIntersectionPolicyData(freezeExemptedApps, currentData);
    needRemoveMergePolicy = serializer->SetNeedRemoveMergePolicyData(mergeData, needRemovePolicy);
    needSetPolicy = serializer->SetNeedRemoveMergePolicyData(needRemoveMergePolicy, currentData);
    std::vector<ApplicationInstance> failedData;
    failedData = serializer->SetNeedRemoveMergePolicyData(needRemoveMergePolicy, freezeExemptedApps);
    if (!failedData.empty()) {
        EDMLOGE("OnRemovePolicy freezeExemptedApps has apps do not belong to current data");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    if (!needRemoveMergePolicy.empty()) {
        ErrCode ret = SetOtherModulePolicy(needSetPolicy);
        if (FAILED(ret)) {
            EDMLOGE("ManageFreezeExemptedAppsPlugin OnRemovePolicy SetOtherModulePolicy fail");
            return ret;
        }
    }
    currentData = serializer->SetDifferencePolicyData(needRemovePolicy, currentData);
    mergeData = serializer->SetUnionPolicyData(currentData, mergeData);
    return ERR_OK;
}

ErrCode ManageFreezeExemptedAppsPlugin::SetOtherModulePolicy(const std::vector<ApplicationInstance> &freezeExemptedApps)
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
        EDMLOGE("ManageFreezeExemptedAppsPlugin SetOtherModulePolicy ReportSyncEvent fail, res = %{public}d", res);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode ManageFreezeExemptedAppsPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data,
    MessageParcel &reply, int32_t userId)
{
    EDMLOGI("ManageFreezeExemptedAppsPlugin OnGetPolicy");
    std::vector<ApplicationInstance> appInfo;
    ManageAppsSerializer::GetInstance()->Deserialize(policyData, appInfo);
    reply.WriteInt32(ERR_OK);
    ApplicationInstanceHandle::WriteApplicationInstanceVector(reply, appInfo);
    return ERR_OK;
}

ErrCode ManageFreezeExemptedAppsPlugin::OnAdminRemove(const std::string &adminName, const std::string &currentJsonData,
    const std::string &mergeJsonData, int32_t userId)
{
    EDMLOGI("ManageFreezeExemptedAppsPlugin OnAdminRemove");
    std::vector<ApplicationInstance> mergeData;
    ManageAppsSerializer::GetInstance()->Deserialize(mergeJsonData, mergeData);
    return SetOtherModulePolicy(mergeData);
}

ErrCode ManageFreezeExemptedAppsPlugin::GetOthersMergePolicyData(const std::string &adminName, int32_t userId,
    std::string &othersMergePolicyData)
{
    std::unordered_map<std::string, std::string> adminValues;
    IPolicyManager::GetInstance()->GetAdminByPolicyName(GetPolicyName(), adminValues, userId);
    EDMLOGI("ManageFreezeExemptedAppsPlugin GetOthersMergePolicyData %{public}s value size %{public}d",
        GetPolicyName().c_str(), (uint32_t)adminValues.size());
    if (adminValues.empty()) {
        return ERR_OK;
    }
    auto entry = adminValues.find(adminName);
    if (entry != adminValues.end()) {
        adminValues.erase(entry);
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

void ManageFreezeExemptedAppsPlugin::OnOtherServiceStart(int32_t systemAbilityId)
{
    EDMLOGI("ManageFreezeExemptedAppsPlugin OnOtherServiceStart");
    std::string mergePolicyStr;
    IPolicyManager::GetInstance()->GetPolicy("", GetPolicyName(), mergePolicyStr, EdmConstants::DEFAULT_USER_ID);
    std::vector<ApplicationInstance> mergePolicyData;
    ManageAppsSerializer::GetInstance()->Deserialize(mergePolicyStr, mergePolicyData);
    ErrCode ret = SetOtherModulePolicy(mergePolicyData);
    if (FAILED(ret)) {
        EDMLOGE("ManageFreezeExemptedAppsPlugin OnOtherServiceStart fail, ret: %{public}d", ret);
    }
}

std::vector<ApplicationInstance> ManageFreezeExemptedAppsPlugin::FilterUninstalledBundle(
    std::vector<ApplicationInstance> &data)
{
    auto bundleMgr = std::make_shared<EdmBundleManagerImpl>();
    std::vector<ApplicationInstance> uninstalledApp;
    for (const ApplicationInstance &appInfo : data) {
        if (!bundleMgr->IsBundleInstalled(appInfo.bundleName, appInfo.accountId, appInfo.appIndex)) {
            uninstalledApp.push_back(appInfo);
        }
    }
    return uninstalledApp;
}
} // namespace EDM
} // namespace OHOS