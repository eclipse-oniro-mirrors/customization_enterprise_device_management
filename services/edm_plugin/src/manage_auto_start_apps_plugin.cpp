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

#include "manage_auto_start_apps_plugin.h"

#include <algorithm>

#include "app_control/app_control_proxy.h"
#include <bundle_info.h>
#include <bundle_mgr_interface.h>
#include <system_ability_definition.h>

#include "ability_auto_startup_client.h"
#include "manage_auto_start_apps_serializer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_sys_manager.h"
#include "element_name.h"
#include "iplugin_manager.h"
#include "ipolicy_manager.h"
#include "func_code_utils.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<ManageAutoStartAppsPlugin>());
const std::string SEPARATOR = "/";
const ErrCode ERR_NO_STATUS_BAR_ABILITY = 29360136;
const ErrCode ERR_CAPABILITY_NOT_SUPPORT = 2097230;

ManageAutoStartAppsPlugin::ManageAutoStartAppsPlugin()
{
    policyCode_ = EdmInterfaceCode::MANAGE_AUTO_START_APPS;
    policyName_ = PolicyName::POLICY_MANAGE_AUTO_START_APPS;
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION);
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = true;
    maxListSize_ = EdmConstants::AUTO_START_APPS_MAX_SIZE;
}

ErrCode ManageAutoStartAppsPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    EDMLOGI("ManageAutoStartAppsPlugin OnHandlePolicy.");
    uint32_t typeCode = FUNC_TO_OPERATE(funcCode);
    FuncOperateType type = FuncCodeUtils::ConvertOperateType(typeCode);
    std::vector<std::string> autoStartApps;
    data.ReadStringVector(&autoStartApps);
    bool disallowModify = false;
    data.ReadBool(disallowModify);
    std::vector<ManageAutoStartAppInfo> currentData;
    bool isDeserializeOk = false;
    isDeserializeOk = ManageAutoStartAppsSerializer::GetInstance()->Deserialize(policyData.policyData, currentData);
    std::vector<ManageAutoStartAppInfo> mergeData;
    isDeserializeOk = isDeserializeOk &&
        ManageAutoStartAppsSerializer::GetInstance()->Deserialize(policyData.mergePolicyData, mergeData);
    std::string mergePolicyStr;
    IPolicyManager::GetInstance()->GetPolicy("", GetPolicyName(), mergePolicyStr, userId);
    std::vector<ManageAutoStartAppInfo> totalMergePolicyData;
    isDeserializeOk = isDeserializeOk &&
        ManageAutoStartAppsSerializer::GetInstance()->Deserialize(mergePolicyStr, totalMergePolicyData);
    if (!isDeserializeOk) {
        EDMLOGE("ManageAutoStartAppsPlugin OnHandlePolicy Deserialize failed.");
    }
    ManageAutoStartAppsSerializer::GetInstance()->UpdateByMergePolicy(currentData,
        totalMergePolicyData);
    ErrCode res = EdmReturnErrCode::PARAM_ERROR;
    std::string errMessage;
    if (type == FuncOperateType::SET) {
        res = OnSetPolicy(autoStartApps, disallowModify, currentData, mergeData, userId);
        GetErrorMessage(res, errMessage);
    } else if (type == FuncOperateType::REMOVE) {
        res = OnRemovePolicy(autoStartApps, currentData, mergeData, userId);
        GetErrorMessage(res, errMessage);
    }
    if (res != ERR_OK) {
        reply.WriteInt32(res);
        reply.WriteString(errMessage);
        return res;
    }
    reply.WriteInt32(ERR_OK);
    std::string afterHandle;
    std::string afterMerge;
    bool isSerializeOk = ManageAutoStartAppsSerializer::GetInstance()->Serialize(currentData, afterHandle);
    isSerializeOk = isSerializeOk && ManageAutoStartAppsSerializer::GetInstance()->Serialize(mergeData, afterMerge);
    if (!isSerializeOk) {
        EDMLOGE("ManageAutoStartAppsPlugin OnHandlePolicy Serialize failed.");
    }
    policyData.isChanged = (policyData.policyData != afterHandle || mergePolicyStr != afterMerge);
    policyData.policyData = afterHandle;
    policyData.mergePolicyData = afterMerge;
    return ERR_OK;
}

ErrCode ManageAutoStartAppsPlugin::OnRemovePolicy(std::vector<std::string> &data,
    std::vector<ManageAutoStartAppInfo> &currentData, std::vector<ManageAutoStartAppInfo> &mergeData, int32_t userId)
{
    if (data.empty()) {
        EDMLOGW("BasicArrayStringPlugin OnRemovePolicy data is empty.");
        return ERR_OK;
    }
    if (data.size() > maxListSize_) {
        EDMLOGE("BasicArrayStringPlugin OnRemovePolicy input data is too large.");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::vector<ManageAutoStartAppInfo> needRemovePolicy =
        ManageAutoStartAppsSerializer::GetInstance()->SetIntersectionPolicyData(data, currentData);
    std::vector<ManageAutoStartAppInfo> needRemoveMergePolicy =
        ManageAutoStartAppsSerializer::GetInstance()->SetNeedRemoveMergePolicyData(mergeData, needRemovePolicy);

    std::vector<ManageAutoStartAppInfo> failedData;
    if (!needRemoveMergePolicy.empty()) {
        ErrCode ret = SetOrRemoveOtherModulePolicy(needRemoveMergePolicy, false, failedData, userId);
        if (FAILED(ret)) {
            return ret;
        }
    }
    if (failedData.empty()) {
        currentData = ManageAutoStartAppsSerializer::GetInstance()->SetDifferencePolicyData(needRemovePolicy,
            currentData);
    } else {
        auto removeData = ManageAutoStartAppsSerializer::GetInstance()->SetDifferencePolicyData(failedData,
            needRemovePolicy);
        currentData = ManageAutoStartAppsSerializer::GetInstance()->SetDifferencePolicyData(removeData,
            currentData);
    }
    mergeData = ManageAutoStartAppsSerializer::GetInstance()->SetUnionPolicyData(currentData, mergeData);
    return ERR_OK;
}

ErrCode ManageAutoStartAppsPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("ManageAutoStartAppsPlugin OnGetPolicy.");
    std::string type = data.ReadString();
    if (type == EdmConstants::AutoStart::GET_MANAGE_AUTO_START_APPS_BUNDLE_INFO) {
        std::vector<ManageAutoStartAppInfo> appInfos;
        ManageAutoStartAppsSerializer::GetInstance()->Deserialize(policyData, appInfos);
        std::vector<std::string> policies;
        for (const ManageAutoStartAppInfo &item : appInfos) {
            std::string isHiddenStartStr = item.GetIsHiddenStart() ? "true" : "false";
            policies.push_back(item.GetUniqueKey() + "/" + isHiddenStartStr);
            EDMLOGD("GetAutoStartApps parse auto start app join isHiddenStart OK");
        }
        reply.WriteInt32(ERR_OK);
        reply.WriteStringVector(policies);
    } else if (type == EdmConstants::AutoStart::GET_MANAGE_AUTO_START_APP_DISALLOW_MODIFY) {
        std::string uniqueKey = data.ReadString();
        std::string mergePolicyStr;
        IPolicyManager::GetInstance()->GetPolicy("", GetPolicyName(), mergePolicyStr, userId);
        std::vector<ManageAutoStartAppInfo> mergePolicyData;
        ManageAutoStartAppsSerializer::GetInstance()->Deserialize(mergePolicyStr, mergePolicyData);
        bool hasSetAutoStart = false;
        for (const ManageAutoStartAppInfo &item : mergePolicyData) {
            if (item.GetUniqueKey() == uniqueKey) {
                reply.WriteInt32(ERR_OK);
                reply.WriteBool(item.GetDisallowModify());
                hasSetAutoStart = true;
                break;
            }
        }
        if (!hasSetAutoStart) {
            reply.WriteInt32(ERR_OK);
            reply.WriteBool(false);
        }
    } else {
        EDMLOGE("ManageAutoStartAppsPlugin::OnGetPolicy type error");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode ManageAutoStartAppsPlugin::OnAdminRemove(const std::string &adminName, const std::string &currentJsonData,
    const std::string &mergeJsonData, int32_t userId)
{
    EDMLOGI("ManageAutoStartAppsPlugin OnAdminRemoveDone");
    
    std::vector<ManageAutoStartAppInfo> currentData;
    ManageAutoStartAppsSerializer::GetInstance()->Deserialize(currentJsonData, currentData);
    std::vector<ManageAutoStartAppInfo> mergeData;
    ManageAutoStartAppsSerializer::GetInstance()->Deserialize(mergeJsonData, mergeData);
    std::vector<ManageAutoStartAppInfo> needRemoveMergePolicy =
        ManageAutoStartAppsSerializer::GetInstance()->SetNeedRemoveMergePolicyData(mergeData, currentData);
    std::vector<ManageAutoStartAppInfo> failedData;
    return SetOrRemoveOtherModulePolicy(needRemoveMergePolicy, false, failedData, userId);
}

ErrCode ManageAutoStartAppsPlugin::GetOthersMergePolicyData(const std::string &adminName, int32_t userId,
    std::string &othersMergePolicyData)
{
    std::unordered_map<std::string, std::string> adminValues;
    IPolicyManager::GetInstance()->GetAdminByPolicyName(GetPolicyName(), adminValues, userId);
    EDMLOGI("ManageAutoStartAppsPlugin::GetOthersMergePolicyData %{public}s value size %{public}d.",
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
    auto serializer = ManageAutoStartAppsSerializer::GetInstance();
    std::vector<std::vector<ManageAutoStartAppInfo>> data;
    for (const auto &item : adminValues) {
        std::vector<ManageAutoStartAppInfo> dataItem;
        if (!item.second.empty()) {
            if (!serializer->Deserialize(item.second, dataItem)) {
                return ERR_EDM_OPERATE_JSON;
            }
            data.push_back(dataItem);
        }
    }
    std::vector<ManageAutoStartAppInfo> result;
    if (!serializer->MergePolicy(data, result)) {
        return ERR_EDM_OPERATE_JSON;
    }

    std::string mergePolicyStr;
    IPolicyManager::GetInstance()->GetPolicy("", GetPolicyName(), mergePolicyStr, userId);
    std::vector<ManageAutoStartAppInfo> mergePolicyData;
    if (!serializer->Deserialize(mergePolicyStr, mergePolicyData)) {
        return ERR_EDM_OPERATE_JSON;
    }

    if (!serializer->UpdateByMergePolicy(result, mergePolicyData)) {
        return ERR_EDM_OPERATE_JSON;
    }

    if (!serializer->Serialize(result, othersMergePolicyData)) {
        return ERR_EDM_OPERATE_JSON;
    }

    return ERR_OK;
}

void ManageAutoStartAppsPlugin::ParseErrCode(ErrCode &res)
{
    if (res != ERR_NO_STATUS_BAR_ABILITY && res != ERR_CAPABILITY_NOT_SUPPORT && res != ERR_OK) {
        res = EdmReturnErrCode::PARAM_ERROR;
    }
}
 
void ManageAutoStartAppsPlugin::GetErrorMessage(ErrCode &errCode, std::string &errMessage)
{
    switch (errCode) {
        case ERR_NO_STATUS_BAR_ABILITY:
            errCode = EdmReturnErrCode::ADD_AUTO_START_APP_FAILED;
            errMessage = "Parameter error. Application does not have status bar ability.";
            break;
        case ERR_CAPABILITY_NOT_SUPPORT:
            errCode = EdmReturnErrCode::ADD_AUTO_START_APP_FAILED;
            errMessage = "Add auto start applications failed. The system ability works abnormally.";
            break;
        default:
            break;
    }
}

void ManageAutoStartAppsPlugin::ParseManageAutoStartAppsInfo(std::vector<std::string> &data, bool disallowModify,
    std::vector<ManageAutoStartAppInfo> &appInfoArray)
{
    for (const auto &item : data) {
        ManageAutoStartAppInfo appInfo;
        if (item.rfind("/") == std::string::npos) {
            continue;
        }
        size_t index = item.rfind("/");
        std::string uniqueKey = item.substr(0, index);
        appInfo.SetUniqueKey(uniqueKey);
        appInfo.SetDisallowModify(disallowModify);
        std::string isHiddenStartStr = item.substr(index + 1);
        bool isHiddenStart = isHiddenStartStr == "true";
        appInfo.SetIsHiddenStart(isHiddenStart);
        appInfoArray.push_back(appInfo);
    }
}

ErrCode ManageAutoStartAppsPlugin::OnSetPolicy(std::vector<std::string> &data, bool disallowModify,
    std::vector<ManageAutoStartAppInfo> &currentData, std::vector<ManageAutoStartAppInfo> &mergeData, int32_t userId)
{
    if (data.empty()) {
        EDMLOGW("ManageAutoStartAppsPlugin OnSetPolicy data is empty.");
        return ERR_OK;
    }
    if (data.size() > maxListSize_) {
        EDMLOGE("ManageAutoStartAppsPlugin OnSetPolicy input data is too large.");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::vector<ManageAutoStartAppInfo> tmpData;
    ParseManageAutoStartAppsInfo(data, disallowModify, tmpData);
    if (tmpData.empty()) {
        EDMLOGE("ManageAutoStartAppsPlugin OnSetPolicy input data is error.");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::vector<ManageAutoStartAppInfo> addData =
        ManageAutoStartAppsSerializer::GetInstance()->SetDifferencePolicyData(currentData, tmpData);
    std::vector<ManageAutoStartAppInfo> needAddMergeData =
        ManageAutoStartAppsSerializer::GetInstance()->SetDifferencePolicyData(mergeData, addData);
    std::vector<ManageAutoStartAppInfo> afterHandle =
        ManageAutoStartAppsSerializer::GetInstance()->SetUnionPolicyData(currentData, addData);
    std::vector<ManageAutoStartAppInfo> afterMerge =
        ManageAutoStartAppsSerializer::GetInstance()->SetUnionPolicyData(mergeData, afterHandle);
    if (afterMerge.size() > maxListSize_) {
        EDMLOGE("ManageAutoStartAppsPlugin OnSetPolicy merge data is too large.");
        return EdmReturnErrCode::PARAM_ERROR;
    }

    std::vector<ManageAutoStartAppInfo> failedData;
    if (!needAddMergeData.empty()) {
        ErrCode ret = SetOrRemoveOtherModulePolicy(needAddMergeData, true, failedData, userId);
        if (FAILED(ret)) {
            return ret;
        }
    }
    if (failedData.empty()) {
        currentData = afterHandle;
        mergeData = afterMerge;
    } else {
        currentData = ManageAutoStartAppsSerializer::GetInstance()->SetDifferencePolicyData(failedData, afterHandle);
        mergeData = ManageAutoStartAppsSerializer::GetInstance()->SetDifferencePolicyData(failedData, afterMerge);
    }
    return ERR_OK;
}

ErrCode ManageAutoStartAppsPlugin::SetOrRemoveOtherModulePolicy(const std::vector<ManageAutoStartAppInfo> &data,
    bool isSet, std::vector<ManageAutoStartAppInfo> &failedData, int32_t userId)
{
    EDMLOGI("ManageAutoStartAppsPlugin SetOrRemoveOtherModulePolicy: %{public}d.", isSet);
    auto autoStartupClient = AAFwk::AbilityAutoStartupClient::GetInstance();
    if (!autoStartupClient) {
        EDMLOGE("ManageAutoStartAppsPlugin SetOrRemoveOtherModulePolicy GetAppControlProxy failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    bool flag = false;
    ErrCode res = ERR_OK;
    for (const ManageAutoStartAppInfo &item : data) {
        OHOS::AbilityRuntime::AutoStartupInfo autoStartupInfo;
        autoStartupInfo.bundleName = item.GetBundleName();
        autoStartupInfo.abilityName = item.GetAbilityName();
        autoStartupInfo.userId = userId;
        if (!CheckBundleAndAbilityExited(autoStartupInfo.bundleName, autoStartupInfo.abilityName, userId)) {
            EDMLOGW("CheckBundleAndAbilityExited failed bundleName: %{public}s, abilityName: %{public}s",
                autoStartupInfo.bundleName.c_str(), autoStartupInfo.abilityName.c_str());
            if (!isSet) {
                flag = true;
            }
            failedData.push_back(item);
            res = EdmReturnErrCode::PARAM_ERROR;
            continue;
        }
        if (isSet) {
            bool isHiddenStart = item.GetIsHiddenStart();
            EDMLOGD("OnSetPolicy bundleName : %{public}s abilityName:%{public}s isHiddenStart is %{public}d",
                autoStartupInfo.bundleName.c_str(), autoStartupInfo.abilityName.c_str(), isHiddenStart);
            res = autoStartupClient->SetApplicationAutoStartupByEDM(autoStartupInfo, item.GetDisallowModify(),
                isHiddenStart);
        } else {
            res = autoStartupClient->CancelApplicationAutoStartupByEDM(autoStartupInfo, item.GetDisallowModify());
        }
        if (res != ERR_OK) {
            EDMLOGW("OnRemovePolicy SetOrCancelApplicationAutoStartupByEDM err res: %{public}d bundleName: %{public}s "
                "abilityName:%{public}s", res, autoStartupInfo.bundleName.c_str(), autoStartupInfo.abilityName.c_str());
            failedData.push_back(item);
            continue;
        }
        flag = true;
    }
    ParseErrCode(res);
    return flag ? ERR_OK : res;
}

bool ManageAutoStartAppsPlugin::CheckBundleAndAbilityExited(const std::string &bundleName,
    const std::string &abilityName, int32_t userId)
{
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (!proxy) {
        EDMLOGE("EnterpriseDeviceMgrAbility::GetAllPermissionsByAdmin GetBundleMgr failed.");
        return false;
    }

    std::vector<AppExecFwk::AbilityInfo> abilityInfos;
    AppExecFwk::ElementName element;
    element.SetBundleName(bundleName);
    element.SetAbilityName(abilityName);
    OHOS::AppExecFwk::IBundleMgr::Want want;
    want.SetElement(element);
    std::vector<AppExecFwk::ExtensionAbilityInfo> extensionAbilityInfo;
    return proxy->QueryAbilityInfos(want, AppExecFwk::AbilityInfoFlag::GET_ABILITY_INFO_DEFAULT,
        userId, abilityInfos) ||
        proxy->QueryExtensionAbilityInfos(want, AppExecFwk::ExtensionAbilityType::SERVICE,
            AppExecFwk::ExtensionAbilityInfoFlag::GET_EXTENSION_INFO_DEFAULT, userId,
            extensionAbilityInfo);
}
} // namespace EDM
} // namespace OHOS
