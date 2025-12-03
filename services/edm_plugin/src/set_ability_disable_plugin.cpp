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

#include "set_ability_disable_plugin.h"
 
#include <memory>
#include <regex>
#include <system_ability_definition.h>
#include "array_string_serializer.h"
#include "edm_constants.h"
#include "iplugin_manager.h"
#include "func_code_utils.h"
#include "edm_ipc_interface_code.h"
#include "application_instance.h"
#include "bundle_mgr_interface.h"
#include "edm_sys_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(
    std::make_shared<SetAbilityDisablePlugin>());

const std::string SEPARATOR = "/";
constexpr int32_t BUNDLENAME_INDEX = 0;
constexpr int32_t APPINDEX_INDEX = 1;
constexpr int32_t ACCOUNTID_INDEX = 2;
constexpr int32_t ABILITY_INDEX = 3;
constexpr int32_t MAX_INDEX = 4;

SetAbilityDisablePlugin::SetAbilityDisablePlugin()
{
    policyCode_ = EdmInterfaceCode::SET_ABILITY_ENABLED;
    policyName_ = PolicyName::POLICY_SET_ABILITY_ENABLED;
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION);
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = true;
}

ErrCode SetAbilityDisablePlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data,
    MessageParcel &reply, HandlePolicyData &policyData, int32_t userId)
{
    EDMLOGD("SetAbilityDisablePlugin::OnHandlePolicy start");
    uint32_t typeCode = FUNC_TO_OPERATE(funcCode);
    FuncOperateType type = FuncCodeUtils::ConvertOperateType(typeCode);
    if (type == FuncOperateType::SET) {
        std::string abilityName = data.ReadString();
        bool isDisable = data.ReadBool();
        ApplicationMsg userApp;
        ApplicationInstanceHandle::ReadApplicationInstance(data, userApp);
        ErrCode ret = SetDisableByBundle(userApp, abilityName, !isDisable);
        if (ret == ERR_OK) {
            SetPolicyData(policyData, userApp, abilityName, isDisable);
        }
        return ret;
    } else if (type == FuncOperateType::REMOVE) {
        ApplicationMsg userApp;
        ApplicationInstanceHandle::ReadApplicationInstance(data, userApp);
        OnRemovePolicy(userApp, policyData);
    }
    return ERR_OK;
}

void SetAbilityDisablePlugin::SetPolicyData(HandlePolicyData &policyData,
    const ApplicationMsg &application, const std::string &abilityName, bool isDisable)
{
    std::vector<std::string> data;
    std::string name = application.bundleName + SEPARATOR + std::to_string(application.appIndex) +
        SEPARATOR + std::to_string(application.accountId) + SEPARATOR + abilityName;
    data.push_back(name);
    auto serializer = ArrayStringSerializer::GetInstance();
    std::vector<std::string> currentPolicies;
    std::vector<std::string> currentMergePolicies;
    serializer->Deserialize(policyData.policyData, currentPolicies);
    serializer->Deserialize(policyData.mergePolicyData, currentMergePolicies);
    std::string afterHandle;
    std::string afterMerge;
    std::vector<std::string> policies;
    std::vector<std::string> mergePolicies;
    if (isDisable) {
        policies = serializer->SetUnionPolicyData(data, currentPolicies);
        mergePolicies = serializer->SetUnionPolicyData(data, currentMergePolicies);
    } else {
        policies = serializer->SetDifferencePolicyData(data, currentPolicies);
        mergePolicies = serializer->SetDifferencePolicyData(data, currentMergePolicies);
    }
    serializer->Serialize(policies, afterHandle);
    serializer->Serialize(mergePolicies, afterMerge);
    policyData.isChanged = true;
    policyData.policyData = afterHandle;
    policyData.mergePolicyData = afterMerge;
}

ErrCode SetAbilityDisablePlugin::OnGetPolicy(std::string &policyData, MessageParcel &data,
    MessageParcel &reply, int32_t userId)
{
    EDMLOGD("SetAbilityDisablePlugin::OnGetPolicy start");
    std::string abilityName = data.ReadString();
    ApplicationMsg userApp;
    ApplicationInstanceHandle::ReadApplicationInstance(data, userApp);
    std::string name = userApp.bundleName + SEPARATOR + std::to_string(userApp.appIndex) +
        SEPARATOR + std::to_string(userApp.accountId) + SEPARATOR + abilityName;

    bool isDisable = false;
    std::vector<std::string> currentPolicies;
    ArrayStringSerializer::GetInstance()->Deserialize(policyData, currentPolicies);
    if (std::find(currentPolicies.begin(), currentPolicies.end(), name) != currentPolicies.end()) {
        isDisable = true;
    }
        
    reply.WriteInt32(ERR_OK);
    reply.WriteBool(isDisable);
    return ERR_OK;
}

ErrCode SetAbilityDisablePlugin::GetAppInfoByPolicyData(const std::string policyData,
    ApplicationMsg &application, std::string &abilityName)
{
    std::vector<std::string> parts;
    size_t start = 0;
    size_t end = policyData.find(SEPARATOR);
    while (end != policyData.npos) {
        parts.push_back(policyData.substr(start, end - start));
        start = end + 1;
        end = policyData.find(SEPARATOR, start);
    }
    parts.push_back(policyData.substr(start));

    if (parts.size() != MAX_INDEX) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }

    application.bundleName = parts[BUNDLENAME_INDEX];
    application.appIndex = std::stoi(parts[APPINDEX_INDEX]);
    application.accountId = std::stoi(parts[ACCOUNTID_INDEX]);
    abilityName = parts[ABILITY_INDEX];

    return ERR_OK;
}

void SetAbilityDisablePlugin::OnRemovePolicy(ApplicationMsg &application, HandlePolicyData &policyData)
{
    auto serializer = ArrayStringSerializer::GetInstance();
    std::vector<std::string> currentPolicies;
    std::vector<std::string> currentMergePolicies;
    serializer->Deserialize(policyData.policyData, currentPolicies);
    serializer->Deserialize(policyData.mergePolicyData, currentMergePolicies);
    std::string removeItem = application.bundleName + SEPARATOR + std::to_string(application.appIndex) +
        SEPARATOR + std::to_string(application.accountId);
    std::vector<std::string> removeVec;
    for (auto policy : currentPolicies) {
        if (policy.find(removeItem) != std::string::npos) {
            removeVec.push_back(policy);
        }
    }
    std::string afterHandle;
    std::string afterMerge;
    std::vector<std::string> policies;
    std::vector<std::string> mergePolicies;
    policies = serializer->SetDifferencePolicyData(removeVec, currentPolicies);
    mergePolicies = serializer->SetDifferencePolicyData(removeVec, currentMergePolicies);
    
    serializer->Serialize(policies, afterHandle);
    serializer->Serialize(mergePolicies, afterMerge);
    policyData.isChanged = true;
    policyData.policyData = afterHandle;
    policyData.mergePolicyData = afterMerge;
}

ErrCode SetAbilityDisablePlugin::SetDisableByBundle(const ApplicationMsg &application,
    const std::string &abilityName, bool isDisable)
{
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (!proxy) {
        EDMLOGE("EnterpriseDeviceMgrAbility::GetAllPermissionsByAdmin GetBundleMgr failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::vector<OHOS::AppExecFwk::AbilityInfo> abilityInfos;
    AppExecFwk::ElementName element;
    element.SetBundleName(application.bundleName);
    element.SetAbilityName(abilityName);
    OHOS::AppExecFwk::IBundleMgr::Want want;
    want.SetElement(element);
    bool res = proxy->QueryAbilityInfos(want, AppExecFwk::AbilityInfoFlag::GET_ABILITY_INFO_WITH_DISABLE,
        application.accountId, abilityInfos);
    if (res && application.appIndex >= 0 && abilityInfos.size() > static_cast<size_t>(application.appIndex)) {
        ErrCode ret = proxy->SetCloneAbilityEnabled(abilityInfos[application.appIndex], application.appIndex,
            isDisable, application.accountId);
        if (FAILED(ret)) {
            EDMLOGE("SetAbilityEnabled failed, ret: %{public}d", ret);
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    } else {
        EDMLOGE("QueryAbilityInfos is empty");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }

    return ERR_OK;
}

ErrCode SetAbilityDisablePlugin::OnAdminRemove(const std::string &adminName, const std::string &policyData,
    const std::string &mergeData, int32_t userId)
{
    auto serializer = ArrayStringSerializer::GetInstance();
    std::vector<std::string> mergePolicies;
    if (!serializer->Deserialize(mergeData, mergePolicies)) {
        EDMLOGE("OnHandlePolicy Deserialize current policy and merge policy failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    for (std::string policy : mergePolicies) {
        ApplicationMsg application;
        std::string abilityName;
        if (GetAppInfoByPolicyData(policy, application, abilityName) == ERR_OK) {
            SetDisableByBundle(application, abilityName, true);
        } else {
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }

    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS