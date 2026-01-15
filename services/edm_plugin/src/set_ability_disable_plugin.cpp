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
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<SetAbilityDisablePlugin>());

const std::string SEPARATOR = "/";

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
    uint32_t typeCode = FUNC_TO_OPERATE(funcCode);
    FuncOperateType type = FuncCodeUtils::ConvertOperateType(typeCode);
    if (type != FuncOperateType::SET) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::string bundleName = data.ReadString();
    std::string abilityName = data.ReadString();
    bool isDisable = data.ReadBool();
    std::vector<std::string> currentPolicy;
    ArrayStringSerializer::GetInstance()->Deserialize(policyData.policyData, currentPolicy);
    std::vector<std::string> mergePolicy;
    ArrayStringSerializer::GetInstance()->Deserialize(policyData.mergePolicyData, mergePolicy);
    EDMLOGI("SetAbilityDisablePlugin::OnHandlePolicy %{public}d start.", isDisable);
    ErrCode ret = EdmReturnErrCode::SYSTEM_ABNORMALLY;
    if (isDisable) {
        ret = SetPolicy(bundleName, abilityName, currentPolicy, mergePolicy, userId);
    } else {
        ret = RemovePolicy(bundleName, abilityName, currentPolicy, mergePolicy, userId);
    }
    if (FAILED(ret)) {
        return ret;
    }
    ArrayStringSerializer::GetInstance()->Serialize(currentPolicy, policyData.policyData);
    ArrayStringSerializer::GetInstance()->Serialize(mergePolicy, policyData.mergePolicyData);
    policyData.isChanged = true;
    return ERR_OK;
}

ErrCode SetAbilityDisablePlugin::SetPolicy(const std::string &bundleName, const std::string &abilityName,
    std::vector<std::string> &currentPolicy, std::vector<std::string> &mergePolicy, int32_t userId)
{
    std::string data = bundleName + SEPARATOR + abilityName;
    if (std::find(currentPolicy.begin(), currentPolicy.end(), data) != currentPolicy.end()) {
        mergePolicy = ArrayStringSerializer::GetInstance()->SetUnionPolicyData(currentPolicy, mergePolicy);
        return ERR_OK;
    }
    if (std::find(mergePolicy.begin(), mergePolicy.end(), data) == mergePolicy.end()) {
        if (FAILED(SetAbilityDisabled(bundleName, userId, abilityName, true))) {
            return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
        }
    }
    currentPolicy.push_back(data);
    mergePolicy = ArrayStringSerializer::GetInstance()->SetUnionPolicyData(currentPolicy, mergePolicy);
    return ERR_OK;
}

ErrCode SetAbilityDisablePlugin::RemovePolicy(const std::string &bundleName, const std::string &abilityName,
    std::vector<std::string> &currentPolicy, std::vector<std::string> &mergePolicy, int32_t userId)
{
    std::string data = bundleName + SEPARATOR + abilityName;
    if (std::find(currentPolicy.begin(), currentPolicy.end(), data) == currentPolicy.end()) {
        mergePolicy = ArrayStringSerializer::GetInstance()->SetUnionPolicyData(currentPolicy, mergePolicy);
        return ERR_OK;
    }
    if (std::find(mergePolicy.begin(), mergePolicy.end(), data) == mergePolicy.end()) {
        if (FAILED(SetAbilityDisabled(bundleName, userId, abilityName, false))) {
            return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
        }
    }
    auto iter = std::remove(currentPolicy.begin(), currentPolicy.end(), data);
    currentPolicy.erase(iter, currentPolicy.end());
    mergePolicy = ArrayStringSerializer::GetInstance()->SetUnionPolicyData(currentPolicy, mergePolicy);
    return ERR_OK;
}

ErrCode SetAbilityDisablePlugin::SetAbilityDisabled(const std::string &bundleName, int32_t userId,
    const std::string &abilityName, bool isDisabled)
{
    EDMLOGI("SetAbilityDisablePlugin::SetAbilityDisabled %{public}d start.", isDisabled);
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (!proxy) {
        EDMLOGE("SetAbilityDisablePlugin::SetAbilityDisabled GetBundleMgr failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::vector<OHOS::AppExecFwk::AbilityInfo> abilityInfos;
    AppExecFwk::ElementName element;
    element.SetBundleName(bundleName);
    element.SetAbilityName(abilityName);
    OHOS::AppExecFwk::IBundleMgr::Want want;
    want.SetElement(element);
    bool res = proxy->QueryAbilityInfos(want, AppExecFwk::AbilityInfoFlag::GET_ABILITY_INFO_WITH_DISABLE,
        userId, abilityInfos);
    if (!res) {
        EDMLOGE("SetAbilityDisablePlugin::SetAbilityDisabled QueryAbilityInfos failed.");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    for (size_t appIndex = 0; appIndex < abilityInfos.size(); ++appIndex) {
        ErrCode ret = proxy->SetCloneAbilityEnabled(abilityInfos[appIndex], appIndex, !isDisabled, userId);
        if (FAILED(ret)) {
            EDMLOGE("SetAbilityEnabled failed, ret: %{public}d", ret);
        }
    }
    return ERR_OK;
}

ErrCode SetAbilityDisablePlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    std::string bundleName = data.ReadString();
    std::string abilityName = data.ReadString();
    std::string name = bundleName + SEPARATOR + abilityName;
    std::vector<std::string> currentPolicies;
    ArrayStringSerializer::GetInstance()->Deserialize(policyData, currentPolicies);
    bool isDisable = std::find(currentPolicies.begin(), currentPolicies.end(), name) != currentPolicies.end();
    reply.WriteInt32(ERR_OK);
    reply.WriteBool(isDisable);
    return ERR_OK;
}

ErrCode SetAbilityDisablePlugin::OnAdminRemove(const std::string &adminName, const std::string &currentData,
    const std::string &mergeData, int32_t userId)
{
    std::vector<std::string> currentPolicy;
    ArrayStringSerializer::GetInstance()->Deserialize(currentData, currentPolicy);
    std::vector<std::string> mergePolicy;
    ArrayStringSerializer::GetInstance()->Deserialize(mergeData, mergePolicy);
    std::vector<std::string> needRemovePolicy =
        ArrayStringSerializer::GetInstance()->SetDifferencePolicyData(mergePolicy, currentPolicy);
    for (const std::string &policy : needRemovePolicy) {
        size_t index = policy.find(SEPARATOR);
        if (index == policy.npos) {
            continue;
        }
        SetAbilityDisabled(policy.substr(0, index), userId, policy.substr(index + 1), false);
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS