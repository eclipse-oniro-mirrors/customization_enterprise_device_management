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

#include "disabled_network_interface_plugin.h"

#include "net_policy_client.h"
#include "netsys_controller.h"
#include "system_ability_definition.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_sys_manager.h"
#include "map_string_serializer.h"
#include "iplugin_manager.h"
#include "ipolicy_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisabledNetworkInterfacePlugin::GetPlugin());

void DisabledNetworkInterfacePlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<DisabledNetworkInterfacePlugin, std::map<std::string, std::string>>> ptr)
{
    EDMLOGI("DisabledNetworkInterfacePlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::DISABLED_NETWORK_INTERFACE, PolicyName::POLICY_DISABLED_NETWORK_INTERFACE,
        true);
    std::map<std::string, std::map<IPlugin::PermissionType, std::string>> tagPermissionsForSet;
    std::map<IPlugin::PermissionType, std::string> typePermissionsForTag11ForSet;
    std::map<IPlugin::PermissionType, std::string> typePermissionsForTag12ForSet;
    typePermissionsForTag11ForSet.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_SET_NETWORK);
    typePermissionsForTag12ForSet.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_NETWORK);
    tagPermissionsForSet.emplace(EdmConstants::PERMISSION_TAG_VERSION_11, typePermissionsForTag11ForSet);
    tagPermissionsForSet.emplace(EdmConstants::PERMISSION_TAG_VERSION_12, typePermissionsForTag12ForSet);
    IPlugin::PolicyPermissionConfig setConfig = IPlugin::PolicyPermissionConfig(tagPermissionsForSet,
        IPlugin::ApiType::PUBLIC);
    ptr->InitPermission(FuncOperateType::SET, setConfig);

    std::map<std::string, std::map<IPlugin::PermissionType, std::string>> tagPermissionsForGet;
    std::map<IPlugin::PermissionType, std::string> typePermissionsForTag11ForGet;
    std::map<IPlugin::PermissionType, std::string> typePermissionsForTag12ForGet;
    typePermissionsForTag11ForGet.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_GET_NETWORK_INFO);
    typePermissionsForTag12ForGet.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_NETWORK);
    tagPermissionsForGet.emplace(EdmConstants::PERMISSION_TAG_VERSION_11, typePermissionsForTag11ForGet);
    tagPermissionsForGet.emplace(EdmConstants::PERMISSION_TAG_VERSION_12, typePermissionsForTag12ForGet);
    IPlugin::PolicyPermissionConfig getConfig = IPlugin::PolicyPermissionConfig(tagPermissionsForGet,
        IPlugin::ApiType::PUBLIC);
    ptr->InitPermission(FuncOperateType::GET, getConfig);
    ptr->SetSerializer(MapStringSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisabledNetworkInterfacePlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&DisabledNetworkInterfacePlugin::OnAdminRemove);
    ptr->SetOtherServiceStartListener(&DisabledNetworkInterfacePlugin::OnOtherServiceStart);
}

ErrCode DisabledNetworkInterfacePlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGD("DisabledNetworkInterfacePlugin OnGetPolicy.");
    std::string networkInterface = data.ReadString();
    auto ret = IsNetInterfaceExist(networkInterface);
    if (FAILED(ret)) {
        reply.WriteInt32(ret);
        return ret;
    }
    std::map<std::string, std::string> policyMap;
    if (!pluginInstance_->serializer_->Deserialize(policyData, policyMap)) {
        EDMLOGE("DisabledNetworkInterfacePlugin OnGetPolicy get policy failed.");
        reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    bool isDisallowed = false;
    if (policyMap.find(networkInterface) != policyMap.end()) {
        isDisallowed = true;
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteBool(isDisallowed);
    return ERR_OK;
}

ErrCode DisabledNetworkInterfacePlugin::OnSetPolicy(std::map<std::string, std::string> &data,
    std::map<std::string, std::string> &currentData, std::map<std::string, std::string> &mergeData, int32_t userId)
{
    EDMLOGD("DisabledNetworkInterfacePlugin OnSetPolicy.");
    if (data.empty()) {
        return EdmReturnErrCode::PARAM_ERROR;
    }
    // data contains one key value pair, the key is the network interface and the value is "true" of "false".
    auto it = data.begin();
    auto ret = IsNetInterfaceExist(it->first);
    if (FAILED(ret)) {
        return ret;
    }
    if (mergeData.find(it->first) == mergeData.end()) {
        if (!SetInterfaceDisabled(it->first, it->second == "true")) {
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    if (it->second == "true") {
        currentData[it->first] = "true";
    } else {
        currentData.erase(it->first);
    }
    for (auto policy : currentData) {
        if (mergeData.find(policy.first) == mergeData.end()) {
            mergeData[policy.first] = policy.second;
        }
    }
    return ERR_OK;
}

ErrCode DisabledNetworkInterfacePlugin::IsNetInterfaceExist(const std::string &netInterface)
{
    std::vector<std::string> ifaces = NetManagerStandard::NetsysController::GetInstance().InterfaceGetList();
    if (ifaces.empty() || std::find(ifaces.begin(), ifaces.end(), netInterface) == ifaces.end()) {
        EDMLOGE("DisabledNetworkInterfacePlugin OnGetPolicy network interface does not exist");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    return ERR_OK;
}

bool DisabledNetworkInterfacePlugin::SetInterfaceDisabled(const std::string &ifaceName, bool status)
{
    auto netPolicyClient = DelayedSingleton<NetManagerStandard::NetPolicyClient>::GetInstance();
    if (netPolicyClient == nullptr) {
        EDMLOGE("DisabledNetworkInterfacePlugin SetInterfaceDisabled get NetPolicyClient failed.");
        return false;
    }
    std::vector<std::string> ifaceNames{ifaceName};
    auto ret = netPolicyClient->SetNicTrafficAllowed(ifaceNames, !status);
    if (FAILED(ret)) {
        EDMLOGE("DisabledNetworkInterfacePlugin SetInterfaceDisabled SetNicTrafficAllowed failed, %{public}d.", ret);
        return false;
    }
    return true;
}

ErrCode DisabledNetworkInterfacePlugin::OnAdminRemove(const std::string &adminName,
    std::map<std::string, std::string> &data, std::map<std::string, std::string> &mergeData, int32_t userId)
{
    for (auto &iter : data) {
        if (mergeData.find(iter.first) == mergeData.end() && !SetInterfaceDisabled(iter.first, false)) {
            EDMLOGE("DisabledNetworkInterfacePlugin OnAdminRemove set %{public}s allowed failed.", iter.first.c_str());
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    return ERR_OK;
}

void DisabledNetworkInterfacePlugin::OnOtherServiceStart(int32_t systemAbilityId)
{
    std::string policyData;
    IPolicyManager::GetInstance()->GetPolicy("", PolicyName::POLICY_DISABLED_NETWORK_INTERFACE,
        policyData, EdmConstants::DEFAULT_USER_ID);
    std::map<std::string, std::string> policyMap;
    MapStringSerializer::GetInstance()->Deserialize(policyData, policyMap);
    std::vector<std::string> netList;
    for (const auto& iter : policyMap) {
        netList.emplace_back(iter.first);
        EDMLOGD("HandleDisallowedNetworkInterface %{public}s", iter.first.c_str());
    }
    auto netPolicyClient = DelayedSingleton<NetManagerStandard::NetPolicyClient>::GetInstance();
    if (netPolicyClient != nullptr) {
        if (FAILED(netPolicyClient->SetNicTrafficAllowed(netList, false))) {
            EDMLOGE("EnterpriseDeviceMgrAbility::HandleDisallowedNetworkInterface SetNicTrafficAllowed failed.");
        }
    } else {
        EDMLOGE("EnterpriseDeviceMgrAbility::HandleDisallowedNetworkInterface get NetPolicyClient failed.");
    }
}
} // namespace EDM
} // namespace OHOS
