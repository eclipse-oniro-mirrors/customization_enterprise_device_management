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
#include "ethernet_client.h"
#include "iplugin_manager.h"
#include "map_string_serializer.h"
#include "policy_info.h"

namespace OHOS {
namespace EDM {
const std::string IF_CFG_DOWN = "down";
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisabledNetworkInterfacePlugin::GetPlugin());

void DisabledNetworkInterfacePlugin::InitPlugin(std::shared_ptr<IPluginTemplate<DisabledNetworkInterfacePlugin,
    std::map<std::string, std::string>>> ptr)
{
    EDMLOGD("DisabledNetworkInterfacePlugin InitPlugin...");
    std::string policyName;
    POLICY_CODE_TO_NAME(DISABLED_NETWORK_INTERFACE, policyName);
    ptr->InitAttribute(DISABLED_NETWORK_INTERFACE, policyName, false);
    ptr->InitPermission(FuncOperateType::SET, "ohos.permission.ENTERPRISE_SET_NETWORK",
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN);
    ptr->InitPermission(FuncOperateType::GET, "ohos.permission.ENTERPRISE_GET_NETWORK_INFO",
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN);
    ptr->SetSerializer(MapStringSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisabledNetworkInterfacePlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode DisabledNetworkInterfacePlugin::OnGetPolicy(std::string &policyData, MessageParcel &data,
    MessageParcel &reply, int32_t userId)
{
    EDMLOGD("DisabledNetworkInterfacePlugin OnGetPolicy.");
    nmd::InterfaceConfigurationParcel config;
    std::string networkInterface;
    data.ReadString(networkInterface);
    DelayedSingleton<NetManagerStandard::EthernetClient>::GetInstance()->GetInterfaceConfig(networkInterface, config);
    if (config.flags.empty()) {
        EDMLOGD("network interface does not exist");
        reply.WriteInt32(EdmReturnErrCode::PARAM_ERROR);
        return EdmReturnErrCode::PARAM_ERROR;
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteBool(std::find(config.flags.begin(), config.flags.end(), IF_CFG_DOWN) != config.flags.end());
    return ERR_OK;
}

ErrCode DisabledNetworkInterfacePlugin::OnSetPolicy(std::map<std::string, std::string> &policyData)
{
    EDMLOGD("DisabledNetworkInterfacePlugin OnSetPolicy.");
    if (policyData.empty()) {
        return EdmReturnErrCode::PARAM_ERROR;
    }
    // policyData contains one key value pair, the key is the network interface and the value is "true" of "false".
    auto it = policyData.begin();
    nmd::InterfaceConfigurationParcel config;
    DelayedSingleton<NetManagerStandard::EthernetClient>::GetInstance()->GetInterfaceConfig(it->first, config);
    if (config.flags.empty()) {
        EDMLOGD("network interface does not exist");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    int32_t ret = it->second == "true" ?
        DelayedSingleton<NetManagerStandard::EthernetClient>::GetInstance()->SetInterfaceDown(it->first) :
        DelayedSingleton<NetManagerStandard::EthernetClient>::GetInstance()->SetInterfaceUp(it->first);
    if (FAILED(ret)) {
        EDMLOGD("DisabledNetworkInterfacePlugin:OnSetPolicy send request fail. %{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS