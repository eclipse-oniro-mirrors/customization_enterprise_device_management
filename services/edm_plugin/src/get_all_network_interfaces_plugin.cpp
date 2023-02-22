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

#include "get_all_network_interfaces_plugin.h"

#include "array_string_serializer.h"
#include "ethernet_client.h"
#include "interface_type.h"
#include "iplugin_manager.h"
#include "policy_info.h"


namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(GetAllNetworkInterfacesPlugin::GetPlugin());

void GetAllNetworkInterfacesPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<GetAllNetworkInterfacesPlugin,
    std::vector<std::string>>> ptr)
{
    EDMLOGI("GetAllNetworkInterfacesPlugin InitPlugin...");
    std::string policyName;
    POLICY_CODE_TO_NAME(GET_NETWORK_INTERFACES, policyName);
    ptr->InitAttribute(GET_NETWORK_INTERFACES, policyName, "ohos.permission.ENTERPRISE_GET_NETWORK_INFO", false);
    ptr->SetSerializer(ArrayStringSerializer::GetInstance());
}

ErrCode GetAllNetworkInterfacesPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply)
{
    EDMLOGI("GetAllNetworkInterfacesPlugin OnGetPolicy.");
    std::vector<std::string> interfaces;
    DelayedSingleton<NetManagerStandard::EthernetClient>::GetInstance()->GetAllActiveIfaces(interfaces);
    reply.WriteInt32(ERR_OK);
    reply.WriteInt32(interfaces.size());
    reply.WriteStringVector(interfaces);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
