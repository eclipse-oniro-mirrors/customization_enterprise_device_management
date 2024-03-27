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

#include "get_ip_address_plugin.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "ethernet_client.h"
#include "interface_type.h"
#include "string_serializer.h"
#include "plugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(GetIpAddressPlugin::GetPlugin());

void GetIpAddressPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<GetIpAddressPlugin, std::string>> ptr)
{
    EDMLOGI("GetIpAddressPlugin InitPlugin...");
    std::map<std::string, std::string> perms;
    perms.insert(std::make_pair(EdmConstants::PERMISSION_TAG_VERSION_11,
        "ohos.permission.ENTERPRISE_GET_NETWORK_INFO"));
    perms.insert(std::make_pair(EdmConstants::PERMISSION_TAG_VERSION_12, "ohos.permission.ENTERPRISE_MANAGE_NETWORK"));
    IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig(perms,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
    ptr->InitAttribute(EdmInterfaceCode::GET_IP_ADDRESS, "get_ip_address", config, false);
    ptr->SetSerializer(StringSerializer::GetInstance());
}

ErrCode GetIpAddressPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("GetIpAddressPlugin OnGetPolicy.");
    nmd::InterfaceConfigurationParcel config;
    std::string networkInterface;
    data.ReadString(networkInterface);
    DelayedSingleton<NetManagerStandard::EthernetClient>::GetInstance()->GetInterfaceConfig(networkInterface, config);
    reply.WriteInt32(ERR_OK);
    reply.WriteString(config.ipv4Addr);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
