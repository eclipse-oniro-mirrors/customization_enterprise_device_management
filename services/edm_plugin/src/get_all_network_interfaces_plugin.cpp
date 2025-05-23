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
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "ethernet_client.h"
#include "interface_type.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(GetAllNetworkInterfacesPlugin::GetPlugin());

void GetAllNetworkInterfacesPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<GetAllNetworkInterfacesPlugin, std::vector<std::string>>> ptr)
{
    EDMLOGI("GetAllNetworkInterfacesPlugin InitPlugin...");
    std::map<std::string, std::map<IPlugin::PermissionType, std::string>> tagPermissions;
    std::map<IPlugin::PermissionType, std::string> typePermissionsForTag11;
    std::map<IPlugin::PermissionType, std::string> typePermissionsForTag12;
    typePermissionsForTag11.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_GET_NETWORK_INFO);
    typePermissionsForTag12.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_NETWORK);
    tagPermissions.emplace(EdmConstants::PERMISSION_TAG_VERSION_11, typePermissionsForTag11);
    tagPermissions.emplace(EdmConstants::PERMISSION_TAG_VERSION_12, typePermissionsForTag12);

    IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig(tagPermissions, IPlugin::ApiType::PUBLIC);
    ptr->InitAttribute(EdmInterfaceCode::GET_NETWORK_INTERFACES, PolicyName::POLICY_GET_NETWORK_INTERFACES,
        config, false);
    ptr->SetSerializer(ArrayStringSerializer::GetInstance());
}

ErrCode GetAllNetworkInterfacesPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("GetAllNetworkInterfacesPlugin OnGetPolicy.");
    std::vector<std::string> interfaces;
    DelayedSingleton<NetManagerStandard::EthernetClient>::GetInstance()->GetAllActiveIfaces(interfaces);
    reply.WriteInt32(ERR_OK);
    reply.WriteStringVector(interfaces);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
