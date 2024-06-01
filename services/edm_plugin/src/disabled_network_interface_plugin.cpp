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

#include "netsys_native_service_proxy.h"
#include "system_ability_definition.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_sys_manager.h"
#include "map_string_serializer.h"
#include "plugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(DisabledNetworkInterfacePlugin::GetPlugin());

void DisabledNetworkInterfacePlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<DisabledNetworkInterfacePlugin, std::map<std::string, std::string>>> ptr)
{
    EDMLOGI("DisabledNetworkInterfacePlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::DISABLED_NETWORK_INTERFACE, "disabled_network_interface", true);
    std::map<std::string, std::string> setPerms;
    setPerms.insert(std::make_pair(EdmConstants::PERMISSION_TAG_VERSION_11, "ohos.permission.ENTERPRISE_SET_NETWORK"));
    setPerms.insert(std::make_pair(EdmConstants::PERMISSION_TAG_VERSION_12,
        "ohos.permission.ENTERPRISE_MANAGE_NETWORK"));
    IPlugin::PolicyPermissionConfig setConfig = IPlugin::PolicyPermissionConfig(setPerms,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
    ptr->InitPermission(FuncOperateType::SET, setConfig);
    std::map<std::string, std::string> getPerms;
    getPerms.insert(std::make_pair(EdmConstants::PERMISSION_TAG_VERSION_11,
        "ohos.permission.ENTERPRISE_GET_NETWORK_INFO"));
    getPerms.insert(std::make_pair(EdmConstants::PERMISSION_TAG_VERSION_12,
        "ohos.permission.ENTERPRISE_MANAGE_NETWORK"));
    IPlugin::PolicyPermissionConfig getConfig = IPlugin::PolicyPermissionConfig(getPerms,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
    ptr->InitPermission(FuncOperateType::GET, getConfig);
    ptr->SetSerializer(MapStringSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisabledNetworkInterfacePlugin::OnSetPolicy, FuncOperateType::SET);
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
    std::map<std::string, std::string> &currentData, int32_t userId)
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
    if (it->second == "true") {
        currentData[it->first] = "true";
    } else {
        currentData.erase(it->first);
    }
    return ERR_OK;
}

ErrCode DisabledNetworkInterfacePlugin::IsNetInterfaceExist(const std::string &netInterface)
{
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(COMM_NETSYS_NATIVE_SYS_ABILITY_ID);
    if (remoteObject == nullptr) {
        EDMLOGE("DisabledNetworkInterfacePlugin GetNetNativeProxy get remote object failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    auto netNativeProxy = iface_cast<NetsysNative::INetsysService>(remoteObject);
    if (netNativeProxy == nullptr) {
        EDMLOGE("DisabledNetworkInterfacePlugin OnGetPolicy get netNativeProxy failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::vector<std::string> ifaces;
    auto ret = netNativeProxy->InterfaceGetList(ifaces);
    if (FAILED(ret)) {
        EDMLOGE("DisabledNetworkInterfacePlugin OnGetPolicy get interface list failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (ifaces.empty() || std::find(ifaces.begin(), ifaces.end(), netInterface) == ifaces.end()) {
        EDMLOGE("DisabledNetworkInterfacePlugin OnGetPolicy network interface does not exist");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
