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

#include "set_network_interface_config_plugin.h"
 
#include <memory>
#include <regex>
#include "edm_constants.h"
#include "iplugin_manager.h"
#include "func_code_utils.h"
#include "edm_ipc_interface_code.h"
#include "ethernet_client.h"

using namespace OHOS::NetManagerStandard;

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(
    std::make_shared<SetNetworkInterfaceConfigPlugin>());

const char* const IP_PATTERN =
    "((2([0-4]\\d|5[0-5])|1\\d\\d|[1-9]\\d|\\d)\\.){3}(2([0-4]\\d|5[0-5])|1\\d\\d|[1-9]\\d|\\d)";
const char* const DEFAULT_IPV4_ADDR = "0.0.0.0";

SetNetworkInterfaceConfigPlugin::SetNetworkInterfaceConfigPlugin()
{
    policyCode_ = EdmInterfaceCode::SET_NETWORK_INTERFACE_CONFIG;
    policyName_ = PolicyName::POLICY_SET_NETWORK_INTERFACE_CONFIG;
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_NETWORK);
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = false;
}

bool SetNetworkInterfaceConfigPlugin::IpAddressIsLegal(std::string ipAddress, bool hasSeparate)
{
    if (hasSeparate) {
        std::vector<std::string> tokens;
        size_t start = 0;
        size_t end = ipAddress.find(',');
        
        while (end != std::string::npos) {
            std::string ip = ipAddress.substr(start, end - start);
            if (!std::regex_match(ip, std::regex(IP_PATTERN))) {
                return false;
            }
            start = end + 1;
            end = ip.find(',', start);
        }
        std::string ip = ipAddress.substr(start);
        if (!std::regex_match(ip, std::regex(IP_PATTERN))) {
            return false;
        }
    } else if (!std::regex_match(ipAddress, std::regex(IP_PATTERN))) {
        return false;
    }

    return true;
}

ErrCode SetNetworkInterfaceConfigPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data,
    MessageParcel &reply, HandlePolicyData &policyData, int32_t userId)
{
    EDMLOGI("SetNetworkInterfaceConfigPlugin::OnHandlePolicy start");
    uint32_t typeCode = FUNC_TO_OPERATE(funcCode);
    FuncOperateType type = FuncCodeUtils::ConvertOperateType(typeCode);
    if (type == FuncOperateType::SET) {
        std::string iface = data.ReadString();
        int32_t setMode = data.ReadInt32();
        std::string ipAddress = data.ReadString();
        std::string gateway = data.ReadString();
        std::string netMask = data.ReadString();
        std::string dnsServers = data.ReadString();
        
        if (setMode != static_cast<int32_t>(IPSetMode::STATIC) && setMode != static_cast<int32_t>(IPSetMode::DHCP)) {
            return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
        }
        if (setMode == static_cast<int32_t>(IPSetMode::STATIC)) {
            bool isLegal = IpAddressIsLegal(ipAddress, false) && IpAddressIsLegal(gateway, false)
                && IpAddressIsLegal(netMask, false) && IpAddressIsLegal(dnsServers, true);
            if (!isLegal) {
                return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
            }
        }
        sptr<InterfaceConfiguration> cfg = new (std::nothrow) InterfaceConfiguration();
        if (cfg == nullptr) {
            EDMLOGE("new InterfaceConfiguration is null");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        cfg->mode_ = IPSetMode(setMode);
        StaticConfiguration::ExtractNetAddrBySeparator(ipAddress, cfg->ipStatic_.ipAddrList_);
        StaticConfiguration::ExtractNetAddrBySeparator(gateway, cfg->ipStatic_.gatewayList_);
        StaticConfiguration::ExtractNetAddrBySeparator(gateway, cfg->ipStatic_.gatewayList_);
        StaticConfiguration::ExtractNetAddrBySeparator(netMask, cfg->ipStatic_.netMaskList_);
        StaticConfiguration::ExtractNetAddrBySeparator(dnsServers, cfg->ipStatic_.dnsServers_);
        StaticConfiguration::ExtractNetAddrBySeparator(DEFAULT_IPV4_ADDR, cfg->ipStatic_.routeList_);

        int32_t result = DelayedSingleton<EthernetClient>::GetInstance()->SetIfaceConfig(iface, cfg);
        if (result != NETMANAGER_EXT_SUCCESS) {
            EDMLOGE("SetIfaceConfig error! result:%{public}d", result);
            return EdmReturnErrCode::ETHERNET_CONFIGURATION_FAILED;
        }
    } else {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS