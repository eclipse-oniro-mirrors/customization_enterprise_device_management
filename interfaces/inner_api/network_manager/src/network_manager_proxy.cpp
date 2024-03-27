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

#include "network_manager_proxy.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "func_code.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<NetworkManagerProxy> NetworkManagerProxy::instance_ = nullptr;
std::mutex NetworkManagerProxy::mutexLock_;
const std::u16string DESCRIPTOR = u"ohos.edm.IEnterpriseDeviceMgr";
#ifdef NETMANAGER_BASE_EDM_ENABLE
constexpr int32_t MAX_SIZE = 16;
#endif

NetworkManagerProxy::NetworkManagerProxy() {}

NetworkManagerProxy::~NetworkManagerProxy() {}

std::shared_ptr<NetworkManagerProxy> NetworkManagerProxy::GetNetworkManagerProxy()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutexLock_);
        if (instance_ == nullptr) {
            std::shared_ptr<NetworkManagerProxy> temp = std::make_shared<NetworkManagerProxy>();
            instance_ = temp;
        }
    }
    return instance_;
}

int32_t NetworkManagerProxy::GetAllNetworkInterfaces(const AppExecFwk::ElementName &admin,
    std::vector<std::string> &networkInterface, bool isSync)
{
#ifdef NETMANAGER_BASE_EDM_ENABLE
    EDMLOGD("NetworkManagerProxy::GetAllNetworkInterfaces");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteString(isSync ? EdmConstants::PERMISSION_TAG_VERSION_12 : EdmConstants::PERMISSION_TAG_VERSION_11);
    data.WriteInt32(HAS_ADMIN);
    data.WriteParcelable(&admin);
    proxy->GetPolicy(EdmInterfaceCode::GET_NETWORK_INTERFACES, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGW("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    int32_t size = reply.ReadInt32();
    if (size > MAX_SIZE) {
        EDMLOGE("networkInterface size=[%{public}d] is too large", size);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    reply.ReadStringVector(&networkInterface);
    return ERR_OK;
#else
    EDMLOGW("NetworkManagerProxy::GetAllNetworkInterfaces Unsupported Capabilities.");
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
}

int32_t NetworkManagerProxy::GetIpOrMacAddress(const AppExecFwk::ElementName &admin,
    const std::string &networkInterface, int policyCode, std::string &info, bool isSync)
{
#ifdef NETMANAGER_BASE_EDM_ENABLE
    EDMLOGD("NetworkManagerProxy::GetIpOrMacAddress");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteString(isSync ? EdmConstants::PERMISSION_TAG_VERSION_12 : EdmConstants::PERMISSION_TAG_VERSION_11);
    data.WriteInt32(HAS_ADMIN);
    data.WriteParcelable(&admin);
    data.WriteString(networkInterface);
    proxy->GetPolicy(policyCode, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGW("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    reply.ReadString(info);
    return ERR_OK;
#else
    EDMLOGW("NetworkManagerProxy::GetIpOrMacAddress Unsupported Capabilities.");
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
}

int32_t NetworkManagerProxy::SetNetworkInterfaceDisabled(const AppExecFwk::ElementName &admin,
    const std::string &networkInterface, bool isDisabled, bool isSync)
{
#ifdef NETMANAGER_BASE_EDM_ENABLE
    EDMLOGD("NetworkManagerProxy::SetNetworkInterfaceDisabled");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DISABLED_NETWORK_INTERFACE);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(isSync ? EdmConstants::PERMISSION_TAG_VERSION_12 : EdmConstants::PERMISSION_TAG_VERSION_11);
    std::vector<std::string> key{networkInterface};
    std::vector<std::string> value{isDisabled ? "true" : "false"};
    data.WriteStringVector(key);
    data.WriteStringVector(value);
    return proxy->HandleDevicePolicy(funcCode, data);
#else
    EDMLOGW("NetworkManagerProxy::SetNetworkInterfaceDisabled Unsupported Capabilities.");
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
}

int32_t NetworkManagerProxy::IsNetworkInterfaceDisabled(const AppExecFwk::ElementName &admin,
    const std::string &networkInterface, bool &status, bool isSync)
{
#ifdef NETMANAGER_BASE_EDM_ENABLE
    EDMLOGD("NetworkManagerProxy::IsNetworkInterfaceDisabled");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteString(isSync ? EdmConstants::PERMISSION_TAG_VERSION_12 : EdmConstants::PERMISSION_TAG_VERSION_11);
    data.WriteInt32(HAS_ADMIN);
    data.WriteParcelable(&admin);
    data.WriteString(networkInterface);
    proxy->GetPolicy(EdmInterfaceCode::DISABLED_NETWORK_INTERFACE, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGW("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    reply.ReadBool(status);
    return ERR_OK;
#else
    EDMLOGW("NetworkManagerProxy::IsNetworkInterfaceDisabled Unsupported Capabilities.");
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
}

int32_t NetworkManagerProxy::AddIptablesFilterRule(const AppExecFwk::ElementName &admin,
    const IPTABLES::AddFilter &filter)
{
    EDMLOGD("NetworkManagerProxy::AddIptablesFilterRule");
    MessageParcel data;
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::IPTABLES_RULE);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    IPTABLES::IptablesUtils::WriteAddFilterConfig(filter, data);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t NetworkManagerProxy::RemoveIptablesFilterRule(const AppExecFwk::ElementName &admin,
    const IPTABLES::RemoveFilter &filter)
{
    EDMLOGD("NetworkManagerProxy::RemoveIptablesFilterRule");
    MessageParcel data;
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::IPTABLES_RULE);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    IPTABLES::IptablesUtils::WriteRemoveFilterConfig(filter, data);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t NetworkManagerProxy::ListIptablesFilterRules(const AppExecFwk::ElementName &admin, std::string &result)
{
    EDMLOGD("NetworkManagerProxy::ListIptablesFilterRules");
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(HAS_ADMIN);
    data.WriteParcelable(&admin);
    EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(EdmInterfaceCode::IPTABLES_RULE, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGE("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    reply.ReadString(result);
    return ERR_OK;
}

int32_t NetworkManagerProxy::AddFirewallRule(const AppExecFwk::ElementName &admin,
    const IPTABLES::FirewallRule &rule)
{
    MessageParcel data;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    IPTABLES::FirewallRuleParcel firewallRuleParcel{rule};
    if (!firewallRuleParcel.Marshalling(data)) {
        EDMLOGE("NetworkManagerProxy::AddFirewallRule Marshalling rule fail.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::FIREWALL_RULE);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t NetworkManagerProxy::RemoveFirewallRule(const AppExecFwk::ElementName &admin,
    const IPTABLES::FirewallRule &rule)
{
    MessageParcel data;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    IPTABLES::FirewallRuleParcel firewallRuleParcel{rule};
    if (!firewallRuleParcel.Marshalling(data)) {
        EDMLOGE("NetworkManagerProxy::RemoveFirewallRule Marshalling rule fail.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::FIREWALL_RULE);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t NetworkManagerProxy::GetFirewallRules(const AppExecFwk::ElementName &admin,
    std::vector<IPTABLES::FirewallRule> &result)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(HAS_ADMIN);
    data.WriteParcelable(&admin);
    EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(EdmInterfaceCode::FIREWALL_RULE, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGE("EnterpriseDeviceMgrProxy:GetFirewallRules fail. %{public}d", ret);
        return ret;
    }
    int32_t size = reply.ReadInt32();
    for (int32_t i = 0; i < size; i++) {
        IPTABLES::FirewallRuleParcel firewallRuleParcel;
        if (!IPTABLES::FirewallRuleParcel::Unmarshalling(reply, firewallRuleParcel)) {
            EDMLOGE("NetworkManagerProxy::GetFirewallRules Unmarshalling rule fail.");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        result.push_back(firewallRuleParcel.GetRule());
    }
    EDMLOGD("EnterpriseDeviceMgrProxy:GetFirewallRules success. %{public}d", size);
    return ERR_OK;
}

int32_t NetworkManagerProxy::AddDomainFilterRule(const AppExecFwk::ElementName &admin,
    const IPTABLES::DomainFilterRule &rule)
{
    MessageParcel data;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    IPTABLES::DomainFilterRuleParcel domainFilterRuleParcel{rule};
    if (!domainFilterRuleParcel.Marshalling(data)) {
        EDMLOGE("NetworkManagerProxy::AddDomainFilterRule Marshalling rule fail.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DOMAIN_FILTER_RULE);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t NetworkManagerProxy::RemoveDomainFilterRule(const AppExecFwk::ElementName &admin,
    const IPTABLES::DomainFilterRule &rule)
{
    MessageParcel data;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    IPTABLES::DomainFilterRuleParcel domainFilterRuleParcel{rule};
    if (!domainFilterRuleParcel.Marshalling(data)) {
        EDMLOGE("NetworkManagerProxy::RemoveDomainFilterRule Marshalling rule fail.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE,
        EdmInterfaceCode::DOMAIN_FILTER_RULE);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t NetworkManagerProxy::GetDomainFilterRules(const AppExecFwk::ElementName &admin,
    std::vector<IPTABLES::DomainFilterRule> &result)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(HAS_ADMIN);
    data.WriteParcelable(&admin);
    EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(EdmInterfaceCode::DOMAIN_FILTER_RULE, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGE("EnterpriseDeviceMgrProxy:GetFirewallRules fail. %{public}d", ret);
        return ret;
    }
    int32_t size = reply.ReadInt32();
    for (int32_t i = 0; i < size; i++) {
        IPTABLES::DomainFilterRuleParcel domainFilterRuleParcel;
        if (!IPTABLES::DomainFilterRuleParcel::Unmarshalling(reply, domainFilterRuleParcel)) {
            EDMLOGE("NetworkManagerProxy::GetDomainFilterRules Unmarshalling rule fail.");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        result.push_back(domainFilterRuleParcel.GetRule());
    }
    EDMLOGD("EnterpriseDeviceMgrProxy:GetDomainFilterRules success. %{public}d", size);
    return ERR_OK;
}

#ifdef NETMANAGER_BASE_EDM_ENABLE
int32_t NetworkManagerProxy::SetGlobalHttpProxy(const AppExecFwk::ElementName &admin,
    const NetManagerStandard::HttpProxy &httpProxy)
{
    EDMLOGD("NetworkManagerProxy::SetGlobalHttpProxy");
    MessageParcel data;
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::GLOBAL_PROXY);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    if (!httpProxy.Marshalling(data)) {
        EDMLOGE("NetworkManagerProxy::SetGlobalHttpProxy Marshalling proxy fail.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int32_t ret = EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
    EDMLOGI("NetworkManagerProxy::SetGlobalHttpProxy ret = %{public}d", ret);
    return ret;
}

int32_t NetworkManagerProxy::GetGlobalHttpProxy(const AppExecFwk::ElementName *admin,
    NetManagerStandard::HttpProxy &httpProxy)
{
    EDMLOGD("NetworkManagerProxy::GetGlobalHttpProxy");
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    if (admin != nullptr) {
        data.WriteInt32(HAS_ADMIN);
        data.WriteParcelable(admin);
    } else {
        if (!EnterpriseDeviceMgrProxy::GetInstance()->IsEdmEnabled()) {
            return ERR_OK;
        }
        data.WriteInt32(WITHOUT_ADMIN);
    }
    EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(EdmInterfaceCode::GLOBAL_PROXY, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGE("GetGlobalHttpProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    if (!NetManagerStandard::HttpProxy::Unmarshalling(reply, httpProxy)) {
        EDMLOGE("NetworkManagerProxy::GetGlobalHttpProxy Unmarshalling proxy fail.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}
#endif
} // namespace EDM
} // namespace OHOS
