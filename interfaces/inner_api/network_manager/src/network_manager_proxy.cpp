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
std::once_flag NetworkManagerProxy::flag_;
const std::u16string DESCRIPTOR = u"ohos.edm.IEnterpriseDeviceMgr";
constexpr int32_t POLICIES_MAX_SIZE = 200;

NetworkManagerProxy::NetworkManagerProxy() {}

NetworkManagerProxy::~NetworkManagerProxy() {}

std::shared_ptr<NetworkManagerProxy> NetworkManagerProxy::GetNetworkManagerProxy()
{
    std::call_once(flag_, []() {
        if (instance_ == nullptr) {
            instance_ = std::make_shared<NetworkManagerProxy>();
        }
    });
    return instance_;
}

int32_t NetworkManagerProxy::GetAllNetworkInterfaces(const AppExecFwk::ElementName &admin,
    std::vector<std::string> &networkInterface, bool isSync)
{
#ifdef NETMANAGER_BASE_EDM_ENABLE
    EDMLOGD("NetworkManagerProxy::GetAllNetworkInterfaces");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
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
    reply.ReadStringVector(&networkInterface);
    return ERR_OK;
#else
    EDMLOGW("NetworkManagerProxy::GetAllNetworkInterfaces Unsupported Capabilities.");
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
}

int32_t NetworkManagerProxy::GetAllNetworkInterfaces(MessageParcel &data,
    std::vector<std::string> &networkInterface)
{
#ifdef NETMANAGER_BASE_EDM_ENABLE
    EDMLOGD("NetworkManagerProxy::GetAllNetworkInterfaces");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    MessageParcel reply;
    proxy->GetPolicy(EdmInterfaceCode::GET_NETWORK_INTERFACES, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGW("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
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

int32_t NetworkManagerProxy::GetIpOrMacAddress(MessageParcel &data, int policyCode, std::string &info)
{
#ifdef NETMANAGER_BASE_EDM_ENABLE
    EDMLOGD("NetworkManagerProxy::GetIpOrMacAddress");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    MessageParcel reply;
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

int32_t NetworkManagerProxy::SetNetworkInterfaceDisabled(MessageParcel &data)
{
#ifdef NETMANAGER_BASE_EDM_ENABLE
    EDMLOGD("NetworkManagerProxy::SetNetworkInterfaceDisabled");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DISABLED_NETWORK_INTERFACE);
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

int32_t NetworkManagerProxy::IsNetworkInterfaceDisabled(MessageParcel &data, bool &status)
{
#ifdef NETMANAGER_BASE_EDM_ENABLE
    EDMLOGD("NetworkManagerProxy::IsNetworkInterfaceDisabled");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    MessageParcel reply;
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

int32_t NetworkManagerProxy::AddIptablesFilterRule(MessageParcel &data)
{
    EDMLOGD("NetworkManagerProxy::AddIptablesFilterRule");
    std::uint32_t funcCode = POLICY_FUNC_CODE(static_cast<std::uint32_t>(FuncOperateType::SET),
        EdmInterfaceCode::IPTABLES_RULE);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t NetworkManagerProxy::RemoveIptablesFilterRule(MessageParcel &data)
{
    EDMLOGD("NetworkManagerProxy::RemoveIptablesFilterRule");
    std::uint32_t funcCode = POLICY_FUNC_CODE(static_cast<std::uint32_t>(FuncOperateType::REMOVE),
        EdmInterfaceCode::IPTABLES_RULE);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t NetworkManagerProxy::ListIptablesFilterRules(MessageParcel &data, std::string &result)
{
    EDMLOGD("NetworkManagerProxy::ListIptablesFilterRules");
    MessageParcel reply;
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

int32_t NetworkManagerProxy::AddFirewallRule(MessageParcel &data)
{
    std::uint32_t funcCode = POLICY_FUNC_CODE(static_cast<std::uint32_t>(FuncOperateType::SET),
        EdmInterfaceCode::FIREWALL_RULE);
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
    std::uint32_t funcCode = POLICY_FUNC_CODE(static_cast<std::uint32_t>(FuncOperateType::REMOVE),
        EdmInterfaceCode::FIREWALL_RULE);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t NetworkManagerProxy::GetFirewallRules(MessageParcel &data,
    std::vector<IPTABLES::FirewallRule> &result)
{
    MessageParcel reply;
    EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(EdmInterfaceCode::FIREWALL_RULE, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGE("EnterpriseDeviceMgrProxy:GetFirewallRules fail. %{public}d", ret);
        return ret;
    }
    int32_t size = reply.ReadInt32();
    if (size > EdmConstants::DEFAULT_LOOP_MAX_SIZE) {
        EDMLOGE("EnterpriseDeviceMgrProxy:GetFirewallRules size overlimit. size: %{public}d", size);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
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

int32_t NetworkManagerProxy::AddDomainFilterRule(MessageParcel &data)
{
    std::uint32_t funcCode = POLICY_FUNC_CODE(static_cast<std::uint32_t>(FuncOperateType::SET),
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
    std::uint32_t funcCode = POLICY_FUNC_CODE(static_cast<std::uint32_t>(FuncOperateType::REMOVE),
        EdmInterfaceCode::DOMAIN_FILTER_RULE);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t NetworkManagerProxy::GetDomainFilterRules(MessageParcel &data,
    std::vector<IPTABLES::DomainFilterRule> &result)
{
    MessageParcel reply;
    EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(EdmInterfaceCode::DOMAIN_FILTER_RULE, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGE("EnterpriseDeviceMgrProxy:GetDomainFilterRules fail. %{public}d", ret);
        return ret;
    }
    int32_t size = reply.ReadInt32();
    if (size > EdmConstants::DEFAULT_LOOP_MAX_SIZE) {
        EDMLOGE("EnterpriseDeviceMgrProxy:GetDomainFilterRules size overlimit. size: %{public}d", size);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
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

int32_t NetworkManagerProxy::TurnOnMobileData(MessageParcel &data)
{
    EDMLOGD("NetworkManagerProxy::TurnOnMobileData");
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::TURNONOFF_MOBILE_DATA);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t NetworkManagerProxy::TurnOffMobileData(MessageParcel &data)
{
    EDMLOGD("NetworkManagerProxy::TurnOffMobileData");
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE,
        EdmInterfaceCode::TURNONOFF_MOBILE_DATA);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t NetworkManagerProxy::ForceTurnOnMobileData(const AppExecFwk::ElementName &admin)
{
    EDMLOGD("NetworkManagerProxy::ForceTurnOnMobileData");
    MessageParcel data;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteString(EdmConstants::MobileData::FORCE_FLAG);
    data.WriteInt32(EdmConstants::MobileData::FORCE_OPEN);
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DISALLOWED_MOBILE_DATA);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t NetworkManagerProxy::AddApn(const AppExecFwk::ElementName &admin,
    const std::map<std::string, std::string> &apnInfoMap, ApnPassword &apnPassword)
{
    MessageParcel data;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteString(EdmConstants::SetApn::ADD_FLAG);
    if (apnInfoMap.size() > EdmConstants::SetApn::MAX_MAP_SIZE) {
        return ERR_INVALID_VALUE;
    }
    data.WriteInt32(apnInfoMap.size());
    for (const auto& iter : apnInfoMap) {
        data.WriteString(iter.first);
    }
    for (const auto& iter : apnInfoMap) {
        data.WriteString(iter.second);
    }
    if (apnPassword.password == nullptr) {
        data.WriteInt32(-1);
    } else {
        data.WriteInt32(static_cast<int32_t>(apnPassword.passwordSize));
        data.WriteCString(apnPassword.password);
    }
    std::uint32_t funcCode = POLICY_FUNC_CODE(static_cast<std::uint32_t>(FuncOperateType::SET),
        EdmInterfaceCode::SET_APN_INFO);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t NetworkManagerProxy::DeleteApn(MessageParcel &data)
{
    EDMLOGD("NetworkManagerProxy::DeleteApn");
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::SET_APN_INFO);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t NetworkManagerProxy::UpdateApn(const AppExecFwk::ElementName &admin,
    const std::map<std::string, std::string> &apnInfoMap, const std::string &apnId, ApnPassword &apnPassword)
{
    MessageParcel data;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteString(EdmConstants::SetApn::UPDATE_FLAG);
    data.WriteString(apnId);
    data.WriteInt32(apnInfoMap.size());
    for (const auto& iter : apnInfoMap) {
        data.WriteString(iter.first);
    }
    for (const auto& iter : apnInfoMap) {
        data.WriteString(iter.second);
    }
    if (apnPassword.password == nullptr) {
        data.WriteInt32(-1);
    } else {
        data.WriteInt32(static_cast<int32_t>(apnPassword.passwordSize));
        data.WriteCString(apnPassword.password);
    }
    std::uint32_t funcCode = POLICY_FUNC_CODE(static_cast<std::uint32_t>(FuncOperateType::SET),
        EdmInterfaceCode::SET_APN_INFO);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t NetworkManagerProxy::SetPreferApn(const AppExecFwk::ElementName &admin, const std::string &apnId)
{
    MessageParcel data;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteString(EdmConstants::SetApn::SET_PREFER_FLAG);
    data.WriteString(apnId);
    
    std::uint32_t funcCode = POLICY_FUNC_CODE(static_cast<std::uint32_t>(FuncOperateType::SET),
        EdmInterfaceCode::SET_APN_INFO);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t NetworkManagerProxy::QueryApn(const AppExecFwk::ElementName &admin, const std::string &apnId,
    std::map<std::string, std::string> &apnInfoMap)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(HAS_ADMIN);
    data.WriteParcelable(&admin);
    data.WriteString(EdmConstants::SetApn::QUERY_INFO_FLAG);
    data.WriteString(apnId);
    EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(EdmInterfaceCode::SET_APN_INFO, data, reply);
    int32_t ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        EDMLOGE("EnterpriseDeviceMgrProxy:QueryApn error: %{public}d", ret);
        return ret;
    }

    int32_t size = reply.ReadInt32();
    if (size > POLICIES_MAX_SIZE) {
        EDMLOGE("EnterpriseDeviceMgrProxy:QueryApn invalid size: %{public}d", size);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::vector<std::string> keys;
    std::vector<std::string> values;
    for (int32_t i = 0; i < size; i++) {
        std::string key = reply.ReadString();
        keys.push_back(key);
    }
    for (int32_t i = 0; i < size; i++) {
        std::string value = reply.ReadString();
        values.push_back(value);
    }
    for (int32_t i = 0; i < size; i++) {
        apnInfoMap[keys[i]] = values[i];
    }

    EDMLOGD("EnterpriseDeviceMgrProxy:QueryApn success");
    return ERR_OK;
}

int32_t NetworkManagerProxy::QueryApnIds(const AppExecFwk::ElementName &admin,
    const std::map<std::string, std::string> &apnInfoMap, std::vector<std::string> &apnIds)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(HAS_ADMIN);
    data.WriteParcelable(&admin);
    data.WriteString(EdmConstants::SetApn::QUERY_ID_FLAG);
    data.WriteInt32(apnInfoMap.size());
    for (const auto& iter : apnInfoMap) {
        data.WriteString(iter.first);
    }
    for (const auto& iter : apnInfoMap) {
        data.WriteString(iter.second);
    }
    EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(EdmInterfaceCode::SET_APN_INFO, data, reply);
    int32_t ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        EDMLOGE("EnterpriseDeviceMgrProxy:QueryApnIds error: %{public}d", ret);
        return ret;
    }
    
    int32_t size = reply.ReadInt32();
    if (size > POLICIES_MAX_SIZE) {
        EDMLOGE("EnterpriseDeviceMgrProxy:QueryApnIds invalid size: %{public}d", size);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    for (int32_t i = 0; i < size; i++) {
        std::string id = reply.ReadString();
        apnIds.push_back(id);
    }
    EDMLOGD("EnterpriseDeviceMgrProxy:QueryApnIds success. %{public}d", size);
    return ERR_OK;
}

#ifdef NETMANAGER_BASE_EDM_ENABLE
int32_t NetworkManagerProxy::SetGlobalHttpProxy(MessageParcel &data)
{
    EDMLOGD("NetworkManagerProxy::SetGlobalHttpProxy");
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::GLOBAL_PROXY);
    int32_t ret = EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
    EDMLOGI("NetworkManagerProxy::SetGlobalHttpProxy ret = %{public}d", ret);
    return ret;
}

int32_t NetworkManagerProxy::GetGlobalHttpProxy(const AppExecFwk::ElementName *admin,
    NetManagerStandard::HttpProxy &httpProxy, int32_t accountId)
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
    data.WriteInt32(accountId);
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
