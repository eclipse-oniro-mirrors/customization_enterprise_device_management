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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_IPTABLES_IPTABLES_MANAGER_H
#define SERVICES_EDM_PLUGIN_INCLUDE_IPTABLES_IPTABLES_MANAGER_H

#include <memory>
#include <thread>
#include <mutex>
#include <unistd.h>
#include <string>
#include <vector>

#include "chain_rule.h"
#include "domain_filter_rule.h"
#include "edm_errors.h"
#include "firewall_rule.h"
#include "i_netsys_service.h"

namespace OHOS {
namespace EDM {
namespace IPTABLES {

class IptablesManager {
public:
    ErrCode AddFirewallRule(const FirewallRuleParcel &firewall, Family family);
    ErrCode RemoveFirewallRule(const FirewallRuleParcel &firewall, Family family);
    ErrCode GetFirewallRules(std::vector<FirewallRuleParcel> &list, Family family);
    ErrCode AddDomainFilterRule(const DomainFilterRuleParcel &domainFilter, Family family);
    ErrCode RemoveDomainFilterRules(const DomainFilterRuleParcel &domainFilter, Family family);
    ErrCode GetDomainFilterRules(std::vector<DomainFilterRuleParcel> &list, Family family);

    virtual ErrCode AddFirewallRule(const FirewallRuleParcel &firewall) = 0;
    virtual ErrCode RemoveFirewallRule(const FirewallRuleParcel &firewall) = 0;
    virtual ErrCode GetFirewallRules(std::vector<FirewallRuleParcel> &list) = 0;
    virtual ErrCode AddDomainFilterRule(const DomainFilterRuleParcel &domainFilter) = 0;
    virtual ErrCode RemoveDomainFilterRules(const DomainFilterRuleParcel &domainFilter) = 0;
    virtual ErrCode GetDomainFilterRules(std::vector<DomainFilterRuleParcel> &list) = 0;

    bool HasInit(NetsysNative::IptablesType ipType);
    void Init(NetsysNative::IptablesType ipType);
    virtual bool HasInit() = 0;
    virtual void Init() = 0;

protected:
    bool g_chainInit = false;
    bool g_defaultFirewallOutputChainInit = false;
    bool g_defaultFirewallForwardChainInit = false;
    bool g_defaultDomainOutputChainInit = false;
    bool g_defaultDomainForwardChainInit = false;

private:
    ErrCode GetRemoveChainName(Direction direction, Action action, std::vector<std::string> &chainNameList);
    ErrCode GetDomainRemoveChainName(Direction direction, Action action, std::vector<std::string>& chainNameList);
    void GetRemoveInputChainName(Action action, std::vector<std::string>& chainNameList);
    void GetRemoveOutputChainName(Action action, std::vector<std::string>& chainNameList);
    void GetRemoveForwardChainName(Action action, std::vector<std::string>& chainNameList);
    void GetDomainRemoveOutputChainName(Action action, std::vector<std::string>& chainNameList);
    void GetDomainRemoveForwardChainName(Action action, std::vector<std::string>& chainNameList);

    bool ExistOutputAllowFirewallRule(NetsysNative::IptablesType ipType);
    bool ExistForwardAllowFirewallRule(NetsysNative::IptablesType ipType);
    bool ExistOutputAllowDomainRule(NetsysNative::IptablesType ipType);
    bool ExistForwardAllowDomainRule(NetsysNative::IptablesType ipType);
    bool GetFirewallChainName(Direction direction, Action action, std::string& chainName);
    bool GetDomainChainName(Direction direction, Action action, std::string& chainName);

    bool ChainExistRule(const std::vector<std::string> &chainNames, NetsysNative::IptablesType ipType);
    void ConvertFirewallRuleList(std::vector<FirewallRuleParcel>& list,
        std::vector<std::string> ruleList, Direction direction, Family family);
    void ConvertDomainFilterRuleList(std::vector<DomainFilterRuleParcel>& list,
        std::vector<std::string> ruleList, Direction direction, Family family);
};
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_PLUGIN_INCLUDE_IPTABLES_IPTABLES_MANAGER_H
