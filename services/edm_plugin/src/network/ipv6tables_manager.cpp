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

#include "ipv6tables_manager.h"

#include <iostream>
#include <unordered_map>

#include "domain_chain_rule.h"
#include "edm_log.h"
#include "executer_factory.h"
#include "firewall_chain_rule.h"
#include "iexecuter.h"
#include "rule_utils.h"

namespace OHOS {
namespace EDM {
namespace IPTABLES {

ErrCode Ipv6tablesManager::AddFirewallRule(const FirewallRuleParcel& firewall)
{
    return IptablesManager::AddFirewallRule(firewall, Family::IPV6);
}

ErrCode Ipv6tablesManager::RemoveFirewallRule(const FirewallRuleParcel& firewall)
{
    return IptablesManager::RemoveFirewallRule(firewall, Family::IPV6);
}

ErrCode Ipv6tablesManager::GetFirewallRules(std::vector<FirewallRuleParcel>& list)
{
    return IptablesManager::GetFirewallRules(list, Family::IPV6);
}

ErrCode Ipv6tablesManager::AddDomainFilterRule(const DomainFilterRuleParcel& domainFilter)
{
    return IptablesManager::AddDomainFilterRule(domainFilter, Family::IPV6);
}

ErrCode Ipv6tablesManager::RemoveDomainFilterRules(const DomainFilterRuleParcel& domainFilter)
{
    return IptablesManager::RemoveDomainFilterRules(domainFilter, Family::IPV6);
}

ErrCode Ipv6tablesManager::GetDomainFilterRules(std::vector<DomainFilterRuleParcel>& list)
{
    return IptablesManager::GetDomainFilterRules(list, Family::IPV6);
}

bool Ipv6tablesManager::HasInit()
{
    return IptablesManager::HasInit(NetsysNative::IptablesType::IPTYPE_IPV6);
}

void Ipv6tablesManager::Init()
{
    IptablesManager::Init(NetsysNative::IptablesType::IPTYPE_IPV6);
}
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS