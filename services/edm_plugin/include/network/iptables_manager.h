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

namespace OHOS {
namespace EDM {
namespace IPTABLES {

class IptablesManager {
public:
    static std::shared_ptr<IptablesManager> GetInstance();
    ErrCode AddFirewallRule(const FirewallRuleParcel &firewall);
    ErrCode RemoveFirewallRule(const FirewallRuleParcel &firewall);
    ErrCode GetFirewallRules(std::vector<FirewallRuleParcel> &list);

    ErrCode AddDomainFilterRule(const DomainFilterRuleParcel &DomainFilter);
    ErrCode RemoveDomainFilterRules(const DomainFilterRuleParcel &DomainFilter);
    ErrCode GetDomainFilterRules(std::vector<DomainFilterRuleParcel> &list);

    static void Init();
    static bool HasInit();

private:
    ErrCode GetRemoveChainName(Direction direction, Action action, std::vector<std::string> &chainNameList);
    ErrCode GetDomainRemoveChainName(Direction direction, Action action, std::vector<std::string>& chainNameList);
    bool ExistOutputAllowFirewallRule();
    bool ExistForwardAllowFirewallRule();
    bool ExistOutputAllowDomainRule();
    bool ExistForwardAllowDomainRule();
    bool CheckRemoveDomainParams(Action action, std::string appUid, std::string domainName);
    bool CheckRemoveFirewallParams(Direction direction, FirewallRule rule);
    bool CheckAddFirewallParams(Direction direction, FirewallRule rule);

    bool ChainExistRule(const std::vector<std::string> &chainNames);

    static void SetDefaultFirewallDenyChain(Direction direction);
    static void ClearDefaultFirewallOutputDenyChain();
    static void ClearDefaultFirewallForwardDenyChain();
    static void SetDefaultDomainDenyChain(Direction direction);
    static void ClearDefaultDomainOutputDenyChain();
    static void ClearDefaultDomainForwardDenyChain();

    static bool g_chainInit;
    static bool g_defaultFirewallOutputChainInit;
    static bool g_defaultFirewallForwardChainInit;
    static bool g_defaultDomainOutputChainInit;
    static bool g_defaultDomainForwardChainInit;

    static std::shared_ptr<IptablesManager> instance_;
    static std::mutex mutexLock_;
};
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_PLUGIN_INCLUDE_IPTABLES_IPTABLES_MANAGER_H
