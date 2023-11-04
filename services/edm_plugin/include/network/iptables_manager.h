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

    bool ExistAllowFirewallRule();
    bool ExistAllowDomainRule();

    bool ChainExistRule(const std::vector<std::string> &chainNames);

    static void SetDefaultFirewallDenyChain();
    static void ClearDefaultFirewallDenyChain();
    static void SetDefaultDomainDenyChain();
    static void ClearDefaultDomainDenyChain();

    static bool g_chainInit;
    static bool g_defaultFirewallChainInit;
    static bool g_defaultDomainChainInit;

    static std::shared_ptr<IptablesManager> instance_;
    static std::mutex mutexLock_;
};
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_PLUGIN_INCLUDE_IPTABLES_IPTABLES_MANAGER_H
