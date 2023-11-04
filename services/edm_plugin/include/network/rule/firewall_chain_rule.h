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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_IPTABLES_FIREWALL_CHAIN_RULE_H
#define SERVICES_EDM_PLUGIN_INCLUDE_IPTABLES_FIREWALL_CHAIN_RULE_H

#include "chain_rule.h"
#include "firewall_rule.h"

namespace OHOS {
namespace EDM {
namespace IPTABLES {

class FirewallChainRule final : public ChainRule {
public:
    explicit FirewallChainRule();
    explicit FirewallChainRule(FirewallRule firewallTuple);
    explicit FirewallChainRule(const std::string &rule);
    FirewallRule ToFilterRule(Direction direction);
    [[nodiscard]] std::string Parameter() const override;

private:
    static std::string IpToParameter(const std::string &ip, const std::string &ipType);
    static std::string PortToParameter(const std::string &port, const std::string &portType,
        const std::string &portOption);

private:
    std::string srcPort_;
    std::string destPort_;
    std::string appUid_;
    std::string state_;
};
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_PLUGIN_INCLUDE_IPTABLES_FIREWALL_CHAIN_RULE_H
