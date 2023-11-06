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

#include "firewall_chain_rule.h"

#include <algorithm>
#include <iostream>
#include <sstream>
#include <string>

#include "rule_utils.h"

namespace OHOS {
namespace EDM {
namespace IPTABLES {

FirewallChainRule::FirewallChainRule(): ChainRule()
{
    target_ = ACCEPT_TARGET;
    state_ = "RELATED,ESTABLISHED";
}

FirewallChainRule::FirewallChainRule(FirewallRule firewallTuple) : ChainRule(),
    srcPort_(std::get<FIREWALL_SRCPORT_IND>(firewallTuple)),
    destPort_(std::get<FIREWALL_DESTPORT_IND>(firewallTuple)),
    appUid_(std::get<FIREWALL_APPUID_IND>(firewallTuple))
{
    target_ = RuleUtils::EnumToString(std::get<FIREWALL_ACTION_IND>(firewallTuple));
    prot_ = RuleUtils::EnumToString(std::get<FIREWALL_PROT_IND>(firewallTuple));
    srcAddr_ = std::get<FIREWALL_SRCADDR_IND>(firewallTuple);
    destAddr_ = std::get<FIREWALL_DESTADDR_IND>(firewallTuple);
}

FirewallChainRule::FirewallChainRule(const std::string &rule) : ChainRule(rule)
{
    GetOption(otherOptions_, "source IP range", srcAddr_);
    GetOption(otherOptions_, "destination IP range", destAddr_);
    std::string spt;
    GetOption(otherOptions_, "spt:", spt);
    if (spt.empty()) {
        GetOption(otherOptions_, "spts:", spt);
        if (spt.empty()) {
            GetOption(otherOptions_, "multiport sports", spt);
        }
    }
    srcPort_ = spt;
    std::string dpt;
    GetOption(otherOptions_, "dpt:", dpt);
    if (dpt.empty()) {
        GetOption(otherOptions_, "dpts:", dpt);
        if (dpt.empty()) {
            GetOption(otherOptions_, "multiport dports", dpt);
        }
    }
    destPort_ = dpt;
    GetOption(otherOptions_, "owner UID match", appUid_);
}

std::string FirewallChainRule::Parameter() const
{
    std::ostringstream parameterString;
    if (!prot_.empty()) {
        parameterString << " -p ";
        parameterString << prot_;
    }
    parameterString << IpToParameter(srcAddr_, "-s");
    parameterString << IpToParameter(destAddr_, "-d");

    std::string splitStr = ",";
    auto sidx = srcPort_.find(splitStr);
    auto didx = destPort_.find(splitStr);
    std::string portOption = SPACE_OPTION;
    if (sidx != std::string::npos || didx != std::string::npos) {
        portOption = " -m multiport ";
    }
    parameterString << PortToParameter(srcPort_, "--sport", portOption);
    parameterString << PortToParameter(destPort_, "--dport", portOption);
    if (!appUid_.empty()) {
        parameterString << " -m owner --uid-owner " << appUid_;
    }
    if (!state_.empty()) {
        parameterString << " -m state --state " << state_;
    }
    return parameterString.str();
}

std::string FirewallChainRule::IpToParameter(const std::string &ip, const std::string &ipType)
{
    if (ip.empty()) {
        return {};
    }
    std::ostringstream parameterString;
    std::string splitStr = "-";
    auto idx = ip.find(splitStr);
    if (idx == std::string::npos) {
        parameterString << SPACE_OPTION << ipType << SPACE_OPTION << ip;
    } else {
        if (ipType == "-s") {
            parameterString << " -m iprange --src-range " << ip;
        } else {
            parameterString << " -m iprange --dst-range " << ip;
        }
    }
    return parameterString.str();
}

std::string FirewallChainRule::PortToParameter(const std::string &port, const std::string &portType,
    const std::string &portOption)
{
    if (port.empty()) {
        return {};
    }
    std::ostringstream parameterString;
    parameterString << portOption << portType << SPACE_OPTION << port;
    return parameterString.str();
}

FirewallRule FirewallChainRule::ToFilterRule(Direction direction)
{
    Action action = RuleUtils::StringToAction(target_);
    Protocol protocl = RuleUtils::StringProtocl(prot_);
    return {direction, action, protocl, srcAddr_, destAddr_, srcPort_, destPort_, appUid_};
}

} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS