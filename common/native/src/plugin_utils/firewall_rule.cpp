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

#include <iostream>

#include "firewall_rule.h"

namespace OHOS {
namespace EDM {
namespace IPTABLES {
FirewallRuleParcel::FirewallRuleParcel(FirewallRule rule) : rule_(std::move(rule)) {}

bool FirewallRuleParcel::Marshalling(Parcel& parcel) const
{
    parcel.WriteUint32(static_cast<int32_t>(std::get<0>(rule_)));
    parcel.WriteUint32(static_cast<int32_t>(std::get<1>(rule_)));
    parcel.WriteUint32(static_cast<int32_t>(std::get<2>(rule_)));
    parcel.WriteString(std::get<3>(rule_));
    parcel.WriteString(std::get<4>(rule_));
    parcel.WriteString(std::get<5>(rule_));
    parcel.WriteString(std::get<6>(rule_));
    parcel.WriteString(std::get<7>(rule_));
    return true;
}

bool FirewallRuleParcel::Unmarshalling(Parcel& parcel, FirewallRuleParcel& firewallRuleParcel)
{
    IPTABLES::Direction direction = IPTABLES::Direction::INVALID;
    IptablesUtils::ProcessFirewallDirection(parcel.ReadInt32(), direction);
    IPTABLES::Action action = IPTABLES::Action::INVALID;
    IptablesUtils::ProcessFirewallAction(parcel.ReadInt32(), action);
    IPTABLES::Protocol protocol = IPTABLES::Protocol::INVALID;
    IptablesUtils::ProcessFirewallProtocol(parcel.ReadInt32(), protocol);
    std::string srcAddr;
    srcAddr = parcel.ReadString();
    std::string destAddr;
    destAddr = parcel.ReadString();
    std::string srcPort;
    srcPort = parcel.ReadString();
    std::string destPort;
    destPort = parcel.ReadString();
    std::string appUid;
    appUid = parcel.ReadString();
    firewallRuleParcel.rule_ = {direction, action, protocol, srcAddr, destAddr, srcPort, destPort, appUid};
    return true;
}

FirewallRule FirewallRuleParcel::GetRule() const
{
    return rule_;
}
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS