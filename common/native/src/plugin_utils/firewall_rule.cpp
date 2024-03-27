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

#include "firewall_rule.h"

namespace OHOS {
namespace EDM {
namespace IPTABLES {
FirewallRuleParcel::FirewallRuleParcel(FirewallRule rule) : rule_(std::move(rule)) {}

bool FirewallRuleParcel::Marshalling(MessageParcel& parcel) const
{
    parcel.WriteUint32(static_cast<int32_t>(std::get<FIREWALL_DICECTION_IND>(rule_)));
    parcel.WriteUint32(static_cast<int32_t>(std::get<FIREWALL_ACTION_IND>(rule_)));
    parcel.WriteUint32(static_cast<int32_t>(std::get<FIREWALL_PROT_IND>(rule_)));
    parcel.WriteString(std::get<FIREWALL_SRCADDR_IND>(rule_));
    parcel.WriteString(std::get<FIREWALL_DESTADDR_IND>(rule_));
    parcel.WriteString(std::get<FIREWALL_SRCPORT_IND>(rule_));
    parcel.WriteString(std::get<FIREWALL_DESTPORT_IND>(rule_));
    parcel.WriteString(std::get<FIREWALL_APPUID_IND>(rule_));
    return true;
}

bool FirewallRuleParcel::Unmarshalling(MessageParcel& parcel, FirewallRuleParcel& firewallRuleParcel)
{
    IPTABLES::Direction direction = IPTABLES::Direction::INVALID;
    IptablesUtils::ProcessFirewallDirection(parcel.ReadInt32(), direction);
    IPTABLES::Action action = IPTABLES::Action::INVALID;
    IptablesUtils::ProcessFirewallAction(parcel.ReadInt32(), action);
    IPTABLES::Protocol protocol = IPTABLES::Protocol::INVALID;
    IptablesUtils::ProcessFirewallProtocol(parcel.ReadInt32(), protocol);
    std::string srcAddr = parcel.ReadString();
    std::string destAddr = parcel.ReadString();
    std::string srcPort = parcel.ReadString();
    std::string destPort = parcel.ReadString();
    std::string appUid = parcel.ReadString();
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