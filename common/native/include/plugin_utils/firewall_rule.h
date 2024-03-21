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

#ifndef INTERFACES_INNER_API_NETWORK_MANAGER_INCLUDE_IPTABLES_FIREWALL_RULE_H
#define INTERFACES_INNER_API_NETWORK_MANAGER_INCLUDE_IPTABLES_FIREWALL_RULE_H

#include <tuple>

#include "iptables_utils.h"
#include "message_parcel.h"

namespace OHOS {
namespace EDM {
namespace IPTABLES {

const int32_t FIREWALL_DICECTION_IND = 0;
const int32_t FIREWALL_ACTION_IND = 1;
const int32_t FIREWALL_PROT_IND = 2;
const int32_t FIREWALL_SRCADDR_IND = 3;
const int32_t FIREWALL_DESTADDR_IND = 4;
const int32_t FIREWALL_SRCPORT_IND = 5;
const int32_t FIREWALL_DESTPORT_IND = 6;
const int32_t FIREWALL_APPUID_IND = 7;

using FirewallRule = std::tuple<Direction, Action, Protocol, std::string /*srcAddr*/, std::string /*destAddr*/,
    std::string /*srcPort*/, std::string /*destPort*/, std::string /*appUid*/>;
class FirewallRuleParcel {
public:
    FirewallRuleParcel() = default;
    explicit FirewallRuleParcel(FirewallRule rule);

    FirewallRule GetRule() const;

    bool Marshalling(MessageParcel& parcel) const;

    static bool Unmarshalling(MessageParcel& parcel, FirewallRuleParcel& firewallRuleParcel);

private:
    FirewallRule rule_;
};
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS
#endif // INTERFACES_INNER_API_NETWORK_MANAGER_INCLUDE_IPTABLES_FIREWALL_RULE_H
