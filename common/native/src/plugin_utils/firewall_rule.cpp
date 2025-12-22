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
#include "edm_log.h"
#include <regex>

namespace OHOS {
namespace EDM {
namespace IPTABLES {

const char* const IP_PATTERN =
    "((2([0-4]\\d|5[0-5])|1\\d\\d|[1-9]\\d|\\d)\\.){3}(2([0-4]\\d|5[0-5])|1\\d\\d|[1-9]\\d|\\d)";

const char* const IP_MASK_PATTERN =
    "((2([0-4]\\d|5[0-5])|1\\d\\d|[1-9]\\d|\\d)\\.){3}(2([0-4]\\d|5[0-5])|1\\d\\d|[1-9]\\d|\\d)/(3[0-2]|[1-2]\\d|\\d)";

const char* const IPV6_PATTERN = "([\\da-fA-F]{0,4}:){2,7}([\\da-fA-F]{0,4})";

const char* const IPV6_MASK_PATTERN = "([\\da-fA-F]{0,4}:){2,7}([\\da-fA-F]{0,4})/(1[0-2][0-8]|[1-9]\\d|[1-9])";

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
    parcel.WriteUint32(static_cast<int32_t>(std::get<FIREWALL_FAMILY_IND>(rule_)));
    parcel.WriteUint32(static_cast<int32_t>(std::get<FIREWALL_LOGTYPE_IND>(rule_)));
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
    IPTABLES::Family family = IPTABLES::Family::IPV4;
    IptablesUtils::ProcessFirewallFamily(parcel.ReadInt32(), family);
    IPTABLES::LogType logType = IPTABLES::LogType::INVALID;
    IptablesUtils::ProcessFirewallLogType(parcel.ReadInt32(), logType);
    firewallRuleParcel.rule_ = {direction, action, protocol, srcAddr, destAddr, srcPort,
        destPort, appUid, family, logType};
    return true;
}

FirewallRule FirewallRuleParcel::GetRule() const
{
    return rule_;
}

bool FirewallRuleParcel::CheckFirewallParams() const
{
    IPTABLES::Direction direction = std::get<FIREWALL_DICECTION_IND>(rule_);
    std::string srcAddr = std::get<FIREWALL_SRCADDR_IND>(rule_);
    std::string destAddr = std::get<FIREWALL_DESTADDR_IND>(rule_);
    IPTABLES::Family family = std::get<FIREWALL_FAMILY_IND>(rule_);
    if ((direction == Direction::INPUT || direction == Direction::FORWARD) &&
        !std::get<FIREWALL_APPUID_IND>(rule_).empty()) {
        EDMLOGE("FirewallRuleParcel CheckFirewallParams: illegal parameter: appUid");
        return false;
    }
    if (!srcAddr.empty() && !IpAddressIsLegal(srcAddr, family)) {
        EDMLOGE("FirewallRuleParcel CheckFirewallParams: illegal parameter: srcAddr");
        return false;
    }
    if (!destAddr.empty() && !IpAddressIsLegal(destAddr, family)) {
        EDMLOGE("FirewallRuleParcel CheckFirewallParams: illegal parameter: destAddr");
        return false;
    }
    return true;
}

bool FirewallRuleParcel::IpAddressIsLegal(const std::string &ip, Family family) const
{
    EDMLOGD("FirewallRuleParcel IpAddressIsLegal: family is %{public}d", static_cast<int32_t>(family));
    std::string splitStr = "-";
    auto idx = ip.find(splitStr);
    if (idx == std::string::npos && IpIsLegal(ip, family, true)) {
        return true;
    }
    if (idx != std::string::npos) {
        std::string ipStart = ip.substr(0, idx);
        std::string ipEnd = ip.substr(idx + splitStr.length());
        EDMLOGD("FirewallRuleParcel IpAddressIsLegal: ipAddress consists of ranges");
        if (IpIsLegal(ipStart, family, false) && IpIsLegal(ipEnd, family, false)) {
            return true;
        }
    }
    return false;
}

bool FirewallRuleParcel::IpIsLegal(const std::string &ip, Family family, bool notIpSegment) const
{
    if (family == IPTABLES::Family::IPV4 && (std::regex_match(ip, std::regex(IP_PATTERN)) ||
        (notIpSegment && std::regex_match(ip, std::regex(IP_MASK_PATTERN))))) {
        return true;
    }
    if (family == IPTABLES::Family::IPV6 && (std::regex_match(ip, std::regex(IPV6_PATTERN)) ||
        (notIpSegment && std::regex_match(ip, std::regex(IPV6_MASK_PATTERN))))) {
        return true;
    }
    EDMLOGD("FirewallRuleParcel IpIsLegal: Ip is illegal.");
    return false;
}
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS