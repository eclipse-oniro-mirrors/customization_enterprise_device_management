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

#include "domain_filter_rule.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
namespace IPTABLES {

const int32_t MAX_DOMAIN_LENGTH = 255;

DomainFilterRuleParcel::DomainFilterRuleParcel(DomainFilterRule rule) : rule_(std::move(rule)) {}

bool DomainFilterRuleParcel::Marshalling(MessageParcel& parcel) const
{
    parcel.WriteInt32(static_cast<int32_t>(std::get<DOMAIN_ACTION_IND>(rule_)));
    parcel.WriteString(std::get<DOMAIN_APPUID_IND>(rule_));
    parcel.WriteString(std::get<DOMAIN_DOMAINNAME_IND>(rule_));
    parcel.WriteInt32(static_cast<int32_t>(std::get<DOMAIN_DIRECTION_IND>(rule_)));
    parcel.WriteInt32(static_cast<int32_t>(std::get<DOMAIN_FAMILY_IND>(rule_)));
    return true;
}

bool DomainFilterRuleParcel::Unmarshalling(MessageParcel& parcel, DomainFilterRuleParcel& domainFilterRuleParcel)
{
    IPTABLES::Action action = IPTABLES::Action::INVALID;
    IPTABLES::Direction direction = IPTABLES::Direction::INVALID;
    IPTABLES::Family family = IPTABLES::Family::IPV4;
    IptablesUtils::ProcessFirewallAction(parcel.ReadInt32(), action);
    std::string appUid = parcel.ReadString();
    std::string domainName = parcel.ReadString();
    IptablesUtils::ProcessFirewallDirection(parcel.ReadInt32(), direction);
    IptablesUtils::ProcessFirewallFamily(parcel.ReadInt32(), family);
    domainFilterRuleParcel.rule_ = {action, appUid, domainName, direction, family};
    return true;
}

DomainFilterRule DomainFilterRuleParcel::GetRule() const
{
    return rule_;
}

bool DomainFilterRuleParcel::CheckAddDomainParams() const
{
    IPTABLES::Direction direction = std::get<DOMAIN_DIRECTION_IND>(rule_);
    std::string appUid = std::get<DOMAIN_APPUID_IND>(rule_);
    std::string domainName = std::get<DOMAIN_DOMAINNAME_IND>(rule_);
    if (direction == Direction::FORWARD && !appUid.empty()) {
        EDMLOGE("AddDomainFilterRule: illegal parameter: appUid");
        return false;
    }
    if (domainName.empty() || domainName.length() > MAX_DOMAIN_LENGTH) {
        EDMLOGE("AddDomainFilterRule: illegal parameter: domainName");
        return false;
    }
    auto index = domainName.find_first_of("|/");
    if (index != std::string ::npos) {
        EDMLOGE("AddDomainFilterRule: illegal parameter: domainName");
        return false;
    }
    return true;
}

bool DomainFilterRuleParcel::CheckRemoveDomainParams() const
{
    IPTABLES::Direction direction = std::get<DOMAIN_DIRECTION_IND>(rule_);
    std::string appUid = std::get<DOMAIN_APPUID_IND>(rule_);
    std::string domainName = std::get<DOMAIN_DOMAINNAME_IND>(rule_);
    IPTABLES::Action action = std::get<DOMAIN_ACTION_IND>(rule_);
    if (direction == Direction::FORWARD && !appUid.empty()) {
        EDMLOGE("RemoveDomainFilterRules: illegal parameter: appUid");
        return false;
    }
    if (domainName.empty() && !appUid.empty()) {
        EDMLOGE("RemoveDomainFilterRules: illegal parameter: appUid");
        return false;
    }
    if (!domainName.empty() && domainName.length() > MAX_DOMAIN_LENGTH) {
        EDMLOGE("RemoveDomainFilterRules: illegal parameter: domainName");
        return false;
    }
    auto index = domainName.find_first_of("|/");
    if (index != std::string ::npos) {
        EDMLOGE("RemoveDomainFilterRules: illegal parameter: domainName");
        return false;
    }

    if (action == Action::INVALID && (!appUid.empty() || !domainName.empty())) {
        EDMLOGE("RemoveDomainFilterRules: illegal parameter: Too many parameters set");
        return false;
    }

    return true;
}
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS