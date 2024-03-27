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

namespace OHOS {
namespace EDM {
namespace IPTABLES {

DomainFilterRuleParcel::DomainFilterRuleParcel(DomainFilterRule rule) : rule_(std::move(rule)) {}

bool DomainFilterRuleParcel::Marshalling(MessageParcel& parcel) const
{
    parcel.WriteUint32(static_cast<int32_t>(std::get<DOMAIN_ACTION_IND>(rule_)));
    parcel.WriteString(std::get<DOMAIN_APPUID_IND>(rule_));
    parcel.WriteString(std::get<DOMAIN_DOMAINNAME_IND>(rule_));
    return true;
}

bool DomainFilterRuleParcel::Unmarshalling(MessageParcel& parcel, DomainFilterRuleParcel& domainFilterRuleParcel)
{
    IPTABLES::Action action = IPTABLES::Action::INVALID;
    IptablesUtils::ProcessFirewallAction(parcel.ReadInt32(), action);
    std::string appUid = parcel.ReadString();
    std::string domainName = parcel.ReadString();
    domainFilterRuleParcel.rule_ = {action, appUid, domainName};
    return true;
}

DomainFilterRule DomainFilterRuleParcel::GetRule() const
{
    return rule_;
}
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS