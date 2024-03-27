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

#ifndef INTERFACES_INNER_API_NETWORK_MANAGER_INCLUDE_IPTABLES_DOMAIN_FILTER_RULE_H
#define INTERFACES_INNER_API_NETWORK_MANAGER_INCLUDE_IPTABLES_DOMAIN_FILTER_RULE_H

#include <tuple>

#include "iptables_utils.h"
#include "message_parcel.h"

namespace OHOS {
namespace EDM {
namespace IPTABLES {

const int32_t DOMAIN_ACTION_IND = 0;
const int32_t DOMAIN_APPUID_IND = 1;
const int32_t DOMAIN_DOMAINNAME_IND = 2;

using DomainFilterRule = std::tuple<Action, std::string /*appUid*/, std::string /*domainName*/>;

class DomainFilterRuleParcel {
public:
    DomainFilterRuleParcel() = default;
    explicit DomainFilterRuleParcel(DomainFilterRule rule);

    [[nodiscard]] DomainFilterRule GetRule() const;

    bool Marshalling(MessageParcel& parcel) const;

    static bool Unmarshalling(MessageParcel& parcel, DomainFilterRuleParcel& domainFilterRuleParcel);

private:
    DomainFilterRule rule_;
};
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS
#endif // INTERFACES_INNER_API_NETWORK_MANAGER_INCLUDE_IPTABLES_DOMAIN_FILTER_RULE_H
