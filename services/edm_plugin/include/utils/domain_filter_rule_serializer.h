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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_UTILS_DOMAIN_FILTER_RULE_SERIALIZER_H
#define SERVICES_EDM_PLUGIN_INCLUDE_UTILS_DOMAIN_FILTER_RULE_SERIALIZER_H

#include "domain_filter_rule.h"
#include "ipolicy_serializer.h"
#include "json/json.h"
#include "singleton.h"

namespace OHOS {
namespace EDM {
/*
* Policy data serializer of type DomainFilterRuleParcel.
*/
class DomainFilterRuleSerializer : public IPolicySerializer<IPTABLES::DomainFilterRuleParcel>,
    public DelayedSingleton<DomainFilterRuleSerializer> {
public:
    bool Deserialize(const std::string &jsonString, IPTABLES::DomainFilterRuleParcel &dataObj) override;

    bool Serialize(const IPTABLES::DomainFilterRuleParcel &dataObj, std::string &jsonString) override;

    bool GetPolicy(MessageParcel &data, IPTABLES::DomainFilterRuleParcel &result) override;

    bool WritePolicy(MessageParcel &reply, IPTABLES::DomainFilterRuleParcel &result) override;

    bool MergePolicy(std::vector<IPTABLES::DomainFilterRuleParcel> &data,
        IPTABLES::DomainFilterRuleParcel &result) override;
};
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_PLUGIN_INCLUDE_UTILS_DOMAIN_FILTER_RULE_SERIALIZER_H