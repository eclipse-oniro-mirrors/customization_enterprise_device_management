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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_IPTABLES_DOMAIN_CHAIN_RULE_H
#define SERVICES_EDM_PLUGIN_INCLUDE_IPTABLES_DOMAIN_CHAIN_RULE_H

#include "domain_filter_rule.h"
#include "chain_rule.h"

namespace OHOS {
namespace EDM {
namespace IPTABLES {

class DomainChainRule final: public ChainRule {
public:
    explicit DomainChainRule(DomainFilterRule domainFilterRule);
    explicit DomainChainRule(const std::string& rule);
    DomainFilterRule ToFilterRule();
    [[nodiscard]] std::string Parameter() const override;

private:
    static std::string DomainToFormatData(const std::string& domainName);
    static std::string FormatDataToDomain(const std::string& formatData);
    static uint8_t CharToHex(const char& first, const char& second);
    static uint8_t CharToHex(const char& hexChar);

private:
    std::string appUid_;
    std::string domainName_;
};
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_PLUGIN_INCLUDE_IPTABLES_DOMAIN_CHAIN_RULE_H
