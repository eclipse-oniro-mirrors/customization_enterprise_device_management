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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_IPTABLES_IPV4TABLES_MANAGER_H
#define SERVICES_EDM_PLUGIN_INCLUDE_IPTABLES_IPV4TABLES_MANAGER_H

#include "iptables_manager.h"

namespace OHOS {
namespace EDM {
namespace IPTABLES {

class Ipv4tablesManager final : public IptablesManager {
public:
    ErrCode AddFirewallRule(const FirewallRuleParcel& firewall) override;
    ErrCode RemoveFirewallRule(const FirewallRuleParcel& firewall) override;
    ErrCode GetFirewallRules(std::vector<FirewallRuleParcel>& list) override;
    ErrCode AddDomainFilterRule(const DomainFilterRuleParcel& domainFilter) override;
    ErrCode RemoveDomainFilterRules(const DomainFilterRuleParcel& domainFilter) override;
    ErrCode GetDomainFilterRules(std::vector<DomainFilterRuleParcel>& list) override;

    bool HasInit() override;
    void Init() override;
};
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_PLUGIN_INCLUDE_IPTABLES_IPV4TABLES_MANAGER_H
