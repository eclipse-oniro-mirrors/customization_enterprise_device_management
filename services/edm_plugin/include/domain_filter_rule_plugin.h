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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_DOMAIN_FILTER_RULE_PLUGIN_H
#define SERVICES_EDM_PLUGIN_INCLUDE_DOMAIN_FILTER_RULE_PLUGIN_H

#include <message_parcel.h>

#include "plugin_singleton.h"
#include "domain_filter_rule.h"

namespace OHOS {
namespace EDM {
class DomainFilterRulePlugin : public PluginSingleton<DomainFilterRulePlugin, IPTABLES::DomainFilterRuleParcel> {
public:
    void InitPlugin(
        std::shared_ptr<IPluginTemplate<DomainFilterRulePlugin, IPTABLES::DomainFilterRuleParcel>> ptr) override;

    ErrCode OnSetPolicy(IPTABLES::DomainFilterRuleParcel &ruleParcel);

    ErrCode OnRemovePolicy(IPTABLES::DomainFilterRuleParcel &ruleParcel);

    ErrCode OnGetPolicy(std::string &value, MessageParcel &data, MessageParcel &reply, int32_t userId) override;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_INCLUDE_DOMAIN_FILTER_RULE_PLUGIN_H