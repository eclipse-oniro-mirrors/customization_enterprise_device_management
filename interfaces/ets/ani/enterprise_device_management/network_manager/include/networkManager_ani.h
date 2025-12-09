/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef NETWORKMANAGER_ANI_H
#define NETWORKMANAGER_ANI_H

#include <ani.h>
#include "domain_filter_rule.h"
#include "firewall_rule.h"
#include "enterprise_device_mgr_proxy.h"

namespace OHOS {
namespace EDM {
class NetworkManagerAni {
public:
    NetworkManagerAni();
    ~NetworkManagerAni() = default;
    static ani_status Init(ani_env* vm);
private:
    static void AddFirewallRule(ani_env* env, ani_object admin, ani_object firewallRule);
    static void RemoveFirewallRule(ani_env* env, ani_object admin, ani_object firewallRule);
    static void AddDomainFilterRule(ani_env* env, ani_object admin, ani_object domainFilterRule);
    static void RemoveDomainFilterRule(ani_env* env, ani_object admin, ani_object domainFilterRule);
    static void JsObjToFirewallRule(ani_env* env, ani_object firewallRule, IPTABLES::FirewallRule &rule);
    static void JsObjToDomainFilterRule(ani_env* env, ani_object domainFilterRule, IPTABLES::DomainFilterRule &rule);
};
} // namespace EDM
} // namespace OHOS
#endif
