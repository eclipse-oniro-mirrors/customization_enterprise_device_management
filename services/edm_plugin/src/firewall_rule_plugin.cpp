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

#include "firewall_rule_plugin.h"

#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "func_code_utils.h"
#include "firewall_rule_serializer.h"
#include "iptables_manager.h"
#include "iplugin_manager.h"
#include "iptables_factory.h"

using namespace OHOS::EDM::IPTABLES;

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(FirewallRulePlugin::GetPlugin());

void FirewallRulePlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<FirewallRulePlugin, IPTABLES::FirewallRuleParcel>> ptr)
{
    EDMLOGI("FirewallRulePlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::FIREWALL_RULE, PolicyName::POLICY_FIREWALL_RULE,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_NETWORK, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(FirewallRuleSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&FirewallRulePlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnHandlePolicyListener(&FirewallRulePlugin::OnRemovePolicy, FuncOperateType::REMOVE);
}

ErrCode FirewallRulePlugin::OnSetPolicy(IPTABLES::FirewallRuleParcel &ruleParcel)
{
    auto rule = ruleParcel.GetRule();
    IPTABLES::Family family = std::get<FIREWALL_FAMILY_IND>(rule);
    std::shared_ptr<IptablesManager> iptablesManager =
        IPTABLES::IptablesFactory::GetInstance()->CreateIptablesManagerForFamily(family);
    if (!iptablesManager->HasInit()) {
        iptablesManager->Init();
    }
    return iptablesManager->AddFirewallRule(ruleParcel);
}

ErrCode FirewallRulePlugin::OnRemovePolicy(IPTABLES::FirewallRuleParcel &ruleParcel)
{
    auto rule = ruleParcel.GetRule();
    IPTABLES::Family family = std::get<FIREWALL_FAMILY_IND>(rule);
    std::shared_ptr<IptablesManager> iptablesManager =
        IPTABLES::IptablesFactory::GetInstance()->CreateIptablesManagerForFamily(family);
    if (!iptablesManager->HasInit()) {
        iptablesManager->Init();
    }
    return iptablesManager->RemoveFirewallRule(ruleParcel);
}

ErrCode FirewallRulePlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    reply.WriteInt32(ERR_OK);
    std::shared_ptr<IptablesManager> ipv4tablesManager =
        IPTABLES::IptablesFactory::GetInstance()->CreateIptablesManagerForFamily(IPTABLES::Family::IPV4);
    std::shared_ptr<IptablesManager> ipv6tablesManager =
        IPTABLES::IptablesFactory::GetInstance()->CreateIptablesManagerForFamily(IPTABLES::Family::IPV6);
    if (!ipv4tablesManager->HasInit() && !ipv6tablesManager->HasInit()) {
        ipv4tablesManager->Init();
        ipv6tablesManager->Init();
        reply.WriteInt32(0);
    } else {
        std::vector<FirewallRuleParcel> list;
        if (ipv4tablesManager->HasInit()) {
            ipv4tablesManager->GetFirewallRules(list);
        }
        if (ipv6tablesManager->HasInit()) {
            ipv6tablesManager->GetFirewallRules(list);
        }
        reply.WriteInt32(list.size());
        for (auto const &item : list) {
            item.Marshalling(reply);
        }
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
