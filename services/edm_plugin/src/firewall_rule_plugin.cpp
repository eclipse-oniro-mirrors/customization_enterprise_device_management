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
#include "plugin_manager.h"

using namespace OHOS::EDM::IPTABLES;

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(FirewallRulePlugin::GetPlugin());

void FirewallRulePlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<FirewallRulePlugin, IPTABLES::FirewallRuleParcel>> ptr)
{
    EDMLOGI("FirewallRulePlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::FIREWALL_RULE, "firewall_rule", "ohos.permission.ENTERPRISE_MANAGE_NETWORK",
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(FirewallRuleSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&FirewallRulePlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnHandlePolicyListener(&FirewallRulePlugin::OnRemovePolicy, FuncOperateType::REMOVE);
}

ErrCode FirewallRulePlugin::OnSetPolicy(IPTABLES::FirewallRuleParcel &ruleParcel)
{
    auto rule = ruleParcel.GetRule();
    if (!IPTABLES::IptablesManager::GetInstance()->HasInit()) {
        IPTABLES::IptablesManager::GetInstance()->Init();
    }
    return IPTABLES::IptablesManager::GetInstance()->AddFirewallRule(ruleParcel);
}

ErrCode FirewallRulePlugin::OnRemovePolicy(IPTABLES::FirewallRuleParcel &ruleParcel)
{
    auto rule = ruleParcel.GetRule();
    if (!IPTABLES::IptablesManager::GetInstance()->HasInit()) {
        IPTABLES::IptablesManager::GetInstance()->Init();
    }
    return IptablesManager::GetInstance()->RemoveFirewallRule(ruleParcel);
}

ErrCode FirewallRulePlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    reply.WriteInt32(ERR_OK);
    if (!IptablesManager::GetInstance()->HasInit()) {
        IptablesManager::GetInstance()->Init();
        reply.WriteInt32(0);
    } else {
        std::vector<FirewallRuleParcel> list;
        ErrCode ret = IptablesManager::GetInstance()->GetFirewallRules(list);
        if (ret != ERR_OK) {
            EDMLOGE("FirewallRulePlugin OnGetPolicy fail");
            return ret;
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
