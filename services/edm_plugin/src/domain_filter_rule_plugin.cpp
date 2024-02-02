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

#include "domain_filter_rule_plugin.h"

#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "func_code_utils.h"
#include "domain_filter_rule_serializer.h"
#include "iptables_manager.h"
#include "plugin_manager.h"

using namespace OHOS::EDM::IPTABLES;

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(DomainFilterRulePlugin::GetPlugin());

void DomainFilterRulePlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<DomainFilterRulePlugin, IPTABLES::DomainFilterRuleParcel>> ptr)
{
    EDMLOGI("DomainFilterRulePlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::DOMAIN_FILTER_RULE, "domain_filter_rule",
        "ohos.permission.ENTERPRISE_MANAGE_NETWORK", IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(DomainFilterRuleSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DomainFilterRulePlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnHandlePolicyListener(&DomainFilterRulePlugin::OnRemovePolicy, FuncOperateType::REMOVE);
}

ErrCode DomainFilterRulePlugin::OnSetPolicy(IPTABLES::DomainFilterRuleParcel &ruleParcel)
{
    auto rule = ruleParcel.GetRule();
    if (!IptablesManager::GetInstance()->HasInit()) {
        IptablesManager::GetInstance()->Init();
    }
    return IptablesManager::GetInstance()->AddDomainFilterRule(ruleParcel);
}

ErrCode DomainFilterRulePlugin::OnRemovePolicy(IPTABLES::DomainFilterRuleParcel &ruleParcel)
{
    auto rule = ruleParcel.GetRule();
    if (!IptablesManager::GetInstance()->HasInit()) {
        IptablesManager::GetInstance()->Init();
    }
    return IptablesManager::GetInstance()->RemoveDomainFilterRules(ruleParcel);
}

ErrCode DomainFilterRulePlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("DomainFilterRulePlugin OnGetPolicy.");
    reply.WriteInt32(ERR_OK);
    if (!IptablesManager::GetInstance()->HasInit()) {
        IptablesManager::GetInstance()->Init();
        reply.WriteInt32(ERR_OK);
    } else {
        std::vector<DomainFilterRuleParcel> list;
        ErrCode ret = IptablesManager::GetInstance()->GetDomainFilterRules(list);
        if (ret != ERR_OK) {
            EDMLOGE("DomainFilterRulePlugin OnGetPolicy fail");
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
