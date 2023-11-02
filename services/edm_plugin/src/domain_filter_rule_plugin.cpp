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
#include "iplugin_manager.h"
#include "iptables_service.h"

using namespace OHOS::EDM::IPTABLES;

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DomainFilterRulePlugin::GetPlugin());

void DomainFilterRulePlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<DomainFilterRulePlugin, IPTABLES::DomainFilterRuleParcel>> ptr)
{
    EDMLOGD("DomainFilterRulePlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::DOMAIN_FILTER_RULE, "firewall_rule", "ohos.permission.ENTERPRISE_MANAGE_NETWORK",
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(DomainFilterRuleSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DomainFilterRulePlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnHandlePolicyListener(&DomainFilterRulePlugin::OnRemovePolicy, FuncOperateType::REMOVE);
}

ErrCode DomainFilterRulePlugin::OnSetPolicy(IPTABLES::DomainFilterRuleParcel &ruleParcel)
{
    auto rule = ruleParcel.GetRule();
    EDMLOGI("DomainFilterRulePlugin OnSetPolicy.");
    EDMLOGI("DomainFilterRulePlugin action %{public}d", static_cast<int32_t>(std::get<0>(rule)));
    EDMLOGI("DomainFilterRulePlugin appUid %{public}s", std::get<1>(rule).c_str());
    EDMLOGI("DomainFilterRulePlugin domainName %{public}s", std::get<2>(rule).c_str());
    if (!IptablesService::GetInstance()->HasInit()) {
        IptablesService::GetInstance()->Init();
    }
    return IptablesService::GetInstance()->AddDomainFilterRule(ruleParcel);
}

ErrCode DomainFilterRulePlugin::OnRemovePolicy(IPTABLES::DomainFilterRuleParcel &ruleParcel)
{
    auto rule = ruleParcel.GetRule();
    EDMLOGI("DomainFilterRulePlugin OnRemovePolicy.");
    EDMLOGI("DomainFilterRulePlugin action %{public}d", static_cast<int32_t>(std::get<0>(rule)));
    EDMLOGI("DomainFilterRulePlugin appUid %{public}s", std::get<1>(rule).c_str());
    EDMLOGI("DomainFilterRulePlugin domainName %{public}s", std::get<2>(rule).c_str());
    if (!IptablesService::GetInstance()->HasInit()) {
        IptablesService::GetInstance()->Init();
    }
    return IptablesService::GetInstance()->RemoveDomainFilterRules(ruleParcel);
}

ErrCode DomainFilterRulePlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("DomainFilterRulePlugin OnGetPolicy.");
    reply.WriteInt32(ERR_OK);
//    IPTABLES::DomainFilterRuleParcel domainFilterRuleParcel1{{IPTABLES::Action::ALLOW, "1000", "www.baidu.com"}};
//    domainFilterRuleParcel1.Marshalling(reply);
//    IPTABLES::DomainFilterRuleParcel domainFilterRuleParcel2{{IPTABLES::Action::ALLOW, "2000", "www.example.com"}};
//    domainFilterRuleParcel2.Marshalling(reply);
    if (!IptablesService::GetInstance()->HasInit()) {
        IptablesService::GetInstance()->Init();
        reply.WriteInt32(ERR_OK);
    } else {
        std::vector<DomainFilterRuleParcel> list;
        ErrCode ret = IptablesService::GetInstance()->GetDomainFilterRules(list);
        if (ret != ERR_OK) {
            EDMLOGE("DomainFilterRulePlugin OnGetPolicy fail");
            return ret;
        }
        reply.WriteInt32(list.size());
        for(auto const &item : list) {
            item.Marshalling(reply);
        }
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
