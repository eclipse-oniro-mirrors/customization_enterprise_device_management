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

#include "iptables_manager.h"

#include <iostream>
#include <unordered_map>

#include "domain_chain_rule.h"
#include "edm_log.h"
#include "executer_factory.h"
#include "firewall_chain_rule.h"
#include "iexecuter.h"
#include "rule_utils.h"

namespace OHOS {
namespace EDM {
namespace IPTABLES {

const int32_t MAX_DOMAIN_LENGTH = 255;

bool IptablesManager::g_chainInit = false;
bool IptablesManager::g_defaultFirewallChainInit = false;
bool IptablesManager::g_defaultDomainChainInit = false;
std::shared_ptr<IptablesManager> IptablesManager::instance_ = nullptr;
std::mutex IptablesManager::mutexLock_;

std::shared_ptr<IptablesManager> IptablesManager::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutexLock_);
        if (instance_ == nullptr) {
            std::shared_ptr<IptablesManager> temp = std::make_shared<IptablesManager>();
            instance_ = temp;
        }
    }
    return instance_;
}

ErrCode IptablesManager::AddFirewallRule(const FirewallRuleParcel& firewall)
{
    auto rule = firewall.GetRule();
    std::string chainName;
    Direction direction = std::get<FIREWALL_DICECTION_IND>(rule);
    if (direction == Direction::INPUT && !std::get<FIREWALL_APPUID_IND>(rule).empty()) {
        EDMLOGE("AddFirewallRule: illegal parameter: appUid");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    if (std::get<FIREWALL_PROT_IND>(rule) == Protocol::ALL &&
        !std::get<FIREWALL_SRCPORT_IND>(rule).empty() && !std::get<FIREWALL_DESTPORT_IND>(rule).empty()) {
        EDMLOGE("AddFirewallRule: illegal parameter: protocol");
        return EdmReturnErrCode::PARAM_ERROR;
    }

    Action action = std::get<FIREWALL_ACTION_IND>(rule);
    if (action == Action::ALLOW && direction == Direction::INPUT) {
        chainName = EDM_ALLOW_INPUT_CHAIN_NAME;
    } else if (action == Action::ALLOW && direction == Direction::OUTPUT) {
        chainName = EDM_ALLOW_OUTPUT_CHAIN_NAME;
    } else if (action == Action::DENY && direction == Direction::INPUT) {
        chainName = EDM_DENY_INPUT_CHAIN_NAME;
    } else if (action == Action::DENY && direction == Direction::OUTPUT) {
        chainName = EDM_DENY_OUTPUT_CHAIN_NAME;
    } else {
        EDMLOGE("AddFirewallRule: illegal parameter: action, direction");
        return EdmReturnErrCode::PARAM_ERROR;
    }

    auto executer = ExecuterFactory::GetInstance()->GetExecuter(chainName);
    if (executer == nullptr) {
        EDMLOGE("AddFirewallRule:GetExecuter fail, this should not happen.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (action == Action::ALLOW) {
        SetDefaultFirewallDenyChain();
    }
    auto chainRule = std::make_shared<FirewallChainRule>(rule);
    return executer->Add(chainRule);
}

ErrCode IptablesManager::RemoveFirewallRule(const FirewallRuleParcel& firewall)
{
    auto rule = firewall.GetRule();
    Direction direction = std::get<FIREWALL_DICECTION_IND>(rule);
    Action action = std::get<FIREWALL_ACTION_IND>(rule);
    if (direction == Direction::INPUT && !std::get<FIREWALL_APPUID_IND>(rule).empty()) {
        EDMLOGE("RemoveFirewallRule: illegal parameter: appUid");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    if (std::get<FIREWALL_PROT_IND>(rule) == Protocol::ALL &&
        (!std::get<FIREWALL_SRCPORT_IND>(rule).empty() || !std::get<FIREWALL_DESTPORT_IND>(rule).empty())) {
        EDMLOGE("RemoveFirewallRule: illegal parameter: protocol");
        return EdmReturnErrCode::PARAM_ERROR;
    }

    std::vector<std::string> chainNameList;
    ErrCode ret = GetRemoveChainName(direction, action, chainNameList);
    if (ret != ERR_OK) {
        EDMLOGE("RemoveFirewallRule: illegal parameter: action, direction");
        return ret;
    }

    if (chainNameList.size() > 1) {
        if (std::get<FIREWALL_PROT_IND>(rule) != IPTABLES::Protocol::INVALID ||
            !std::get<FIREWALL_SRCADDR_IND>(rule).empty() || !std::get<FIREWALL_DESTADDR_IND>(rule).empty() ||
            !std::get<FIREWALL_SRCPORT_IND>(rule).empty() || !std::get<FIREWALL_DESTPORT_IND>(rule).empty() ||
            !std::get<FIREWALL_APPUID_IND>(rule).empty()) {
            EDMLOGE("RemoveFirewallRule: illegal parameter: Too many parameters set");
            return EdmReturnErrCode::PARAM_ERROR;
        }
        // flash chain
        for (const auto& chainName : chainNameList) {
            auto executer = ExecuterFactory::GetInstance()->GetExecuter(chainName);
            if (executer == nullptr) {
                EDMLOGE("RemoveFirewallRule:GetExecuter fail, this should not happen.");
                continue;
            }
            executer->Remove(nullptr);
        }
    } else if (chainNameList.size() == 1) {
        auto executer = ExecuterFactory::GetInstance()->GetExecuter(chainNameList[0]);
        if (executer == nullptr) {
            EDMLOGE("RemoveFirewallRule:GetExecuter fail, this should not happen.");
        } else {
            auto chainRule = std::make_shared<FirewallChainRule>(rule);
            executer->Remove(chainRule);
        }
    }
    if (!ExistAllowFirewallRule()) {
        ClearDefaultFirewallDenyChain();
    }
    return ERR_OK;
}

ErrCode IptablesManager::GetFirewallRules(std::vector<FirewallRuleParcel>& list)
{
    std::vector<std::string> inputRuleList;
    std::vector<std::string> inputChainVector{EDM_ALLOW_INPUT_CHAIN_NAME, EDM_DENY_INPUT_CHAIN_NAME};
    for (const auto& chainName : inputChainVector) {
        auto executer = ExecuterFactory::GetInstance()->GetExecuter(chainName);
        if (executer == nullptr) {
            EDMLOGE("GetFirewallRules:GetExecuter fail, this should not happen.");
            continue;
        }
        executer->GetAll(inputRuleList);
    }

    for (const auto& rule : inputRuleList) {
        FirewallChainRule firewallRule{rule};
        FirewallRuleParcel firewall{firewallRule.ToFilterRule(Direction::INPUT)};
        list.emplace_back(firewall);
    }

    std::vector<std::string> outputRuleList;
    std::vector<std::string> outputChainVector{EDM_ALLOW_OUTPUT_CHAIN_NAME, EDM_DENY_OUTPUT_CHAIN_NAME};
    for (const auto& chainName : outputChainVector) {
        auto executer = ExecuterFactory::GetInstance()->GetExecuter(chainName);
        if (executer == nullptr) {
            EDMLOGE("GetFirewallRules:GetExecuter fail, this should not happen.");
            continue;
        }
        executer->GetAll(outputRuleList);
    }
    for (const auto& rule : outputRuleList) {
        FirewallChainRule firewallRule{rule};
        FirewallRuleParcel firewall{firewallRule.ToFilterRule(Direction::OUTPUT)};
        list.emplace_back(firewall);
    }
    return ERR_OK;
}

ErrCode IptablesManager::AddDomainFilterRule(const DomainFilterRuleParcel& DomainFilter)
{
    auto rule = DomainFilter.GetRule();
    Action action = std::get<DOMAIN_ACTION_IND>(rule);
    std::string domainName = std::get<DOMAIN_DOMAINNAME_IND>(rule);
    std::string chainName;
    if (action == Action::ALLOW) {
        chainName = EDM_DNS_ALLOW_OUTPUT_CHAIN_NAME;
    } else if (action == Action::DENY) {
        chainName = EDM_DNS_DENY_OUTPUT_CHAIN_NAME;
    } else {
        EDMLOGE("AddDomainFilterRule: illegal parameter: action");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    if (domainName.empty() || domainName.length() > MAX_DOMAIN_LENGTH) {
        EDMLOGE("AddDomainFilterRule: illegal parameter: domainName");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    auto index = domainName.find_first_of("|/");
    if (index != std::string ::npos) {
        EDMLOGE("AddDomainFilterRule: illegal parameter: domainName");
        return EdmReturnErrCode::PARAM_ERROR;
    }

    auto executer = ExecuterFactory::GetInstance()->GetExecuter(chainName);
    if (executer == nullptr) {
        EDMLOGE("AddDomainFilterRule:GetExecuter fail, this should not happen.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (action == Action::ALLOW) {
        EDMLOGD("AddDomainFilterRule:GetExecuter before SetDefaultDomainDenyChain.");
        SetDefaultDomainDenyChain();
    }
    auto chainRule = std::make_shared<DomainChainRule>(rule);
    return executer->Add(chainRule);
}

ErrCode IptablesManager::RemoveDomainFilterRules(const DomainFilterRuleParcel& DomainFilter)
{
    auto rule = DomainFilter.GetRule();
    Action action = std::get<DOMAIN_ACTION_IND>(rule);
    std::string appUid = std::get<DOMAIN_APPUID_IND>(rule);
    std::string domainName = std::get<DOMAIN_DOMAINNAME_IND>(rule);
    if (domainName.empty() && !appUid.empty()) {
        EDMLOGE("RemoveDomainFilterRules: illegal parameter: appUid");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    if (!domainName.empty() && domainName.length() > MAX_DOMAIN_LENGTH) {
        EDMLOGE("RemoveDomainFilterRules: illegal parameter: domainName");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    auto index = domainName.find_first_of("|/");
    if (index != std::string ::npos) {
        EDMLOGE("RemoveDomainFilterRules: illegal parameter: domainName");
        return EdmReturnErrCode::PARAM_ERROR;
    }

    if (action == Action::INVALID && (!appUid.empty() || !domainName.empty())) {
        EDMLOGE("RemoveDomainFilterRules: illegal parameter: Too many parameters set");
        return EdmReturnErrCode::PARAM_ERROR;
    }

    std::vector<std::string> chainNameList;
    if (action == Action::ALLOW) {
        chainNameList.emplace_back(EDM_DNS_ALLOW_OUTPUT_CHAIN_NAME);
    } else if (action == Action::DENY) {
        chainNameList.emplace_back(EDM_DNS_DENY_OUTPUT_CHAIN_NAME);
    } else {
        chainNameList.emplace_back(EDM_DNS_ALLOW_OUTPUT_CHAIN_NAME);
        chainNameList.emplace_back(EDM_DNS_DENY_OUTPUT_CHAIN_NAME);
        for (const auto& chainName : chainNameList) {
            auto executer = ExecuterFactory::GetInstance()->GetExecuter(chainName);
            // flush chain
            executer->Remove(nullptr);
        }
        ClearDefaultDomainDenyChain();
        return ERR_OK;
    }

    auto executer = ExecuterFactory::GetInstance()->GetExecuter(chainNameList[0]);
    if (executer == nullptr) {
        EDMLOGE("RemoveDomainFilterRules:GetExecuter fail, this should not happen.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    auto chainRule = std::make_shared<DomainChainRule>(rule);
    auto ret = executer->Remove(chainRule);
    if (ret == ERR_OK && !ExistAllowDomainRule()) {
        ClearDefaultDomainDenyChain();
    }
    return ret;
}

ErrCode IptablesManager::GetDomainFilterRules(std::vector<DomainFilterRuleParcel>& list)
{
    std::vector<std::string> ruleList;
    std::vector<std::string> chainNameVector{EDM_DNS_ALLOW_OUTPUT_CHAIN_NAME, EDM_DNS_DENY_OUTPUT_CHAIN_NAME};
    for (const auto& chainName : chainNameVector) {
        auto executer = ExecuterFactory::GetInstance()->GetExecuter(chainName);
        executer->GetAll(ruleList);
    }
    for (const auto& rule : ruleList) {
        DomainChainRule chainRule{rule};
        list.emplace_back(chainRule.ToFilterRule());
    }
    return ERR_OK;
}

ErrCode IptablesManager::GetRemoveChainName(Direction direction, Action action, std::vector<std::string>& chainNameList)
{
    if (direction == Direction::INPUT) {
        if (action == Action::ALLOW) {
            chainNameList.emplace_back(EDM_ALLOW_INPUT_CHAIN_NAME);
        } else if (action == Action::DENY) {
            chainNameList.emplace_back(EDM_DENY_INPUT_CHAIN_NAME);
        } else {
            chainNameList.emplace_back(EDM_ALLOW_INPUT_CHAIN_NAME);
            chainNameList.emplace_back(EDM_DENY_INPUT_CHAIN_NAME);
        }
    } else if (direction == Direction::OUTPUT) {
        if (action == Action::ALLOW) {
            chainNameList.emplace_back(EDM_ALLOW_OUTPUT_CHAIN_NAME);
        } else if (action == Action::DENY) {
            chainNameList.emplace_back(EDM_DENY_OUTPUT_CHAIN_NAME);
        } else {
            chainNameList.emplace_back(EDM_ALLOW_OUTPUT_CHAIN_NAME);
            chainNameList.emplace_back(EDM_DENY_OUTPUT_CHAIN_NAME);
        }
    } else {
        if (action == Action::INVALID) {
            chainNameList.emplace_back(EDM_ALLOW_INPUT_CHAIN_NAME);
            chainNameList.emplace_back(EDM_ALLOW_OUTPUT_CHAIN_NAME);
            chainNameList.emplace_back(EDM_DENY_INPUT_CHAIN_NAME);
            chainNameList.emplace_back(EDM_DENY_OUTPUT_CHAIN_NAME);
        } else {
            EDMLOGE("GetRemoveChainName: illegal parameter: direction, action");
            return EdmReturnErrCode::PARAM_ERROR;
        }
    }
    return ERR_OK;
}

bool IptablesManager::HasInit()
{
    return g_chainInit;
}

void IptablesManager::Init()
{
    if (!g_chainInit) {
        EDMLOGD("IptablesManager:start init.");
        std::vector<std::shared_ptr<IExecuter>> allExecuter = ExecuterFactory::GetInstance()->GetAllExecuter();
        for (const auto &executer : allExecuter) {
            ErrCode ret = executer->CreateChain();
            if (ret != ERR_OK) {
                EDMLOGE("Init CreateChain fail, this should not happen.");
                return;
            }
        }
        for (const auto &executer : allExecuter) {
            ErrCode ret = executer->Init();
            if (ret != ERR_OK) {
                EDMLOGE("Init fail, this should not happen.");
                return;
            }
        }
        g_chainInit = true;
    }
}

void IptablesManager::SetDefaultFirewallDenyChain()
{
    if (!g_defaultFirewallChainInit) {
        FirewallRule firewallRule1{Direction::OUTPUT, Action::DENY, Protocol::UDP, "", "", "", "", ""};
        FirewallRule firewallRule2{Direction::OUTPUT, Action::DENY, Protocol::TCP, "", "", "", "", ""};

        std::vector<std::shared_ptr<ChainRule>> chainRuleVector{std::make_shared<FirewallChainRule>(),
            std::make_shared<FirewallChainRule>(firewallRule1), std::make_shared<FirewallChainRule>(firewallRule2)};

        auto executer = ExecuterFactory::GetInstance()->GetExecuter(EDM_DEFAULT_DENY_OUTPUT_CHAIN_NAME);
        for (const auto& chainRule : chainRuleVector) {
            if (executer == nullptr) {
                EDMLOGE("SetDefaultFirewallDenyChain:GetExecuter fail, this should not happen.");
            } else {
                executer->Add(chainRule);
                g_defaultFirewallChainInit = true;
            }
        }
    }
}

void IptablesManager::ClearDefaultFirewallDenyChain()
{
    if (g_defaultFirewallChainInit) {
        auto executer = ExecuterFactory::GetInstance()->GetExecuter(EDM_DEFAULT_DENY_OUTPUT_CHAIN_NAME);
        if (executer == nullptr) {
            EDMLOGE("ClearDefaultFirewallDenyChain:GetExecuter fail, this should not happen.");
        } else {
            executer->Remove(nullptr);
            g_defaultFirewallChainInit = false;
        }
    }
}

void IptablesManager::SetDefaultDomainDenyChain()
{
    if (!g_defaultDomainChainInit) {
        DomainFilterRule domainFilterRule{Action::DENY, "", ""};
        std::shared_ptr<ChainRule> chainRule = std::make_shared<DomainChainRule>(domainFilterRule);
        auto executer = ExecuterFactory::GetInstance()->GetExecuter(EDM_DEFAULT_DNS_DENY_OUTPUT_CHAIN_NAME);
        if (executer == nullptr) {
            EDMLOGE("SetDefaultDomainDenyChain:GetExecuter fail, this should not happen.");
        } else {
            executer->Add(chainRule);
            g_defaultDomainChainInit = true;
        }
    }
}

void IptablesManager::ClearDefaultDomainDenyChain()
{
    if (g_defaultDomainChainInit) {
        auto executer = ExecuterFactory::GetInstance()->GetExecuter(EDM_DEFAULT_DNS_DENY_OUTPUT_CHAIN_NAME);
        if (executer == nullptr) {
            EDMLOGE("ClearDefaultDomainDenyChain:GetExecuter fail, this should not happen.");
        } else {
            executer->Remove(nullptr);
            g_defaultDomainChainInit = false;
        }
    }
}

bool IptablesManager::ExistAllowFirewallRule()
{
    std::vector<std::string> chainNameVector{EDM_ALLOW_INPUT_CHAIN_NAME, EDM_ALLOW_OUTPUT_CHAIN_NAME};
    return ChainExistRule(chainNameVector);
}

bool IptablesManager::ExistAllowDomainRule()
{
    std::vector<std::string> chainNameVector{EDM_DNS_ALLOW_OUTPUT_CHAIN_NAME};
    return ChainExistRule(chainNameVector);
}

bool IptablesManager::ChainExistRule(const std::vector<std::string>& chainNames)
{
    std::vector<std::string> ruleList;
    for (const auto& chainName : chainNames) {
        auto executer = ExecuterFactory::GetInstance()->GetExecuter(chainName);
        executer->GetAll(ruleList);
        if (!ruleList.empty()) {
            return true;
        }
    }
    return false;
}

} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS