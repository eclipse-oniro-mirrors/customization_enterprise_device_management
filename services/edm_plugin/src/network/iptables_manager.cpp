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

ErrCode IptablesManager::AddFirewallRule(const FirewallRuleParcel& firewall, Family family)
{
    auto rule = firewall.GetRule();
    std::string chainName;
    Direction direction = std::get<FIREWALL_DICECTION_IND>(rule);
    if (!firewall.CheckFirewallParams()) {
        return EdmReturnErrCode::PARAM_ERROR;
    }
    Action action = std::get<FIREWALL_ACTION_IND>(rule);
    
    if (!GetFirewallChainName(direction, action, chainName)) {
        return EdmReturnErrCode::PARAM_ERROR;
    }
    auto executer = ExecuterFactory::GetInstance()->GetExecuter(chainName);
    if (executer == nullptr) {
        EDMLOGE("AddFirewallRule:GetExecuter fail, this should not happen.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    NetsysNative::IptablesType ipType = static_cast<NetsysNative::IptablesType>(family);
    if (action == Action::ALLOW) {
        std::vector<std::string> firewallOutputChainNameVector{EDM_DEFAULT_DENY_OUTPUT_CHAIN_NAME};
        if (!g_defaultFirewallOutputChainInit && !ChainExistRule(firewallOutputChainNameVector, ipType)) {
            auto executerOutput = ExecuterFactory::GetInstance()->GetExecuter(EDM_DEFAULT_DENY_OUTPUT_CHAIN_NAME);
            if (executerOutput == nullptr) {
                EDMLOGE("SetDefaultFirewallOutputDenyChain:GetExecuter fail, this should not happen.");
            } else if (executerOutput->SetDefaultOutputDenyChain(direction, family)) {
                g_defaultFirewallOutputChainInit = true;
            }
        }
        std::vector<std::string> firewallForwardChainNameVector{EDM_DEFAULT_DENY_FORWARD_CHAIN_NAME};
        if (!g_defaultFirewallForwardChainInit && !ChainExistRule(firewallForwardChainNameVector, ipType)) {
            auto executerForward = ExecuterFactory::GetInstance()->GetExecuter(EDM_DEFAULT_DENY_FORWARD_CHAIN_NAME);
            if (executerForward == nullptr) {
                EDMLOGE("SetDefaultFirewallForwardDenyChain:GetExecuter fail, this should not happen.");
            } else if (executerForward->SetDefaultForwardDenyChain(direction, family)) {
                g_defaultFirewallForwardChainInit = true;
            }
        }
    }
    auto chainRule = std::make_shared<FirewallChainRule>(rule);
    return executer->Add(chainRule, ipType);
}

ErrCode IptablesManager::RemoveFirewallRule(const FirewallRuleParcel& firewall, Family family)
{
    auto rule = firewall.GetRule();
    Direction direction = std::get<FIREWALL_DICECTION_IND>(rule);
    Action action = std::get<FIREWALL_ACTION_IND>(rule);
    if (!firewall.CheckFirewallParams()) {
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::vector<std::string> chainNameList;
    ErrCode ret = GetRemoveChainName(direction, action, chainNameList);
    if (ret != ERR_OK) {
        EDMLOGE("RemoveFirewallRule: illegal parameter: action, direction");
        return ret;
    }
    NetsysNative::IptablesType ipType = static_cast<NetsysNative::IptablesType>(family);
    if (chainNameList.size() > 1) {
        bool ifParamNotEmpty = !std::get<FIREWALL_SRCADDR_IND>(rule).empty() ||
            !std::get<FIREWALL_DESTADDR_IND>(rule).empty() || !std::get<FIREWALL_SRCPORT_IND>(rule).empty() ||
            !std::get<FIREWALL_DESTPORT_IND>(rule).empty() || !std::get<FIREWALL_APPUID_IND>(rule).empty();
        if (std::get<FIREWALL_PROT_IND>(rule) != IPTABLES::Protocol::INVALID || ifParamNotEmpty) {
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
            executer->Remove(nullptr, ipType);
        }
    } else if (chainNameList.size() == 1) {
        auto executer = ExecuterFactory::GetInstance()->GetExecuter(chainNameList[0]);
        if (executer == nullptr) {
            EDMLOGE("RemoveFirewallRule:GetExecuter fail, this should not happen.");
        } else {
            auto chainRule = std::make_shared<FirewallChainRule>(rule);
            executer->Remove(chainRule, ipType);
        }
    }
    if (!ExistOutputAllowFirewallRule(ipType)) {
        auto executerOutput = ExecuterFactory::GetInstance()->GetExecuter(EDM_DEFAULT_DENY_OUTPUT_CHAIN_NAME);
        if (executerOutput == nullptr) {
            EDMLOGE("ClearDefaultFirewallOutputDenyChain:GetExecuter fail, this should not happen.");
        } else {
            executerOutput->ClearDefaultDenyChain(ipType);
            g_defaultFirewallOutputChainInit = false;
        }
    }
    if (!ExistForwardAllowFirewallRule(ipType)) {
        auto executerForward = ExecuterFactory::GetInstance()->GetExecuter(EDM_DEFAULT_DENY_FORWARD_CHAIN_NAME);
        if (executerForward == nullptr) {
            EDMLOGE("ClearDefaultFirewallForwardDenyChain:GetExecuter fail, this should not happen.");
        } else {
            executerForward->ClearDefaultDenyChain(ipType);
            g_defaultFirewallForwardChainInit = false;
        }
    }
    return ERR_OK;
}

ErrCode IptablesManager::GetFirewallRules(std::vector<FirewallRuleParcel>& list, Family family)
{
    NetsysNative::IptablesType ipType = static_cast<NetsysNative::IptablesType>(family);
    std::vector<std::string> inputRuleList;
    std::vector<std::string> inputChainVector{EDM_ALLOW_INPUT_CHAIN_NAME,
        EDM_DENY_INPUT_CHAIN_NAME, EDM_REJECT_INPUT_CHAIN_NAME};
    for (const auto& chainName : inputChainVector) {
        auto executer = ExecuterFactory::GetInstance()->GetExecuter(chainName);
        if (executer == nullptr) {
            EDMLOGE("GetFirewallRules:GetExecuter fail, this should not happen.");
            continue;
        }
        executer->GetAll(inputRuleList, ipType);
    }
    ConvertFirewallRuleList(list, inputRuleList, Direction::INPUT, family);

    std::vector<std::string> outputRuleList;
    std::vector<std::string> outputChainVector{EDM_ALLOW_OUTPUT_CHAIN_NAME,
        EDM_DENY_OUTPUT_CHAIN_NAME, EDM_REJECT_OUTPUT_CHAIN_NAME};
    for (const auto& chainName : outputChainVector) {
        auto executer = ExecuterFactory::GetInstance()->GetExecuter(chainName);
        if (executer == nullptr) {
            EDMLOGE("GetFirewallRules:GetExecuter fail, this should not happen.");
            continue;
        }
        executer->GetAll(outputRuleList, ipType);
    }
    ConvertFirewallRuleList(list, outputRuleList, Direction::OUTPUT, family);

    std::vector<std::string> forwardRuleList;
    std::vector<std::string> forwardChainVector{EDM_ALLOW_FORWARD_CHAIN_NAME,
        EDM_DENY_FORWARD_CHAIN_NAME, EDM_REJECT_FORWARD_CHAIN_NAME};
    for (const auto& chainName : forwardChainVector) {
        auto executer = ExecuterFactory::GetInstance()->GetExecuter(chainName);
        if (executer == nullptr) {
            EDMLOGE("GetFirewallRules:GetExecuter fail, this should not happen.");
            continue;
        }
        executer->GetAll(forwardRuleList, ipType);
    }
    ConvertFirewallRuleList(list, forwardRuleList, Direction::FORWARD, family);
    return ERR_OK;
}

ErrCode IptablesManager::AddDomainFilterRule(const DomainFilterRuleParcel& domainFilter, Family family)
{
    auto rule = domainFilter.GetRule();
    Action action = std::get<DOMAIN_ACTION_IND>(rule);
    std::string domainName = std::get<DOMAIN_DOMAINNAME_IND>(rule);
    std::string chainName;
    Direction direction = std::get<DOMAIN_DIRECTION_IND>(rule);
    if (!domainFilter.CheckAddDomainParams()) {
        return EdmReturnErrCode::PARAM_ERROR;
    }
    if (!GetDomainChainName(direction, action, chainName)) {
        return EdmReturnErrCode::PARAM_ERROR;
    }

    auto executer = ExecuterFactory::GetInstance()->GetExecuter(chainName);
    if (executer == nullptr) {
        EDMLOGE("AddDomainFilterRule:GetExecuter fail, this should not happen.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    NetsysNative::IptablesType ipType = static_cast<NetsysNative::IptablesType>(family);
    if (action == Action::ALLOW) {
        EDMLOGD("AddDomainFilterRule:GetExecuter before SetDefaultDomainDenyChain.");
        std::vector<std::string> domainOutputChainNameVector{EDM_DEFAULT_DNS_DENY_OUTPUT_CHAIN_NAME};
        if (!g_defaultDomainOutputChainInit && !ChainExistRule(domainOutputChainNameVector, ipType)) {
            auto executerOutput = ExecuterFactory::GetInstance()->GetExecuter(EDM_DEFAULT_DNS_DENY_OUTPUT_CHAIN_NAME);
            if (executerOutput == nullptr) {
                EDMLOGE("SetDefaultDomainOutputDenyChain:GetExecuter fail, this should not happen.");
            } else if (executerOutput->SetDefaultOutputDenyChain(direction, family)) {
                g_defaultDomainOutputChainInit = true;
            }
        }
        std::vector<std::string> domainForwardChainNameVector{EDM_DEFAULT_DNS_DENY_FORWARD_CHAIN_NAME};
        if (!g_defaultDomainForwardChainInit && !ChainExistRule(domainForwardChainNameVector, ipType)) {
            auto executerForward = ExecuterFactory::GetInstance()->GetExecuter(EDM_DEFAULT_DNS_DENY_FORWARD_CHAIN_NAME);
            if (executerForward == nullptr) {
                EDMLOGE("SetDefaultDomainForwardDenyChain:GetExecuter fail, this should not happen.");
            } else if (executerForward->SetDefaultForwardDenyChain(direction, family)) {
                g_defaultDomainForwardChainInit = true;
            }
        }
    }
    auto chainRule = std::make_shared<DomainChainRule>(rule);
    return executer->Add(chainRule, ipType);
}

ErrCode IptablesManager::RemoveDomainFilterRules(const DomainFilterRuleParcel& domainFilter, Family family)
{
    auto rule = domainFilter.GetRule();
    Action action = std::get<DOMAIN_ACTION_IND>(rule);
    std::string appUid = std::get<DOMAIN_APPUID_IND>(rule);
    std::string domainName = std::get<DOMAIN_DOMAINNAME_IND>(rule);
    Direction direction = std::get<DOMAIN_DIRECTION_IND>(rule);
    if (!domainFilter.CheckRemoveDomainParams()) {
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::vector<std::string> chainNameList;
    ErrCode ret = GetDomainRemoveChainName(direction, action, chainNameList);
    if (ret != ERR_OK) {
        EDMLOGE("RemoveDomainRule: illegal parameter: action, direction");
        return ret;
    }
    NetsysNative::IptablesType ipType = static_cast<NetsysNative::IptablesType>(family);
    if (chainNameList.size() > 1) {
        for (const auto& chainName : chainNameList) {
            auto executer = ExecuterFactory::GetInstance()->GetExecuter(chainName);
            if (executer == nullptr) {
                EDMLOGE("RemoveDomainFilterRules:GetExecuter fail, this should not happen.");
                return EdmReturnErrCode::SYSTEM_ABNORMALLY;
            }
            // flush chain
            executer->Remove(nullptr, ipType);
        }
    } else if (chainNameList.size() == 1) {
        auto executer = ExecuterFactory::GetInstance()->GetExecuter(chainNameList[0]);
        if (executer == nullptr) {
            EDMLOGE("RemoveDomainFilterRules:GetExecuter fail, this should not happen.");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        auto chainRule = std::make_shared<DomainChainRule>(rule);
        executer->Remove(chainRule, ipType);
    } else {
        // this branch should never happen
    }
    
    if (!ExistOutputAllowDomainRule(ipType)) {
        auto executerOutput = ExecuterFactory::GetInstance()->GetExecuter(EDM_DEFAULT_DNS_DENY_OUTPUT_CHAIN_NAME);
        if (executerOutput == nullptr) {
            EDMLOGE("ClearDefaultDomainOutputDenyChain:GetExecuter fail, this should not happen.");
        } else {
            executerOutput->ClearDefaultDenyChain(ipType);
            g_defaultDomainOutputChainInit = false;
        }
    }
    if (!ExistForwardAllowDomainRule(ipType)) {
        auto executerForward = ExecuterFactory::GetInstance()->GetExecuter(EDM_DEFAULT_DNS_DENY_FORWARD_CHAIN_NAME);
        if (executerForward == nullptr) {
            EDMLOGE("ClearDefaultDomainForwardDenyChain:GetExecuter fail, this should not happen.");
        } else {
            executerForward->ClearDefaultDenyChain(ipType);
            g_defaultDomainForwardChainInit = false;
        }
    }
    return ERR_OK;
}

ErrCode IptablesManager::GetDomainFilterRules(std::vector<DomainFilterRuleParcel>& list, Family family)
{
    NetsysNative::IptablesType ipType = static_cast<NetsysNative::IptablesType>(family);
    std::vector<std::string> outputRuleList;
    std::vector<std::string> outputChainVector{EDM_DNS_ALLOW_OUTPUT_CHAIN_NAME,
        EDM_DNS_DENY_OUTPUT_CHAIN_NAME, EDM_DNS_REJECT_OUTPUT_CHAIN_NAME};
    for (const auto& chainName : outputChainVector) {
        auto executer = ExecuterFactory::GetInstance()->GetExecuter(chainName);
        if (executer == nullptr) {
            EDMLOGE("ChainExistRule executer null");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        executer->GetAll(outputRuleList, ipType);
    }
    ConvertDomainFilterRuleList(list, outputRuleList, Direction::OUTPUT, family);

    std::vector<std::string> forwardRuleList;
    std::vector<std::string> forwardChainVector{EDM_DNS_ALLOW_FORWARD_CHAIN_NAME,
        EDM_DNS_DENY_FORWARD_CHAIN_NAME, EDM_DNS_REJECT_FORWARD_CHAIN_NAME};
    for (const auto& chainName : forwardChainVector) {
        auto executer = ExecuterFactory::GetInstance()->GetExecuter(chainName);
        if (executer == nullptr) {
            EDMLOGE("GetFirewallRules:GetExecuter fail, this should not happen.");
            continue;
        }
        executer->GetAll(forwardRuleList, ipType);
    }
    ConvertDomainFilterRuleList(list, forwardRuleList, Direction::FORWARD, family);
    return ERR_OK;
}

ErrCode IptablesManager::GetRemoveChainName(
    Direction direction, Action action, std::vector<std::string>& chainNameList)
{
    if (direction == Direction::INPUT) {
        GetRemoveInputChainName(action, chainNameList);
    } else if (direction == Direction::OUTPUT) {
        GetRemoveOutputChainName(action, chainNameList);
    } else if (direction == Direction::FORWARD) {
        GetRemoveForwardChainName(action, chainNameList);
    } else {
        if (action == Action::INVALID) {
            chainNameList.emplace_back(EDM_ALLOW_INPUT_CHAIN_NAME);
            chainNameList.emplace_back(EDM_ALLOW_OUTPUT_CHAIN_NAME);
            chainNameList.emplace_back(EDM_ALLOW_FORWARD_CHAIN_NAME);
            chainNameList.emplace_back(EDM_DENY_INPUT_CHAIN_NAME);
            chainNameList.emplace_back(EDM_DENY_OUTPUT_CHAIN_NAME);
            chainNameList.emplace_back(EDM_DENY_FORWARD_CHAIN_NAME);
            chainNameList.emplace_back(EDM_REJECT_INPUT_CHAIN_NAME);
            chainNameList.emplace_back(EDM_REJECT_OUTPUT_CHAIN_NAME);
            chainNameList.emplace_back(EDM_REJECT_FORWARD_CHAIN_NAME);
        } else {
            EDMLOGE("GetRemoveChainName: illegal parameter: direction, action");
            return EdmReturnErrCode::PARAM_ERROR;
        }
    }
    return ERR_OK;
}

void IptablesManager::GetRemoveInputChainName(Action action, std::vector<std::string>& chainNameList)
{
    if (action == Action::ALLOW) {
        chainNameList.emplace_back(EDM_ALLOW_INPUT_CHAIN_NAME);
    } else if (action == Action::DENY) {
        chainNameList.emplace_back(EDM_DENY_INPUT_CHAIN_NAME);
    } else if (action == Action::REJECT) {
        chainNameList.emplace_back(EDM_REJECT_INPUT_CHAIN_NAME);
    } else {
        chainNameList.emplace_back(EDM_ALLOW_INPUT_CHAIN_NAME);
        chainNameList.emplace_back(EDM_DENY_INPUT_CHAIN_NAME);
        chainNameList.emplace_back(EDM_REJECT_INPUT_CHAIN_NAME);
    }
}

void IptablesManager::GetRemoveOutputChainName(Action action, std::vector<std::string>& chainNameList)
{
    if (action == Action::ALLOW) {
        chainNameList.emplace_back(EDM_ALLOW_OUTPUT_CHAIN_NAME);
    } else if (action == Action::DENY) {
        chainNameList.emplace_back(EDM_DENY_OUTPUT_CHAIN_NAME);
    } else if (action == Action::REJECT) {
        chainNameList.emplace_back(EDM_REJECT_OUTPUT_CHAIN_NAME);
    } else {
        chainNameList.emplace_back(EDM_ALLOW_OUTPUT_CHAIN_NAME);
        chainNameList.emplace_back(EDM_DENY_OUTPUT_CHAIN_NAME);
        chainNameList.emplace_back(EDM_REJECT_OUTPUT_CHAIN_NAME);
    }
}

void IptablesManager::GetRemoveForwardChainName(Action action, std::vector<std::string>& chainNameList)
{
    if (action == Action::ALLOW) {
        chainNameList.emplace_back(EDM_ALLOW_FORWARD_CHAIN_NAME);
    } else if (action == Action::DENY) {
        chainNameList.emplace_back(EDM_DENY_FORWARD_CHAIN_NAME);
    } else if (action == Action::REJECT) {
        chainNameList.emplace_back(EDM_REJECT_FORWARD_CHAIN_NAME);
    } else {
        chainNameList.emplace_back(EDM_ALLOW_FORWARD_CHAIN_NAME);
        chainNameList.emplace_back(EDM_DENY_FORWARD_CHAIN_NAME);
        chainNameList.emplace_back(EDM_REJECT_FORWARD_CHAIN_NAME);
    }
}

ErrCode IptablesManager::GetDomainRemoveChainName(Direction direction, Action action,
    std::vector<std::string>& chainNameList)
{
    if (direction == Direction::OUTPUT) {
        GetDomainRemoveOutputChainName(action, chainNameList);
    } else if (direction == Direction::FORWARD) {
        GetDomainRemoveForwardChainName(action, chainNameList);
    } else {
        if (action == Action::INVALID) {
            chainNameList.emplace_back(EDM_DNS_ALLOW_FORWARD_CHAIN_NAME);
            chainNameList.emplace_back(EDM_DNS_ALLOW_OUTPUT_CHAIN_NAME);
            chainNameList.emplace_back(EDM_DNS_DENY_FORWARD_CHAIN_NAME);
            chainNameList.emplace_back(EDM_DNS_DENY_OUTPUT_CHAIN_NAME);
            chainNameList.emplace_back(EDM_DNS_REJECT_FORWARD_CHAIN_NAME);
            chainNameList.emplace_back(EDM_DNS_REJECT_OUTPUT_CHAIN_NAME);
        } else {
            GetDomainRemoveOutputChainName(action, chainNameList);
        }
    }
    return ERR_OK;
}

void IptablesManager::GetDomainRemoveOutputChainName(Action action,
    std::vector<std::string>& chainNameList)
{
    if (action == Action::ALLOW) {
        chainNameList.emplace_back(EDM_DNS_ALLOW_OUTPUT_CHAIN_NAME);
    } else if (action == Action::DENY) {
        chainNameList.emplace_back(EDM_DNS_DENY_OUTPUT_CHAIN_NAME);
    } else if (action == Action::REJECT) {
        chainNameList.emplace_back(EDM_DNS_REJECT_OUTPUT_CHAIN_NAME);
    } else {
        chainNameList.emplace_back(EDM_DNS_ALLOW_OUTPUT_CHAIN_NAME);
        chainNameList.emplace_back(EDM_DNS_DENY_OUTPUT_CHAIN_NAME);
        chainNameList.emplace_back(EDM_DNS_REJECT_OUTPUT_CHAIN_NAME);
    }
}

void IptablesManager::GetDomainRemoveForwardChainName(Action action,
    std::vector<std::string>& chainNameList)
{
    if (action == Action::ALLOW) {
        chainNameList.emplace_back(EDM_DNS_ALLOW_FORWARD_CHAIN_NAME);
    } else if (action == Action::DENY) {
        chainNameList.emplace_back(EDM_DNS_DENY_FORWARD_CHAIN_NAME);
    } else if (action == Action::REJECT) {
        chainNameList.emplace_back(EDM_DNS_REJECT_FORWARD_CHAIN_NAME);
    } else {
        chainNameList.emplace_back(EDM_DNS_ALLOW_FORWARD_CHAIN_NAME);
        chainNameList.emplace_back(EDM_DNS_DENY_FORWARD_CHAIN_NAME);
        chainNameList.emplace_back(EDM_DNS_REJECT_FORWARD_CHAIN_NAME);
    }
}

bool IptablesManager::HasInit(NetsysNative::IptablesType ipType)
{
    if (!g_chainInit) {
        auto executer = ExecuterFactory::GetInstance()->GetExecuter(EDM_REJECT_INPUT_CHAIN_NAME);
        if (executer != nullptr && executer->ChainInit(ipType)) {
            g_chainInit = true;
        }
    }
    return g_chainInit;
}

void IptablesManager::Init(NetsysNative::IptablesType ipType)
{
    if (!g_chainInit) {
        EDMLOGD("IptablesManager:start init.");
        std::vector<std::shared_ptr<IExecuter>> allExecuter = ExecuterFactory::GetInstance()->GetAllExecuter();
        for (const auto &executer : allExecuter) {
            ErrCode ret = executer->CreateChain(ipType);
            if (ret != ERR_OK) {
                EDMLOGE("Init CreateChain fail, this should not happen.");
                return;
            }
        }
        for (const auto &executer : allExecuter) {
            ErrCode ret = executer->Init(ipType);
            if (ret != ERR_OK) {
                EDMLOGE("Init fail, this should not happen.");
                return;
            }
        }
        g_chainInit = true;
    }
}

bool IptablesManager::ExistOutputAllowFirewallRule(NetsysNative::IptablesType ipType)
{
    std::vector<std::string> chainNameVector{EDM_ALLOW_INPUT_CHAIN_NAME, EDM_ALLOW_OUTPUT_CHAIN_NAME};
    return ChainExistRule(chainNameVector, ipType);
}

bool IptablesManager::ExistForwardAllowFirewallRule(NetsysNative::IptablesType ipType)
{
    std::vector<std::string> chainNameVector{EDM_ALLOW_FORWARD_CHAIN_NAME};
    return ChainExistRule(chainNameVector, ipType);
}

bool IptablesManager::ExistOutputAllowDomainRule(NetsysNative::IptablesType ipType)
{
    std::vector<std::string> chainNameVector{EDM_DNS_ALLOW_OUTPUT_CHAIN_NAME};
    return ChainExistRule(chainNameVector, ipType);
}

bool IptablesManager::ExistForwardAllowDomainRule(NetsysNative::IptablesType ipType)
{
    std::vector<std::string> chainNameVector{EDM_DNS_ALLOW_FORWARD_CHAIN_NAME};
    return ChainExistRule(chainNameVector, ipType);
}

bool IptablesManager::GetFirewallChainName(Direction direction, Action action, std::string& chainName)
{
    if (action == Action::ALLOW && direction == Direction::INPUT) {
        chainName = EDM_ALLOW_INPUT_CHAIN_NAME;
    } else if (action == Action::ALLOW && direction == Direction::OUTPUT) {
        chainName = EDM_ALLOW_OUTPUT_CHAIN_NAME;
    } else if (action == Action::ALLOW && direction == Direction::FORWARD) {
        chainName = EDM_ALLOW_FORWARD_CHAIN_NAME;
    } else if (action == Action::DENY && direction == Direction::INPUT) {
        chainName = EDM_DENY_INPUT_CHAIN_NAME;
    } else if (action == Action::DENY && direction == Direction::OUTPUT) {
        chainName = EDM_DENY_OUTPUT_CHAIN_NAME;
    } else if (action == Action::DENY && direction == Direction::FORWARD) {
        chainName = EDM_DENY_FORWARD_CHAIN_NAME;
    } else if (action == Action::REJECT && direction == Direction::INPUT) {
        chainName = EDM_REJECT_INPUT_CHAIN_NAME;
    } else if (action == Action::REJECT && direction == Direction::OUTPUT) {
        chainName = EDM_REJECT_OUTPUT_CHAIN_NAME;
    } else if (action == Action::REJECT && direction == Direction::FORWARD) {
        chainName = EDM_REJECT_FORWARD_CHAIN_NAME;
    } else {
        EDMLOGE("AddFirewallRule: illegal parameter: action, direction");
        return false;
    }
    return true;
}

bool IptablesManager::GetDomainChainName(Direction direction, Action action, std::string& chainName)
{
    if (action == Action::ALLOW) {
        chainName = EDM_DNS_ALLOW_OUTPUT_CHAIN_NAME;
        if (direction == Direction::FORWARD) {
            chainName = EDM_DNS_ALLOW_FORWARD_CHAIN_NAME;
        }
    } else if (action == Action::DENY) {
        chainName = EDM_DNS_DENY_OUTPUT_CHAIN_NAME;
        if (direction == Direction::FORWARD) {
            chainName = EDM_DNS_DENY_FORWARD_CHAIN_NAME;
        }
    } else if (action == Action::REJECT) {
        chainName = EDM_DNS_REJECT_OUTPUT_CHAIN_NAME;
        if (direction == Direction::FORWARD) {
            chainName = EDM_DNS_REJECT_FORWARD_CHAIN_NAME;
        }
    } else {
        EDMLOGE("AddDomainFilterRule: illegal parameter: action");
        return false;
    }
    return true;
}

bool IptablesManager::ChainExistRule(const std::vector<std::string>& chainNames, NetsysNative::IptablesType ipType)
{
    std::vector<std::string> ruleList;
    for (const auto& chainName : chainNames) {
        auto executer = ExecuterFactory::GetInstance()->GetExecuter(chainName);
        if (executer == nullptr) {
            EDMLOGE("ChainExistRule executer null");
            return false;
        }
        executer->GetAll(ruleList, ipType);
        if (!ruleList.empty()) {
            EDMLOGI("ChainExistRule: ruleList size is %{public}zu", ruleList.size());
            return true;
        }
    }
    return false;
}

void IptablesManager::ConvertFirewallRuleList(std::vector<FirewallRuleParcel>& list,
    std::vector<std::string> ruleList, Direction direction, Family family)
{
    for (const auto& rule : ruleList) {
        FirewallChainRule firewallRule{rule};
        FirewallRuleParcel firewall{firewallRule.ToFilterRule(direction, family)};
        list.emplace_back(firewall);
    }
}

void IptablesManager::ConvertDomainFilterRuleList(std::vector<DomainFilterRuleParcel>& list,
    std::vector<std::string> ruleList, Direction direction, Family family)
{
    for (const auto& rule : ruleList) {
        DomainChainRule domainFilter{rule};
        DomainFilterRuleParcel domain{domainFilter.ToFilterRule(direction, family)};
        list.emplace_back(domain);
    }
}
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS