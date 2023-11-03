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

#include "iptables_service.h"

#include <iostream>
#include <unordered_map>

#include "dao_factory.h"
#include "domain_chain_rule.h"
#include "edm_log.h"
#include "firewall_chain_rule.h"
#include "idao.h"
#include "rule_utils.h"

namespace OHOS {
namespace EDM {
namespace IPTABLES {

const int32_t MAX_DOMAIN_LENGTH = 255;

bool IptablesService::g_chainInit = false;
bool IptablesService::g_defaultFirewallChainInit = false;
bool IptablesService::g_defaultDomainChainInit = false;
std::shared_ptr<IptablesService> IptablesService::instance_ = nullptr;
std::mutex IptablesService::mutexLock_;

std::shared_ptr<IptablesService> IptablesService::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutexLock_);
        if (instance_ == nullptr) {
            std::shared_ptr<IptablesService> temp = std::make_shared<IptablesService>();
            instance_ = temp;
        }
    }
    return instance_;
}

ErrCode IptablesService::AddFirewallRule(const FirewallRuleParcel& firewall)
{
    auto rule = firewall.GetRule();
    std::string chainName;
    Direction direction = std::get<0>(rule);
    if (direction == Direction::INPUT && !std::get<7>(rule).empty()) {
        EDMLOGE("AddFirewallRule: illegal parameter: appUid");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    if (std::get<2>(rule) == Protocol::ALL && !std::get<5>(rule).empty() && !std::get<6>(rule).empty()) {
        EDMLOGE("AddFirewallRule: illegal parameter: protocol");
        return EdmReturnErrCode::PARAM_ERROR;
    }

    Action action = std::get<1>(rule);
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

    auto dao = DaoFactory::GetInstance()->GetDao(chainName);
    if (dao == nullptr) {
        EDMLOGE("AddFirewallRule:GetDao fail, this should not happen.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (action == Action::DENY) {
        SetDefaultFirewallDenyChain();
    }
    auto chainRule = std::make_shared<FirewallChainRule>(rule);
    return dao->Add(chainRule);
}

ErrCode IptablesService::RemoveFirewallRule(const FirewallRuleParcel& firewall)
{
    auto rule = firewall.GetRule();
    Direction direction = std::get<0>(rule);
    Action action = std::get<1>(rule);
    if (direction == Direction::INPUT && !std::get<7>(rule).empty()) {
        EDMLOGE("RemoveFirewallRule: illegal parameter: appUid");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    if (std::get<2>(rule) == Protocol::ALL && (!std::get<5>(rule).empty() || !std::get<6>(rule).empty())) {
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
        if (std::get<2>(rule) != IPTABLES::Protocol::INVALID || !std::get<3>(rule).empty() ||
            !std::get<4>(rule).empty() || !std::get<5>(rule).empty() || !std::get<6>(rule).empty() ||
            !std::get<7>(rule).empty()) {
            EDMLOGE("RemoveFirewallRule: illegal parameter: Too many parameters set");
            return EdmReturnErrCode::PARAM_ERROR;
        }
        // flash chain
        for (const auto& chainName : chainNameList) {
            auto dao = DaoFactory::GetInstance()->GetDao(chainName);
            if (dao == nullptr) {
                EDMLOGE("GetFirewallRules:GetDao fail, this should not happen.");
                continue;
            }
            dao->Remove(nullptr);
        }
    } else if (chainNameList.size() == 1) {
        auto dao = DaoFactory::GetInstance()->GetDao(chainNameList[0]);
        if (dao == nullptr) {
            EDMLOGE("RemoveFirewallRule:GetDao fail, this should not happen.");
        } else {
            auto chainRule = std::make_shared<FirewallChainRule>(rule);
            dao->Remove(chainRule);
        }
    }
    if (!ExistDenyFirewallRule()) {
        ClearDefaultFirewallDenyChain();
    }
    return ERR_OK;
}

ErrCode IptablesService::GetFirewallRules(std::vector<FirewallRuleParcel>& list)
{
    std::vector<std::string> inputRuleList;
    std::vector<std::string> inputChainVector{EDM_ALLOW_INPUT_CHAIN_NAME, EDM_DENY_INPUT_CHAIN_NAME};
    for (const auto& chainName : inputChainVector) {
        auto dao = DaoFactory::GetInstance()->GetDao(chainName);
        if (dao == nullptr) {
            EDMLOGE("GetFirewallRules:GetDao fail, this should not happen.");
            continue;
        }
        dao->GetAll(inputRuleList);
    }

    for (const auto& rule : inputRuleList) {
        FirewallChainRule firewallRule{rule};
        FirewallRuleParcel firewall{firewallRule.ToFilterRule(Direction::INPUT)};
        list.emplace_back(firewall);
    }

    std::vector<std::string> outputRuleList;
    std::vector<std::string> outputChainVector{EDM_ALLOW_OUTPUT_CHAIN_NAME, EDM_DENY_OUTPUT_CHAIN_NAME};
    for (const auto& chainName : outputChainVector) {
        auto dao = DaoFactory::GetInstance()->GetDao(chainName);
        if (dao == nullptr) {
            EDMLOGE("GetFirewallRules:GetDao fail, this should not happen.");
            continue;
        }
        dao->GetAll(outputRuleList);
    }
    for (const auto& rule : outputRuleList) {
        FirewallChainRule firewallRule{rule};
        FirewallRuleParcel firewall{firewallRule.ToFilterRule(Direction::OUTPUT)};
        list.emplace_back(firewall);
    }
    return ERR_OK;
}

ErrCode IptablesService::AddDomainFilterRule(const DomainFilterRuleParcel& DomainFilter)
{
    auto rule = DomainFilter.GetRule();
    Action action = std::get<0>(rule);
    std::string domainName = std::get<2>(rule);
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

    auto dao = DaoFactory::GetInstance()->GetDao(chainName);
    if (dao == nullptr) {
        EDMLOGE("AddDomainFilterRule:GetDao fail, this should not happen.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (action == Action::DENY) {
        EDMLOGD("AddDomainFilterRule:GetDao before SetDefaultDomainDenyChain.");
        SetDefaultDomainDenyChain();
    }
    auto chainRule = std::make_shared<DomainChainRule>(rule);
    return dao->Add(chainRule);
}

ErrCode IptablesService::RemoveDomainFilterRules(const DomainFilterRuleParcel& DomainFilter)
{
    auto rule = DomainFilter.GetRule();
    Action action = std::get<0>(rule);
    std::string domainName = std::get<2>(rule);
    if (domainName.empty() && !std::get<1>(rule).empty()) {
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

    if (action == Action::INVALID && (!std::get<1>(rule).empty() || !std::get<2>(rule).empty())) {
        EDMLOGE("RemoveFirewallRule: illegal parameter: Too many parameters set");
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
            auto dao = DaoFactory::GetInstance()->GetDao(chainName);
            // flush chain
            dao->Remove(nullptr);
        }
        ClearDefaultDomainDenyChain();
        return ERR_OK;
    }

    auto dao = DaoFactory::GetInstance()->GetDao(chainNameList[0]);
    if (dao == nullptr) {
        EDMLOGE("RemoveDomainFilterRules:GetDao fail, this should not happen.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    auto chainRule = std::make_shared<DomainChainRule>(rule);
    auto ret = dao->Remove(chainRule);
    if (ret == ERR_OK && !ExistDenyDomainRule()) {
        ClearDefaultDomainDenyChain();
    }
    return ret;
}

ErrCode IptablesService::GetDomainFilterRules(std::vector<DomainFilterRuleParcel>& list)
{
    std::vector<std::string> ruleList;
    std::vector<std::string> chainNameVector{EDM_DNS_ALLOW_OUTPUT_CHAIN_NAME, EDM_DNS_DENY_OUTPUT_CHAIN_NAME};
    for (const auto& chainName : chainNameVector) {
        auto dao = DaoFactory::GetInstance()->GetDao(chainName);
        dao->GetAll(ruleList);
    }
    for (const auto& rule : ruleList) {
        DomainChainRule chainRule{rule};
        list.emplace_back(chainRule.ToFilterRule());
    }
    return ERR_OK;
}

ErrCode IptablesService::GetRemoveChainName(Direction direction, Action action, std::vector<std::string>& chainNameList)
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

bool IptablesService::HasInit()
{
    return g_chainInit;
}

void IptablesService::Init()
{
    if (!g_chainInit) {
        std::vector<std::shared_ptr<IDao>> daoVector = DaoFactory::GetInstance()->GetAllDao();
        for (const auto& dao : daoVector) {
            ErrCode ret = dao->CreateChain();
            if (ret != ERR_OK) {
                EDMLOGE("Init CreateChain fail, this should not happen.");
            }
        }
        for (const auto& dao : daoVector) {
            ErrCode ret = dao->Init();
            if (ret != ERR_OK) {
                EDMLOGE("Init fail, this should not happen.");
            }
        }
        g_chainInit = true;
    }
}

void IptablesService::SetDefaultFirewallDenyChain()
{
    if (!g_defaultFirewallChainInit) {
        FirewallRule firewallRule1{Direction::OUTPUT, Action::DENY, Protocol::UDP, "", "", "", "", ""};
        FirewallRule firewallRule2{Direction::OUTPUT, Action::DENY, Protocol::TCP, "", "", "", "", ""};

        std::vector<std::shared_ptr<ChainRule>> chainRuleVector{std::make_shared<FirewallChainRule>(),
            std::make_shared<FirewallChainRule>(firewallRule1), std::make_shared<FirewallChainRule>(firewallRule2)};

        auto dao = DaoFactory::GetInstance()->GetDao(EDM_DEFAULT_DENY_OUTPUT_CHAIN_NAME);
        for (const auto& chainRule : chainRuleVector) {
            if (dao == nullptr) {
                EDMLOGE("SetDefaultFirewallDenyChain:GetDao fail, this should not happen.");
            } else {
                dao->Add(chainRule);
                g_defaultFirewallChainInit = true;
            }
        }
    }
}

void IptablesService::ClearDefaultFirewallDenyChain()
{
    if (g_defaultFirewallChainInit) {
        auto dao = DaoFactory::GetInstance()->GetDao(EDM_DEFAULT_DENY_OUTPUT_CHAIN_NAME);
        if (dao == nullptr) {
            EDMLOGE("ClearDefaultFirewallDenyChain:GetDao fail, this should not happen.");
        } else {
            dao->Remove(nullptr);
            g_defaultFirewallChainInit = false;
        }
    }
}

void IptablesService::SetDefaultDomainDenyChain()
{
    if (!g_defaultDomainChainInit) {
        DomainFilterRule domainFilterRule{Action::DENY, "", ""};
        std::shared_ptr<ChainRule> chainRule = std::make_shared<DomainChainRule>(domainFilterRule);
        auto dao = DaoFactory::GetInstance()->GetDao(EDM_DEFAULT_DNS_DENY_OUTPUT_CHAIN_NAME);
        if (dao == nullptr) {
            EDMLOGE("SetDefaultDomainDenyChain:GetDao fail, this should not happen.");
        } else {
            dao->Add(chainRule);
            g_defaultDomainChainInit = true;
        }
    }
}

void IptablesService::ClearDefaultDomainDenyChain()
{
    if (g_defaultDomainChainInit) {
        auto dao = DaoFactory::GetInstance()->GetDao(EDM_DEFAULT_DNS_DENY_OUTPUT_CHAIN_NAME);
        if (dao == nullptr) {
            EDMLOGE("ClearDefaultDomainDenyChain:GetDao fail, this should not happen.");
        } else {
            dao->Remove(nullptr);
            g_defaultDomainChainInit = false;
        }
    }
}

bool IptablesService::ExistDenyFirewallRule()
{
    std::vector<std::string> chainNameVector{EDM_DENY_INPUT_CHAIN_NAME, EDM_DENY_OUTPUT_CHAIN_NAME};
    return ChainExistRule(chainNameVector);
}

bool IptablesService::ExistDenyDomainRule()
{
    std::vector<std::string> chainNameVector{EDM_DNS_DENY_OUTPUT_CHAIN_NAME};
    return ChainExistRule(chainNameVector);
}

bool IptablesService::ChainExistRule(const std::vector<std::string>& chainNames)
{
    std::vector<std::string> ruleList;
    for (const auto& chainName : chainNames) {
        auto dao = DaoFactory::GetInstance()->GetDao(chainName);
        dao->GetAll(ruleList);
        if (!ruleList.empty()) {
            return true;
        }
    }
    return false;
}

} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS