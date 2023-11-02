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

#include "dao_factory.h"

#include <algorithm>

#include "domain_dao.h"
#include "firewall_dao.h"
#include "rule_utils.h"

namespace OHOS {
namespace EDM {
namespace IPTABLES {

const std::string OUTPUT_CHAIN = "OUTPUT";
const std::string INPUT_CHAIN = "INPUT";

std::shared_ptr<DaoFactory> DaoFactory::instance_;
std::mutex DaoFactory::mutexLock_;

std::shared_ptr<DaoFactory> DaoFactory::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutexLock_);
        if (instance_ == nullptr) {
            std::shared_ptr<DaoFactory> temp = std::make_shared<DaoFactory>();
            instance_ = temp;

            instance_->chainNames_.emplace_back(EDM_DEFAULT_DENY_OUTPUT_CHAIN_NAME);
            instance_->daoVector_.emplace_back(
                std::make_shared<FirewallDao>(OUTPUT_CHAIN, EDM_DEFAULT_DENY_OUTPUT_CHAIN_NAME));
            instance_->chainNames_.emplace_back(EDM_DENY_OUTPUT_CHAIN_NAME);
            instance_->daoVector_.emplace_back(std::make_shared<FirewallDao>(OUTPUT_CHAIN, 
                EDM_DENY_OUTPUT_CHAIN_NAME));
            instance_->chainNames_.emplace_back(EDM_DENY_INPUT_CHAIN_NAME);
            instance_->daoVector_.emplace_back(std::make_shared<FirewallDao>(INPUT_CHAIN, 
                EDM_DENY_INPUT_CHAIN_NAME));
            instance_->chainNames_.emplace_back(EDM_ALLOW_OUTPUT_CHAIN_NAME);
            instance_->daoVector_.emplace_back(std::make_shared<FirewallDao>(OUTPUT_CHAIN, 
                EDM_ALLOW_OUTPUT_CHAIN_NAME));
            instance_->chainNames_.emplace_back(EDM_ALLOW_INPUT_CHAIN_NAME);
            instance_->daoVector_.emplace_back(std::make_shared<FirewallDao>(INPUT_CHAIN, 
                EDM_ALLOW_INPUT_CHAIN_NAME));

            instance_->chainNames_.emplace_back(EDM_DEFAULT_DNS_DENY_OUTPUT_CHAIN_NAME);
            instance_->daoVector_.emplace_back(std::make_shared<FirewallDao>(OUTPUT_CHAIN, 
                EDM_DEFAULT_DNS_DENY_OUTPUT_CHAIN_NAME));
            instance_->chainNames_.emplace_back(EDM_DNS_DENY_OUTPUT_CHAIN_NAME);
            instance_->daoVector_.emplace_back(std::make_shared<DomainDao>(EDM_DNS_DENY_OUTPUT_CHAIN_NAME));
            instance_->chainNames_.emplace_back(EDM_DNS_ALLOW_OUTPUT_CHAIN_NAME);
            instance_->daoVector_.emplace_back(std::make_shared<DomainDao>(EDM_DNS_ALLOW_OUTPUT_CHAIN_NAME));
        }
    }
    return instance_;
}

std::shared_ptr<IDao> DaoFactory::GetDao(const std::string& chainName) const
{
    auto it = std::find(chainNames_.begin(), chainNames_.end(), chainName);
    if (it != chainNames_.end()) {
        int index = it - chainNames_.begin();
        return daoVector_[index];
    }
    return nullptr;
}

std::vector<std::shared_ptr<IDao>> DaoFactory::GetAllDao() const
{
    return daoVector_;
}

} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS