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

#include "domain_executer.h"
#include "domain_chain_rule.h"

#include <iostream>
#include <sstream>
#include <utility>

#include "edm_log.h"

namespace OHOS {
namespace EDM {
namespace IPTABLES {

const std::string SELECT_TABLE_OPTION = "-t ";
const std::string JUMP_OPTION = " -j ";
const std::string INSERT_OPTION = " -I ";

DomainExecuter::DomainExecuter(std::string actualChainName, const std::string& chainName) : IExecuter(chainName),
    actualChainName_(std::move(actualChainName))
{
}


ErrCode DomainExecuter::Init(NetsysNative::IptablesType ipType)
{
    std::ostringstream oss;
    oss << SELECT_TABLE_OPTION << tableName_ << INSERT_OPTION << actualChainName_ << " -p udp --dport 53"
        << JUMP_OPTION << chainName_;
    std::string result;
    ErrCode ret = ExecuterUtils::GetInstance()->Execute(oss.str(), result, ipType);
    if (ret != ERR_OK) {
        EDMLOGE("DomainExecuter:Init error.ret:%{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

bool DomainExecuter::SetDefaultOutputDenyChain(Direction direction, Family family)
{
    if (direction == Direction::OUTPUT) {
        DomainFilterRule domainFilterRule{Action::DENY, "", "", Direction::OUTPUT, family};
        std::shared_ptr<ChainRule> chainRule = std::make_shared<DomainChainRule>(domainFilterRule);
        NetsysNative::IptablesType ipType = static_cast<NetsysNative::IptablesType>(static_cast<int32_t>(family));
        Add(chainRule, ipType);
        return true;
    }
    return false;
}

bool DomainExecuter::SetDefaultForwardDenyChain(Direction direction, Family family)
{
    if (direction == Direction::FORWARD) {
        DomainFilterRule domainFilterRule{Action::DENY, "", "", Direction::FORWARD, family};
        std::shared_ptr<ChainRule> chainRule = std::make_shared<DomainChainRule>(domainFilterRule);
        NetsysNative::IptablesType ipType = static_cast<NetsysNative::IptablesType>(static_cast<int32_t>(family));
        Add(chainRule, ipType);
        return true;
    }
    return false;
}
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS