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

#include "chain_rule.h"

#include <sstream>

namespace OHOS {
namespace EDM {
namespace IPTABLES {

ChainRule::ChainRule(const std::string& rule)
{
    std::istringstream iss(rule);
    iss >> ruleNo_;
    uint64_t pkts = 0;
    iss >> pkts;
    uint64_t bytes = 0;
    iss >> bytes;
    iss >> target_;
    iss >> prot_;
    std::string opt;
    iss >> opt;
    std::string in;
    iss >> in;
    std::string out;
    iss >> out;
    std::string defaultIp = "0.0.0.0/0";
    std::string source;
    iss >> source;
    if (source != defaultIp) {
        srcAddr_ = source;
    }
    std::string destination;
    iss >> destination;
    if (destination != defaultIp) {
        destAddr_ = destination;
    }
    std::getline(iss, otherOptions_);
}

uint32_t ChainRule::RuleNum()
{
    return ruleNo_;
}

std::string ChainRule::Target()
{
    return target_;
}

void ChainRule::GetOption(const std::string& options, const std::string& key, std::string& value)
{
    std::string result;
    TruncateOption(options, key, result);
    if (!result.empty()) {
        std::istringstream iss{result};
        iss >> value;
    }
}

void ChainRule::GetOption(const std::string& options, const std::string& key, uint32_t& value)
{
    std::string result;
    TruncateOption(options, key, result);
    if (!result.empty()) {
        std::istringstream iss{result};
        iss >> value;
    }
}

void ChainRule::TruncateOption(const std::string& options, const std::string& key, std::string &result)
{
    auto index = options.find(key);
    if (index != std::string::npos) {
        result = options.substr(index + key.length());
    }
}
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS