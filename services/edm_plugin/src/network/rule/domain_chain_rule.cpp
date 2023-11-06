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

#include "domain_chain_rule.h"

#include <algorithm>
#include <iostream>
#include <sstream>
#include <string>

#include "edm_log.h"
#include "rule_utils.h"

namespace OHOS {
namespace EDM {
namespace IPTABLES {

const char DOMAIN_DELIM = '.';
const uint32_t DOUBLE_NUM = 2;
const uint32_t FOUR_BIT = 4;
const uint8_t HEX_TEM_NUM = 10;

DomainChainRule::DomainChainRule(DomainFilterRule domainFilterRule) : ChainRule(),
    appUid_(std::get<DOMAIN_APPUID_IND>(domainFilterRule)),
    domainName_(std::get<DOMAIN_DOMAINNAME_IND>(domainFilterRule))
{
    target_ = RuleUtils::EnumToString(std::get<DOMAIN_ACTION_IND>(domainFilterRule));
}

DomainChainRule::DomainChainRule(const std::string &rule) : ChainRule(rule)
{
    std::string formatDomain;
    GetOption(otherOptions_, "owner UID match", appUid_);
    GetOption(otherOptions_, "STRING match", formatDomain);
    domainName_ = FormatDataToDomain(formatDomain);
}

std::string DomainChainRule::Parameter() const
{
    // domain type policy uses fixed port and protocol
    std::ostringstream parameter;
    parameter << " -p udp --dport 53";
    if (!appUid_.empty()) {
        parameter << " -m owner --uid-owner " << appUid_;
    }
    if (!domainName_.empty()) {
        parameter << " -m string --hex-string " << DomainToFormatData(domainName_) << " --algo bm";
    }
    return parameter.str();
}

DomainFilterRule DomainChainRule::ToFilterRule()
{
    Action action = RuleUtils::StringToAction(target_);
    return {action, appUid_, domainName_};
}

std::string DomainChainRule::DomainToFormatData(const std::string &domainName)
{
    std::istringstream iss(domainName);
    std::string segment;
    std::vector<std::string> segmentArray;
    while (std::getline(iss, segment, DOMAIN_DELIM)) {
        segmentArray.emplace_back(segment);
    }

    // no need to use the "" symbol
    // www.example.com -> |03|www|07|example|03|com|
    std::ostringstream domainParameterString;
    for (const auto &item : segmentArray) {
        domainParameterString << '|';
        if (item.length() > 0xf) {
            domainParameterString << std::hex << item.length();
        } else {
            domainParameterString << '0' << std::hex << item.length();
        }
        domainParameterString << '|';
        domainParameterString << item;
    }
    domainParameterString << '|';
    return domainParameterString.str();
}

std::string DomainChainRule::FormatDataToDomain(const std::string &formatData)
{
    std::string tempFormatData{formatData};
    std::string invalidChar = "|\"";
    tempFormatData.erase(std::remove_if(tempFormatData.begin(), tempFormatData.end(),
        [&invalidChar](const char &c) { return invalidChar.find(c) != std::string::npos; }),
        tempFormatData.end());

    if (tempFormatData.empty() || tempFormatData.length() % DOUBLE_NUM != 0) {
        EDMLOGE("FormatDataToDomain: wrong domain data, this should not happen.");
        return {};
    }

    std::string ret;
    std::istringstream iss{tempFormatData};
    char firstChar;
    char secondChar;
    std::vector<std::string> segmentList;
    while (iss >> firstChar >> secondChar) {
        uint8_t segmentSize = CharToHex(firstChar, secondChar);
        std::ostringstream segmentOss;
        for (uint8_t j = 0; j < segmentSize; ++j) {
            iss >> firstChar >> secondChar;
            uint8_t segmentChar = CharToHex(firstChar, secondChar);
            segmentOss << segmentChar;
        }
        segmentList.emplace_back(segmentOss.str());
    }
    std::ostringstream oss;
    for (uint32_t i = 0; i < segmentList.size(); ++i) {
        oss << segmentList[i];
        if (i == (segmentList.size() - 1)) {
            break;
        }
        oss << DOMAIN_DELIM;
    }
    return oss.str();
}

uint8_t DomainChainRule::CharToHex(const char &first, const char &second)
{
    uint8_t high = CharToHex(first);
    uint8_t low = CharToHex(second);
    return (high << FOUR_BIT) | low;
}

uint8_t DomainChainRule::CharToHex(const char &hexChar)
{
    if (hexChar >= '0' && hexChar <= '9') {
        return hexChar - '0';
    } else if (hexChar >= 'a' && hexChar <= 'f') {
        return hexChar - 'a' + HEX_TEM_NUM;
    } else if (hexChar >= 'A' && hexChar <= 'F') {
        return hexChar - 'A' + HEX_TEM_NUM;
    }
    return 0;
}
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS