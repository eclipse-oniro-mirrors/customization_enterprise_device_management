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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_IPTABLES_CHAIN_RULE_H
#define SERVICES_EDM_PLUGIN_INCLUDE_IPTABLES_CHAIN_RULE_H

#include <string>
#include <vector>

#include "edm_errors.h"

namespace OHOS {
namespace EDM {
namespace IPTABLES {

class ChainRule {
public:
    explicit ChainRule(const std::string &rule);

    virtual uint32_t RuleNum();
    [[nodiscard]] virtual std::string Parameter() const = 0;
    virtual std::string Target();

protected:
    ChainRule() = default;

    void GetOption(const std::string &options, const std::string &key, std::string &value);
    void GetOption(const std::string &options, const std::string &key, uint32_t &value);

private:
    void TruncateOption(const std::string &options, const std::string &key, std::string &result);

protected:
    uint32_t ruleNo_ = 0;

    std::string target_;
    std::string prot_;

    std::string srcAddr_;
    std::string destAddr_;

    std::string otherOptions_;
};
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_PLUGIN_INCLUDE_IPTABLES_CHAIN_RULE_H
