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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_IPTABLES_RULE_UTILS_H
#define SERVICES_EDM_PLUGIN_INCLUDE_IPTABLES_RULE_UTILS_H

#include "iptables_utils.h"

namespace OHOS {
namespace EDM {
namespace IPTABLES {

const std::string SPACE_OPTION = " ";

const std::string ACCEPT_TARGET = "ACCEPT";
const std::string REJECT_TARGET = "REJECT";
const std::string DROP_TARGET = "DROP";

const std::string PROTOCOL_ALL = "all";
const std::string PROTOCOL_TCP = "tcp";
const std::string PROTOCOL_UDP = "udp";
const std::string PROTOCOL_ICMP = "icmp";


const std::string EDM_DENY_OUTPUT_CHAIN_NAME = "edm_deny_output";
const std::string EDM_DENY_INPUT_CHAIN_NAME = "edm_deny_input";
const std::string EDM_ALLOW_OUTPUT_CHAIN_NAME = "edm_allow_output";
const std::string EDM_ALLOW_INPUT_CHAIN_NAME = "edm_allow_input";
const std::string EDM_DEFAULT_DENY_OUTPUT_CHAIN_NAME = "edm_default_deny_output";

const std::string EDM_DNS_DENY_OUTPUT_CHAIN_NAME = "edm_dns_deny_output";
const std::string EDM_DNS_ALLOW_OUTPUT_CHAIN_NAME = "edm_dns_allow_output";
const std::string EDM_DEFAULT_DNS_DENY_OUTPUT_CHAIN_NAME = "edm_default_dns_deny_output";

class RuleUtils {
public:
    static std::string EnumToString(Action action);
    static Action StringToAction(std::string action);
    static std::string EnumToString(Protocol protocol);
    static Protocol StringProtocl(std::string protocol);
};
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_PLUGIN_INCLUDE_IPTABLES_RULE_UTILS_H
