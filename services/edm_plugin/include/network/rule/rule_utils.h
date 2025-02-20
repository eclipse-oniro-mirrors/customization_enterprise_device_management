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

const char* const SPACE_OPTION = " ";

const char* const ACCEPT_TARGET = "ACCEPT";
const char* const REJECT_TARGET = "REJECT";
const char* const DROP_TARGET = "DROP";

const char* const PROTOCOL_ALL = "all";
const char* const PROTOCOL_TCP = "tcp";
const char* const PROTOCOL_UDP = "udp";
const char* const PROTOCOL_ICMP = "icmp";


const char* const EDM_DENY_OUTPUT_CHAIN_NAME = "edm_deny_output";
const char* const EDM_DENY_FORWARD_CHAIN_NAME = "edm_deny_forward";
const char* const EDM_DENY_INPUT_CHAIN_NAME = "edm_deny_input";
const char* const EDM_ALLOW_OUTPUT_CHAIN_NAME = "edm_allow_output";
const char* const EDM_ALLOW_FORWARD_CHAIN_NAME = "edm_allow_forward";
const char* const EDM_ALLOW_INPUT_CHAIN_NAME = "edm_allow_input";
const char* const EDM_REJECT_OUTPUT_CHAIN_NAME = "edm_reject_output";
const char* const EDM_REJECT_FORWARD_CHAIN_NAME = "edm_reject_forward";
const char* const EDM_REJECT_INPUT_CHAIN_NAME = "edm_reject_input";
const char* const EDM_DEFAULT_DENY_OUTPUT_CHAIN_NAME = "edm_default_deny_output";
const char* const EDM_DEFAULT_DENY_FORWARD_CHAIN_NAME = "edm_default_deny_forward";

const char* const EDM_DNS_DENY_OUTPUT_CHAIN_NAME = "edm_dns_deny_output";
const char* const EDM_DNS_DENY_FORWARD_CHAIN_NAME = "edm_dns_deny_forward";
const char* const EDM_DNS_ALLOW_OUTPUT_CHAIN_NAME = "edm_dns_allow_output";
const char* const EDM_DNS_ALLOW_FORWARD_CHAIN_NAME = "edm_dns_allow_forward";
const char* const EDM_DNS_REJECT_OUTPUT_CHAIN_NAME = "edm_dns_reject_output";
const char* const EDM_DNS_REJECT_FORWARD_CHAIN_NAME = "edm_dns_reject_forward";
const char* const EDM_DEFAULT_DNS_DENY_OUTPUT_CHAIN_NAME = "edm_default_dns_deny_output";
const char* const EDM_DEFAULT_DNS_DENY_FORWARD_CHAIN_NAME = "edm_default_dns_deny_forward";

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
