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

#include "rule_utils.h"

namespace OHOS {
namespace EDM {
namespace IPTABLES {

std::string RuleUtils::EnumToString(Action action)
{
    switch (action) {
        case Action::INVALID:
            return {};
        case Action::ALLOW:
            return ACCEPT_TARGET;
        case Action::DENY:
            return DROP_TARGET;
    }
    return {};
}

Action RuleUtils::StringToAction(std::string action)
{
    if (action == ACCEPT_TARGET) {
        return Action::ALLOW;
    } else if (action == DROP_TARGET) {
        return Action::DENY;
    } else {
        return Action::INVALID;
    }
}

std::string RuleUtils::EnumToString(Protocol protocol)
{
    switch (protocol) {
        case Protocol::INVALID:
            return {};
        case Protocol::ALL:
            return PROTOCOL_ALL;
        case Protocol::TCP:
            return PROTOCOL_TCP;
        case Protocol::UDP:
            return PROTOCOL_UDP;
        case Protocol::ICMP:
            return PROTOCOL_ICMP;
    }
    return {};
}
Protocol RuleUtils::StringProtocl(std::string protocol)
{
    if (protocol == PROTOCOL_ALL) {
        return Protocol::ALL;
    } else if (protocol == PROTOCOL_TCP) {
        return Protocol::TCP;
    } else if (protocol == PROTOCOL_UDP) {
        return Protocol::UDP;
    } else if (protocol == PROTOCOL_ICMP) {
        return Protocol::ICMP;
    } else {
        return Protocol::INVALID;
    }
}
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS