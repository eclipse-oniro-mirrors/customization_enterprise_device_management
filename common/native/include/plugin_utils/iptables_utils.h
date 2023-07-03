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

#ifndef INTERFACES_INNER_API_NETWORK_MANAGER_INCLUDE_IPTABLES_UTILS_H
#define INTERFACES_INNER_API_NETWORK_MANAGER_INCLUDE_IPTABLES_UTILS_H

#include <string>

#include "message_parcel.h"

namespace OHOS {
namespace EDM {
namespace IPTABLES {
enum class AddMethod { INVALID = -1, APPEND, INSERT };

enum class Direction { INVALID = -1, INPUT, OUTPUT };

enum class Action { INVALID = -1, ALLOW, DENY };

enum class Protocol { INVALID = -1, ALL, TCP, UDP, ICMP };

struct Firewall {
    std::string srcAddr;
    std::string destAddr;
    std::string srcPort;
    std::string destPort;
    std::string uid;
    Direction direction;
    Action action;
    Protocol protocol;
};

struct AddFilter : Firewall {
    uint32_t ruleNo = 0;
    AddMethod method;
    AddFilter()
    {
        protocol = Protocol::INVALID;
        action = Action::INVALID;
        direction = Direction::INVALID;
        method = AddMethod::INVALID;
    }
};

struct RemoveFilter : Firewall {
    RemoveFilter()
    {
        protocol = Protocol::INVALID;
        action = Action::INVALID;
        direction = Direction::INVALID;
    }
};

class IptablesUtils {
public:
    static void WriteAddFilterConfig(const AddFilter &fiter, MessageParcel &data);
    static void WriteRemoveFilterConfig(const RemoveFilter &fiter, MessageParcel &data);
    static void ReadAddFilterConfig(AddFilter &fiter, MessageParcel &data);
    static void ReadRemoveFilterConfig(RemoveFilter &fiter, MessageParcel &data);
    static bool ProcessFirewallAction(int32_t type, Action &action);
    static bool ProcessFirewallMethod(int32_t type, AddMethod &method);
    static bool ProcessFirewallDirection(int32_t type, Direction &direction);
    static void ProcessFirewallProtocol(int32_t type, Protocol &protocol);
};
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_NETWORK_MANAGER_INCLUDE_IPTABLES_UTILS_H
