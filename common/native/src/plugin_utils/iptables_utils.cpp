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

#include "iptables_utils.h"

#include "edm_log.h"

namespace OHOS {
namespace EDM {
namespace IPTABLES {
void IptablesUtils::WriteAddFilterConfig(const AddFilter &filter, MessageParcel &data)
{
    data.WriteUint32(filter.ruleNo);
    data.WriteString(filter.srcAddr);
    data.WriteString(filter.destAddr);
    data.WriteString(filter.srcPort);
    data.WriteString(filter.destPort);
    data.WriteString(filter.uid);
    data.WriteInt32(static_cast<int32_t>(filter.method));
    data.WriteInt32(static_cast<int32_t>(filter.direction));
    data.WriteInt32(static_cast<int32_t>(filter.action));
    data.WriteInt32(static_cast<int32_t>(filter.protocol));
}

void IptablesUtils::ReadAddFilterConfig(AddFilter &filter, MessageParcel &data)
{
    filter.ruleNo = data.ReadUint32();
    filter.srcAddr = data.ReadString();
    filter.destAddr = data.ReadString();
    filter.srcPort = data.ReadString();
    filter.destPort = data.ReadString();
    filter.uid = data.ReadString();
    IptablesUtils::ProcessFirewallMethod(data.ReadInt32(), filter.method);
    IptablesUtils::ProcessFirewallDirection(data.ReadInt32(), filter.direction);
    IptablesUtils::ProcessFirewallAction(data.ReadInt32(), filter.action);
    IptablesUtils::ProcessFirewallProtocol(data.ReadInt32(), filter.protocol);
}

void IptablesUtils::WriteRemoveFilterConfig(const RemoveFilter &filter, MessageParcel &data)
{
    data.WriteString(filter.srcAddr);
    data.WriteString(filter.destAddr);
    data.WriteString(filter.srcPort);
    data.WriteString(filter.destPort);
    data.WriteString(filter.uid);
    data.WriteInt32(static_cast<int32_t>(filter.direction));
    data.WriteInt32(static_cast<int32_t>(filter.action));
    data.WriteInt32(static_cast<int32_t>(filter.protocol));
}

void IptablesUtils::ReadRemoveFilterConfig(RemoveFilter &filter, MessageParcel &data)
{
    filter.srcAddr = data.ReadString();
    filter.destAddr = data.ReadString();
    filter.srcPort = data.ReadString();
    filter.destPort = data.ReadString();
    filter.uid = data.ReadString();
    IptablesUtils::ProcessFirewallDirection(data.ReadInt32(), filter.direction);
    IptablesUtils::ProcessFirewallAction(data.ReadInt32(), filter.action);
    IptablesUtils::ProcessFirewallProtocol(data.ReadInt32(), filter.protocol);
}

bool IptablesUtils::ProcessFirewallAction(int32_t type, Action &action)
{
    if (type >= static_cast<int32_t>(Action::ALLOW) && type <= static_cast<int32_t>(Action::DENY)) {
        action = Action(type);
        return true;
    }
    return false;
}

bool IptablesUtils::ProcessFirewallMethod(int32_t type, AddMethod &method)
{
    if (type >= static_cast<int32_t>(AddMethod::APPEND) && type <= static_cast<int32_t>(AddMethod::INSERT)) {
        method = AddMethod(type);
        return true;
    }
    return false;
}

bool IptablesUtils::ProcessFirewallDirection(int32_t type, Direction &direction)
{
    if (type >= static_cast<int32_t>(Direction::INPUT) && type <= static_cast<int32_t>(Direction::OUTPUT)) {
        direction = Direction(type);
        return true;
    }
    return false;
}

void IptablesUtils::ProcessFirewallProtocol(int32_t type, Protocol &protocol)
{
    if (type >= static_cast<int32_t>(Protocol::ALL) && type <= static_cast<int32_t>(Protocol::ICMP)) {
        protocol = Protocol(type);
    }
}
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS