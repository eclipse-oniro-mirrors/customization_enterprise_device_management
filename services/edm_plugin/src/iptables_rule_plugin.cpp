/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "iptables_rule_plugin.h"

#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "func_code_utils.h"
#include "netsys_controller.h"
#include "plugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(std::make_shared<IptablesRulePlugin>());
const std::string EDM_CHAIN_ALLOW_INPUT = "edm_allow_input";
const std::string EDM_CHAIN_ALLOW_OUTPUT = "edm_allow_output";
const std::string EDM_CHAIN_DENY_INPUT = "edm_deny_input";
const std::string EDM_CHAIN_DENY_OUTPUT = "edm_deny_output";

bool IptablesRulePlugin::isChainInit_ = false;

IptablesRulePlugin::IptablesRulePlugin()
{
    policyCode_ = EdmInterfaceCode::IPTABLES_RULE;
    policyName_ = "iptables_rule";
    permissionConfig_.permission = "ohos.permission.ENTERPRISE_MANAGE_NETWORK";
    permissionConfig_.permissionType = IPlugin::PermissionType::SUPER_DEVICE_ADMIN;
    permissionConfig_.apiType = IPlugin::ApiType::SYSTEM;
    needSave_ = false;
}

ErrCode IptablesRulePlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    uint32_t typeCode = FUNC_TO_OPERATE(funcCode);
    FuncOperateType type = FuncCodeUtils::ConvertOperateType(typeCode);
    if (type == FuncOperateType::SET) {
        return AddIptablesFilterRule(data);
    } else if (type == FuncOperateType::REMOVE) {
        return RemoveIptablesFilterRule(data);
    } else {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
}

ErrCode IptablesRulePlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    std::string result;
    std::string command("-t filter -n -v -L --line-number");
    int32_t ret = NetManagerStandard::NetsysController::GetInstance().SetIptablesCommandForRes(command, result);
    EDMLOGI("IptablesRulePlugin::OnGetPolicy end retCode = %{public}d", ret);
    if (ret == ERR_OK) {
        reply.WriteInt32(ERR_OK);
        reply.WriteString(result);
        return ERR_OK;
    }
    reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
    return EdmReturnErrCode::SYSTEM_ABNORMALLY;
}

ErrCode IptablesRulePlugin::AddIptablesFilterRule(MessageParcel &data)
{
    IPTABLES::AddFilter addFilter;
    IPTABLES::IptablesUtils::ReadAddFilterConfig(addFilter, data);
    std::string command;
    if (!ConvertAddFilterToIptablesCommand(addFilter, command)) {
        EDMLOGE("ConvertAddFilterToIptablesCommand failed");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    InitFirewallChain();
    std::string result;
    int32_t ret = NetManagerStandard::NetsysController::GetInstance().SetIptablesCommandForRes(command, result);
    EDMLOGI("AddIptablesFilterRule errcode = %{public}d, response = %{public}s", ret, result.c_str());
    return ret;
}

ErrCode IptablesRulePlugin::RemoveIptablesFilterRule(MessageParcel &data)
{
    IPTABLES::RemoveFilter removeFilter;
    IPTABLES::IptablesUtils::ReadRemoveFilterConfig(removeFilter, data);
    return ExecRemoveFilterIptablesCommand(removeFilter);
}

void IptablesRulePlugin::InitFirewallChain()
{
    if (isChainInit_) {
        EDMLOGD("no need init firewall chain");
        return;
    }
    std::string allowInputChain = "-t filter -N " + EDM_CHAIN_ALLOW_INPUT;
    std::string allowOutputChain = "-t filter -N " + EDM_CHAIN_ALLOW_OUTPUT;
    std::string denyInputChain = "-t filter -N " + EDM_CHAIN_DENY_INPUT;
    std::string denyOutputChain = "-t filter -N " + EDM_CHAIN_DENY_OUTPUT;

    std::string result;
    NetManagerStandard::NetsysController::GetInstance().SetIptablesCommandForRes(allowInputChain, result);
    NetManagerStandard::NetsysController::GetInstance().SetIptablesCommandForRes(allowOutputChain, result);
    NetManagerStandard::NetsysController::GetInstance().SetIptablesCommandForRes(denyInputChain, result);
    NetManagerStandard::NetsysController::GetInstance().SetIptablesCommandForRes(denyOutputChain, result);

    std::string refDenyOutputChain = "-t filter -I OUTPUT -j " + EDM_CHAIN_DENY_OUTPUT;
    std::string refDenyInputChain = "-t filter -I INPUT -j " + EDM_CHAIN_DENY_INPUT;
    std::string refAllowOutputChain = "-t filter -I OUTPUT -j " + EDM_CHAIN_ALLOW_OUTPUT;
    std::string refAllowInputChain = "-t filter -I INPUT -j " + EDM_CHAIN_ALLOW_INPUT;
    NetManagerStandard::NetsysController::GetInstance().SetIptablesCommandForRes(refDenyOutputChain, result);
    NetManagerStandard::NetsysController::GetInstance().SetIptablesCommandForRes(refDenyInputChain, result);
    NetManagerStandard::NetsysController::GetInstance().SetIptablesCommandForRes(refAllowOutputChain, result);
    NetManagerStandard::NetsysController::GetInstance().SetIptablesCommandForRes(refAllowInputChain, result);
    isChainInit_ = true;
    EDMLOGD("InitFirewallChain success");
}

bool IptablesRulePlugin::ConvertAddFilterToIptablesCommand(const IPTABLES::AddFilter &addFilter, std::string &command)
{
    command = "-t filter";
    if (addFilter.method == IPTABLES::AddMethod::APPEND) {
        command.append(" -A");
    } else if (addFilter.method == IPTABLES::AddMethod::INSERT) {
        command.append(" -I");
    } else {
        EDMLOGE("ConvertFirewallToIptablesCommand AddMethod must specify");
        return false;
    }
    if (!ConvertChainCommand(addFilter.action, addFilter.direction, command)) {
        EDMLOGE("ConvertFirewallToIptablesCommand action and direction must specify");
        return false;
    }
    ConvertRuleNoCommand(addFilter.method, addFilter.ruleNo, command);
    ConvertProtocolCommand(addFilter.protocol, command);
    ConvertIpAddressCommand(addFilter.srcAddr, true, command);
    ConvertIpAddressCommand(addFilter.destAddr, false, command);
    ConvertPortCommand(addFilter.srcPort, true, command);
    ConvertPortCommand(addFilter.destPort, false, command);
    ConvertUidCommand(addFilter.uid, command);
    return ConvertActionCommand(addFilter.action, command);
}

ErrCode IptablesRulePlugin::ExecRemoveFilterIptablesCommand(const IPTABLES::RemoveFilter &removeFilter)
{
    if (removeFilter.direction == IPTABLES::Direction::INVALID) {
        return EdmReturnErrCode::PARAM_ERROR;
    }
    if (removeFilter.srcAddr.empty() && removeFilter.destAddr.empty() && removeFilter.srcPort.empty() &&
        removeFilter.destPort.empty() && removeFilter.uid.empty() && removeFilter.action == IPTABLES::Action::INVALID &&
        removeFilter.protocol == IPTABLES::Protocol::INVALID) {
        return ExecRemoveFilterBySimpleCommand(removeFilter.direction);
    }
    return ExecRemoveFilterByDetailedCommand(removeFilter);
}

ErrCode IptablesRulePlugin::ExecRemoveFilterBySimpleCommand(const IPTABLES::Direction &direction)
{
    std::string commandAllow("-t filter -F");
    std::string commandDeny("-t filter -F");
    switch (direction) {
        case IPTABLES::Direction::INPUT:
            commandAllow.append(" " + EDM_CHAIN_ALLOW_INPUT);
            commandDeny.append(" " + EDM_CHAIN_DENY_INPUT);
            break;
        case IPTABLES::Direction::OUTPUT:
            commandAllow.append(" " + EDM_CHAIN_ALLOW_OUTPUT);
            commandDeny.append(" " + EDM_CHAIN_DENY_OUTPUT);
            break;
        default:
            return EdmReturnErrCode::PARAM_ERROR;
    }
    std::string result;
    NetManagerStandard::NetsysController::GetInstance().SetIptablesCommandForRes(commandAllow, result);
    NetManagerStandard::NetsysController::GetInstance().SetIptablesCommandForRes(commandDeny, result);
    return ERR_OK;
}

ErrCode IptablesRulePlugin::ExecRemoveFilterByDetailedCommand(const IPTABLES::RemoveFilter &removeFilter)
{
    std::string command = "-t filter -D";
    ConvertChainCommand(removeFilter.action, removeFilter.direction, command);
    ConvertProtocolCommand(removeFilter.protocol, command);
    ConvertIpAddressCommand(removeFilter.srcAddr, true, command);
    ConvertIpAddressCommand(removeFilter.destAddr, false, command);
    ConvertPortCommand(removeFilter.srcPort, true, command);
    ConvertPortCommand(removeFilter.destPort, false, command);
    ConvertUidCommand(removeFilter.uid, command);
    ConvertActionCommand(removeFilter.action, command);
    std::string result;
    return NetManagerStandard::NetsysController::GetInstance().SetIptablesCommandForRes(command, result);
}

bool IptablesRulePlugin::ConvertChainCommand(const IPTABLES::Action &action, const IPTABLES::Direction &direction,
    std::string &command)
{
    if (action == IPTABLES::Action::ALLOW && direction == IPTABLES::Direction::INPUT) {
        command.append(" " + EDM_CHAIN_ALLOW_INPUT);
    } else if (action == IPTABLES::Action::ALLOW && direction == IPTABLES::Direction::OUTPUT) {
        command.append(" " + EDM_CHAIN_ALLOW_OUTPUT);
    } else if (action == IPTABLES::Action::DENY && direction == IPTABLES::Direction::INPUT) {
        command.append(" " + EDM_CHAIN_DENY_INPUT);
    } else if (action == IPTABLES::Action::DENY && direction == IPTABLES::Direction::OUTPUT) {
        command.append(" " + EDM_CHAIN_DENY_OUTPUT);
    } else {
        return false;
    }
    return true;
}

void IptablesRulePlugin::ConvertProtocolCommand(const IPTABLES::Protocol &protocol, std::string &command)
{
    switch (protocol) {
        case IPTABLES::Protocol::TCP:
            command.append(" -p tcp");
            break;
        case IPTABLES::Protocol::UDP:
            command.append(" -p udp");
            break;
        case IPTABLES::Protocol::ICMP:
            command.append(" -p icmp");
            break;
        case IPTABLES::Protocol::ALL:
            command.append(" -p all");
            break;
        default:
            break;
    }
}

bool IptablesRulePlugin::ConvertActionCommand(const IPTABLES::Action &action, std::string &command)
{
    switch (action) {
        case IPTABLES::Action::ALLOW:
            command.append(" -j ACCEPT");
            break;
        case IPTABLES::Action::DENY:
            command.append(" -j REJECT");
            break;
        default:
            return false;
    }
    return true;
}

void IptablesRulePlugin::ConvertIpAddressCommand(const std::string &ipAddress, const bool isSourceIp,
    std::string &command)
{
    if (ipAddress.empty()) {
        return;
    }
    std::string splitStr = "-";
    std::string::size_type idx = ipAddress.find(splitStr);
    if (idx == std::string::npos) {
        if (isSourceIp) {
            command.append(" -s " + ipAddress);
        } else {
            command.append(" -d " + ipAddress);
        }
    } else {
        if (isSourceIp) {
            command.append(" -m iprange --src-range " + ipAddress);
        } else {
            command.append(" -m iprange --dst-range " + ipAddress);
        }
    }
}

void IptablesRulePlugin::ConvertPortCommand(const std::string &port, const bool isSourcePort, std::string &command)
{
    if (port.empty()) {
        return;
    }
    if (isSourcePort) {
        command.append(" --sport " + port);
    } else {
        command.append(" --dport " + port);
    }
}

void IptablesRulePlugin::ConvertUidCommand(const std::string &uid, std::string &command)
{
    if (uid.empty()) {
        return;
    }
    command.append(" -m owner --uid-owner " + uid);
}

void IptablesRulePlugin::ConvertRuleNoCommand(const IPTABLES::AddMethod &method, uint32_t ruleNo, std::string &command)
{
    if (method == IPTABLES::AddMethod::INSERT && ruleNo != 0) {
        command.append(" " + std::to_string(ruleNo));
    }
}
} // namespace EDM
} // namespace OHOS
