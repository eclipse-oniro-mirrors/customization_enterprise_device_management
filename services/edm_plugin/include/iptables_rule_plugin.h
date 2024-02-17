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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_IPTABLES_RULE_PLUGIN_H
#define SERVICES_EDM_PLUGIN_INCLUDE_IPTABLES_RULE_PLUGIN_H

#include <message_parcel.h>

#include "iplugin.h"
#include "iptables_utils.h"

namespace OHOS {
namespace EDM {
class IptablesRulePlugin : public IPlugin {
public:
    IptablesRulePlugin();
    ErrCode OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
        HandlePolicyData &policyData, int32_t userId) override;

    void OnHandlePolicyDone(std::uint32_t funcCode, const std::string &adminName, bool isGlobalChanged,
        int32_t userId) override{};

    ErrCode OnAdminRemove(const std::string &adminName, const std::string &policyData, int32_t userId) override
    {
        return ERR_OK;
    };

    void OnAdminRemoveDone(const std::string &adminName, const std::string &currentJsonData, int32_t userId) override{};

    ErrCode OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId) override;

private:
    void InitFirewallChain();
    bool ConvertAddFilterToIptablesCommand(const IPTABLES::AddFilter &addFilter, std::string &Command);
    ErrCode ExecRemoveFilterIptablesCommand(const IPTABLES::RemoveFilter &removeFilter);
    ErrCode ExecRemoveFilterBySimpleCommand(const IPTABLES::Direction &direction);
    ErrCode ExecRemoveFilterByDetailedCommand(const IPTABLES::RemoveFilter &removeFilter);
    bool ConvertChainCommand(const IPTABLES::Action &action, const IPTABLES::Direction &direction,
        std::string &Command);
    void ConvertIpAddressCommand(const std::string &ipAddress, const bool isSourceIp, std::string &Command);
    void ConvertPortCommand(const std::string &port, const bool isSourcePort, std::string &Command);
    void ConvertProtocolCommand(const IPTABLES::Protocol &protocol, std::string &Command);
    bool ConvertActionCommand(const IPTABLES::Action &action, std::string &Command);
    void ConvertRuleNoCommand(const IPTABLES::AddMethod &method, uint32_t ruleNo, std::string &Command);
    void ConvertUidCommand(const std::string &uid, std::string &Command);
    ErrCode AddIptablesFilterRule(MessageParcel &data);
    ErrCode RemoveIptablesFilterRule(MessageParcel &data);

    static bool isChainInit_;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_INCLUDE_IPTABLES_RULE_PLUGIN_H
