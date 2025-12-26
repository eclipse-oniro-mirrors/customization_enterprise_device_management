/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "networkManager_ani.h"
#include "edm_ani_utils.h"
#include "edm_log.h"
#include "network_manager_proxy.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "iptables_utils.h"

namespace OHOS {
namespace EDM {

static const char* NAMESPACE_NAME = "@ohos.enterprise.networkManager.networkManager";
const std::u16string DESCRIPTOR = u"ohos.edm.IEnterpriseDeviceMgr";

ani_status NetworkManagerAni::Init(ani_env* env)
{
    ani_namespace ns;
    if (ANI_OK != env->FindNamespace(NAMESPACE_NAME, &ns)) {
        EDMLOGE("Not found namespace %{public}s.", NAMESPACE_NAME);
        return ANI_ERROR;
    }
    std::array methods = {
        ani_native_function { "addFirewallRule", nullptr, reinterpret_cast<void*>(AddFirewallRule) },
        ani_native_function { "removeFirewallRule", nullptr, reinterpret_cast<void*>(RemoveFirewallRule) },
        ani_native_function { "addDomainFilterRule", nullptr, reinterpret_cast<void*>(AddDomainFilterRule) },
        ani_native_function { "removeDomainFilterRule", nullptr, reinterpret_cast<void*>(RemoveDomainFilterRule) },
    };
    if (ANI_OK != env->Namespace_BindNativeFunctions(ns, methods.data(), methods.size())) {
        EDMLOGE("Cannot bind native methods to namespace[%{public}s]", NAMESPACE_NAME);
        return ANI_ERROR;
    };
    return ANI_OK;
}

void NetworkManagerAni::AddFirewallRule(ani_env* env, ani_object aniAdmin, ani_object firewallRule)
{
    EDMLOGI("ANI_AddFirewallRule called");
    AppExecFwk::ElementName admin;
    if (!EdmAniUtils::UnWrapAdmin(env, aniAdmin, admin)) {
        EdmAniUtils::AniThrow(env, EdmReturnErrCode::PARAM_ERROR, "The admin parameter is invalid.");
        return;
    }

    IPTABLES::FirewallRule rule;
    JsObjToFirewallRule(env, firewallRule, rule);

    MessageParcel data;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteUint32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);

    IPTABLES::FirewallRuleParcel firewallRuleParcel{rule};
    if (!firewallRuleParcel.Marshalling(data)) {
        EDMLOGE("NetworkManagerAni::AddOrRemoveFirewallRuleCommon Marshalling rule fail.");
        return;
    }

    int32_t ret = NetworkManagerProxy::GetNetworkManagerProxy()->AddFirewallRule(data);
    if (FAILED(ret)) {
        EdmAniUtils::AniThrow(env, ret);
        EDMLOGE("AddFirewallRule fail errcode:%{public}d", ret);
        return;
    }
}

void NetworkManagerAni::RemoveFirewallRule(ani_env* env, ani_object aniAdmin, ani_object firewallRule)
{
    EDMLOGI("ANI_RemoveFirewallRule called");
    AppExecFwk::ElementName admin;
    if (!EdmAniUtils::UnWrapAdmin(env, aniAdmin, admin)) {
        EdmAniUtils::AniThrow(env, EdmReturnErrCode::PARAM_ERROR, "The admin parameter is invalid.");
        return;
    }

    IPTABLES::FirewallRule rule = {IPTABLES::Direction::INVALID, IPTABLES::Action::INVALID,
        IPTABLES::Protocol::INVALID, "", "", "", "", "", IPTABLES::Family::IPV4, IPTABLES::LogType::INVALID};
    ani_boolean isUndefined;
    if (env->Reference_IsUndefined(firewallRule, &isUndefined) == ANI_OK && !isUndefined) {
        JsObjToFirewallRule(env, firewallRule, rule);
    }

    int32_t ret = NetworkManagerProxy::GetNetworkManagerProxy()->RemoveFirewallRule(admin, rule);
    if (FAILED(ret)) {
        EdmAniUtils::AniThrow(env, ret);
        EDMLOGE("RemoveFirewallRule fail errcode:%{public}d", ret);
        return;
    }
}

void NetworkManagerAni::JsObjToFirewallRule(ani_env* env, ani_object firewallRule, IPTABLES::FirewallRule &rule)
{
    IPTABLES::Direction directionEnum = IPTABLES::Direction::INVALID;
    IPTABLES::Action actionEnum = IPTABLES::Action::INVALID;
    IPTABLES::Protocol protocolEnum = IPTABLES::Protocol::INVALID;
    IPTABLES::Family familyEnum = IPTABLES::Family::IPV4;
    IPTABLES::LogType logTypeEnum = IPTABLES::LogType::INVALID;
    int32_t direction;
    int32_t action;
    int32_t protocol;
    int32_t family;
    int32_t logType;
    std::string srcAddr;
    std::string destAddr;
    std::string srcPort;
    std::string destPort;
    std::string appUid;

    EdmAniUtils::GetStringProperty(env, firewallRule, "srcAddr", srcAddr);
    EdmAniUtils::GetStringProperty(env, firewallRule, "destAddr", destAddr);
    EdmAniUtils::GetStringProperty(env, firewallRule, "srcPort", srcPort);
    EdmAniUtils::GetStringProperty(env, firewallRule, "destPort", destPort);
    EdmAniUtils::GetStringProperty(env, firewallRule, "appUid", appUid);

    if (EdmAniUtils::GetEnumMember(env, firewallRule, "direction", direction)) {
        IPTABLES::IptablesUtils::ProcessFirewallDirection(direction, directionEnum);
    }
    if (EdmAniUtils::GetEnumMember(env, firewallRule, "action", action)) {
        IPTABLES::IptablesUtils::ProcessFirewallAction(action, actionEnum);
    }
    if (EdmAniUtils::GetEnumMember(env, firewallRule, "protocol", protocol)) {
        IPTABLES::IptablesUtils::ProcessFirewallProtocol(protocol, protocolEnum);
    }
    if (EdmAniUtils::GetOptionalIntProperty(env, firewallRule, "family", family)) {
        IPTABLES::IptablesUtils::ProcessFirewallFamily(family, familyEnum);
    }
    if (EdmAniUtils::GetEnumMember(env, firewallRule, "logType", logType)) {
        IPTABLES::IptablesUtils::ProcessFirewallLogType(logType, logTypeEnum);
    }

    rule = {directionEnum, actionEnum, protocolEnum, srcAddr, destAddr, srcPort, destPort, appUid,
        familyEnum, logTypeEnum};
    return;
}

void NetworkManagerAni::AddDomainFilterRule(ani_env* env, ani_object aniAdmin, ani_object domainFilterRule)
{
    EDMLOGI("ANI_AddDomainFilterRule called");
    AppExecFwk::ElementName admin;
    if (!EdmAniUtils::UnWrapAdmin(env, aniAdmin, admin)) {
        EdmAniUtils::AniThrow(env, EdmReturnErrCode::PARAM_ERROR, "The admin parameter is invalid.");
        return;
    }

    IPTABLES::DomainFilterRule rule = {IPTABLES::Action::INVALID, "", "", IPTABLES::Direction::INVALID,
        IPTABLES::Family::IPV4, IPTABLES::LogType::INVALID};
    JsObjToDomainFilterRule(env, domainFilterRule, rule);

    MessageParcel data;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteUint32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);

    IPTABLES::DomainFilterRuleParcel domainFilterRuleParcel{rule};
    if (!domainFilterRuleParcel.Marshalling(data)) {
        EDMLOGE("NetworkManagerAni::AddOrRemoveDomainFilterRuleCommon Marshalling rule fail.");
        return;
    }

    int32_t ret = NetworkManagerProxy::GetNetworkManagerProxy()->AddDomainFilterRule(data);
    if (FAILED(ret)) {
        EdmAniUtils::AniThrow(env, ret);
        EDMLOGE("AddDomainFilterRule fail errcode:%{public}d", ret);
        return;
    }
}

void NetworkManagerAni::RemoveDomainFilterRule(ani_env* env, ani_object aniAdmin, ani_object domainFilterRule)
{
    EDMLOGI("ANI_RemoveDomainFilterRule called");
    AppExecFwk::ElementName admin;
    if (!EdmAniUtils::UnWrapAdmin(env, aniAdmin, admin)) {
        EdmAniUtils::AniThrow(env, EdmReturnErrCode::PARAM_ERROR, "The admin parameter is invalid.");
        return;
    }

    IPTABLES::DomainFilterRule rule = {IPTABLES::Action::INVALID, "", "", IPTABLES::Direction::INVALID,
        IPTABLES::Family::IPV4, IPTABLES::LogType::INVALID};
    ani_boolean isUndefined;
    if (env->Reference_IsUndefined(domainFilterRule, &isUndefined) == ANI_OK && !isUndefined) {
        JsObjToDomainFilterRule(env, domainFilterRule, rule);
    }

    int32_t ret = NetworkManagerProxy::GetNetworkManagerProxy()->RemoveDomainFilterRule(admin, rule);
    if (FAILED(ret)) {
        EdmAniUtils::AniThrow(env, ret);
        EDMLOGE("RemoveDomainFilterRule fail errcode:%{public}d", ret);
        return;
    }
}

void NetworkManagerAni::JsObjToDomainFilterRule(ani_env* env, ani_object domainFilterRule,
    IPTABLES::DomainFilterRule &rule)
{
    IPTABLES::Action actionEnum = IPTABLES::Action::INVALID;
    IPTABLES::Direction directionEnum = IPTABLES::Direction::INVALID;
    IPTABLES::Family familyEnum = IPTABLES::Family::IPV4;
    IPTABLES::LogType logTypeEnum = IPTABLES::LogType::INVALID;
    int32_t direction;
    int32_t action;
    int32_t family;
    int32_t logType;
    std::string appUid;
    std::string domainName;

    EdmAniUtils::GetStringProperty(env, domainFilterRule, "appUid", appUid);
    EdmAniUtils::GetStringProperty(env, domainFilterRule, "domainName", domainName);

    if (EdmAniUtils::GetEnumMember(env, domainFilterRule, "action", action)) {
        IPTABLES::IptablesUtils::ProcessFirewallAction(action, actionEnum);
    }
    if (EdmAniUtils::GetEnumMember(env, domainFilterRule, "direction", direction)) {
        IPTABLES::IptablesUtils::ProcessFirewallDirection(direction, directionEnum);
    }
    if (EdmAniUtils::GetOptionalIntProperty(env, domainFilterRule, "family", family)) {
        IPTABLES::IptablesUtils::ProcessFirewallFamily(family, familyEnum);
    }
    if (EdmAniUtils::GetEnumMember(env, domainFilterRule, "logType", logType)) {
        IPTABLES::IptablesUtils::ProcessFirewallLogType(logType, logTypeEnum);
    }

    rule = {actionEnum, appUid, domainName, directionEnum, familyEnum, logTypeEnum};
    return;
}
} // namespace EDM
} // namespace OHOS

ANI_EXPORT ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
{
    ani_env* env;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        EDMLOGE("Unsupported ANI_VERSION_1.");
        return (ani_status)ANI_ERROR;
    }

    auto status = OHOS::EDM::NetworkManagerAni::Init(env);
    if (status != ANI_OK) {
        return status;
    }
    *result = ANI_VERSION_1;
    return ANI_OK;
}
