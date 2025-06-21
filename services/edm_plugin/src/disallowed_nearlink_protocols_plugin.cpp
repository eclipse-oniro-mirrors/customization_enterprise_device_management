/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "disallowed_nearlink_protocols_plugin.h"

#include "common_event_manager.h"
#include "common_event_support.h"

#include "array_int_serializer.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_os_account_manager_impl.h"
#include "func_code_utils.h"
#include "nearlink_config_utils.h"
#include "nearlink_protocol_utils.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisallowedNearlinkProtocolsPlugin::GetPlugin());
constexpr int32_t NEARLINK_UID = 7030;

void DisallowedNearlinkProtocolsPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<DisallowedNearlinkProtocolsPlugin, std::vector<int32_t>>> ptr)
{
    EDMLOGI("DisallowedNearlinkProtocolsPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::DISALLOWED_NEARLINK_PROTOCOLS,
        PolicyName::POLICY_DISALLOWED_NEARLINK_PROTOCOLS,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SYSTEM,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        true);
    ptr->SetSerializer(ArrayIntSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisallowedNearlinkProtocolsPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnHandlePolicyDoneListener(&DisallowedNearlinkProtocolsPlugin::OnChangedPolicyDone, FuncOperateType::SET);
    ptr->SetOnHandlePolicyListener(&DisallowedNearlinkProtocolsPlugin::OnRemovePolicy, FuncOperateType::REMOVE);
    ptr->SetOnHandlePolicyDoneListener(
        &DisallowedNearlinkProtocolsPlugin::OnChangedPolicyDone, FuncOperateType::REMOVE);
    ptr->SetOnAdminRemoveListener(&DisallowedNearlinkProtocolsPlugin::OnAdminRemove);
}

ErrCode DisallowedNearlinkProtocolsPlugin::OnSetPolicy(
    std::vector<int32_t> &data, std::vector<int32_t> &currentData, std::vector<int32_t> &mergeData, int32_t userId)
{
    EDMLOGI("DisallowedNearlinkProtocolsPlugin OnSetPolicy userId = %{public}d", userId);
    if (data.empty()) {
        EDMLOGE("DisallowedNearlinkProtocolsPlugin OnSetPolicy data is empty");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    if (data.size() > EdmConstants::DEFAULT_LOOP_MAX_SIZE) {
        EDMLOGE("DisallowedNearlinkProtocolsPlugin OnSetPolicy size is over limit");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    NearlinkConfigUtils nearlinkConfigUtils;
    for (size_t i = 0; i < data.size(); ++i) {
        std::string protocol;
        if (!NearlinkProtocolUtils::IntToProtocolStr(data[i], protocol)) {
            return EdmReturnErrCode::PARAM_ERROR;
        }
        if (!nearlinkConfigUtils.UpdateProtocol(std::to_string(userId), protocol, true)) {
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    currentData = data;
    mergeData = currentData;
    NotifyNearlinkProtocolsChanged();
    return ERR_OK;
}

ErrCode DisallowedNearlinkProtocolsPlugin::OnRemovePolicy(
    std::vector<int32_t> &data, std::vector<int32_t> &currentData, std::vector<int32_t> &mergeData, int32_t userId)
{
    EDMLOGI("DisallowedNearlinkProtocolsPlugin OnRemovePolicy userId = %{public}d", userId);
    if (data.empty()) {
        EDMLOGE("DisallowedNearlinkProtocolsPlugin OnRemovePolicy data is empty");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    if (data.size() > EdmConstants::DEFAULT_LOOP_MAX_SIZE) {
        EDMLOGE("DisallowedNearlinkProtocolsPlugin OnRemovePolicy size is over limit");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    NearlinkConfigUtils nearlinkConfigUtils;
    for (size_t i = 0; i < data.size(); ++i) {
        std::string protocol;
        if (!NearlinkProtocolUtils::IntToProtocolStr(data[i], protocol)) {
            return EdmReturnErrCode::PARAM_ERROR;
        }
        if (!nearlinkConfigUtils.UpdateProtocol(std::to_string(userId), protocol, false)) {
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    currentData = data;
    mergeData = currentData;
    NotifyNearlinkProtocolsChanged();
    return ERR_OK;
}

ErrCode DisallowedNearlinkProtocolsPlugin::OnGetPolicy(
    std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId)
{
    EDMLOGI("DisallowedNearlinkProtocolsPlugin OnGetPolicy");
    std::vector<int32_t> protocols;
    NearlinkConfigUtils nearlinkConfigUtils;
    if (!nearlinkConfigUtils.QueryProtocols(std::to_string(userId), protocols)) {
        reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteInt32Vector(protocols);
    return ERR_OK;
}

ErrCode DisallowedNearlinkProtocolsPlugin::OnAdminRemove(
    const std::string &adminName, std::vector<int32_t> &policyData, std::vector<int32_t> &mergeData, int32_t userId)
{
    EDMLOGI("DisallowedNearlinkProtocolsPlugin OnAdminRemove");
    NearlinkConfigUtils nearlinkConfigUtils;
    if (!nearlinkConfigUtils.RemoveProtocolDenyList()) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    NotifyNearlinkProtocolsChanged();
    return ERR_OK;
}

void DisallowedNearlinkProtocolsPlugin::OnChangedPolicyDone(bool isGlobalChanged)
{
    if (!isGlobalChanged) {
        return;
    }
    NotifyNearlinkProtocolsChanged();
}

void DisallowedNearlinkProtocolsPlugin::NotifyNearlinkProtocolsChanged()
{
    EDMLOGD("DisallowedNearlinkProtocolsPlugin NotifyNearlinkProtocolsChanged.");
    AAFwk::Want want;
    want.SetAction(EdmConstants::EDM_CONFIG_CHANGED_EVENT);
    EventFwk::CommonEventData eventData;
    eventData.SetWant(want);
    EventFwk::CommonEventPublishInfo eventInfo;
    std::vector<int32_t> subscriberUids;
    subscriberUids.push_back(NEARLINK_UID);
    eventInfo.SetSubscriberUid(subscriberUids);
    if (!EventFwk::CommonEventManager::NewPublishCommonEvent(eventData, eventInfo)) {
        EDMLOGE("NotifyNearlinkProtocolsChanged failed.");
    }
}
}  // namespace EDM
}  // namespace OHOS
