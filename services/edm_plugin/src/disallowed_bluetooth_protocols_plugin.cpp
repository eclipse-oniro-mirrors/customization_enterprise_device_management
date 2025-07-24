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

#include "disallowed_bluetooth_protocols_plugin.h"

#include "array_int_serializer.h"
#include "bluetooth_config_utils.h"
#include "bt_protocol_utils.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_os_account_manager_impl.h"
#include "func_code_utils.h"
#include "parameters.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisallowedBluetoothProtocolsPlugin::GetPlugin());

void DisallowedBluetoothProtocolsPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<DisallowedBluetoothProtocolsPlugin, std::vector<int32_t>>> ptr)
{
    EDMLOGI("DisallowedBluetoothProtocolsPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::DISALLOWED_BLUETOOTH_PROTOCOLS,
        PolicyName::POLICY_DISALLOWED_BLUETOOTH_PROTOCOLS, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_BLUETOOTH,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(ArrayIntSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisallowedBluetoothProtocolsPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnHandlePolicyDoneListener(&DisallowedBluetoothProtocolsPlugin::OnChangedPolicyDone, FuncOperateType::SET);
    ptr->SetOnHandlePolicyListener(&DisallowedBluetoothProtocolsPlugin::OnRemovePolicy, FuncOperateType::REMOVE);
    ptr->SetOnHandlePolicyDoneListener(&DisallowedBluetoothProtocolsPlugin::OnChangedPolicyDone,
        FuncOperateType::REMOVE);
    ptr->SetOnAdminRemoveListener(&DisallowedBluetoothProtocolsPlugin::OnAdminRemove);
}

ErrCode DisallowedBluetoothProtocolsPlugin::OnSetPolicy(std::vector<int32_t> &data, std::vector<int32_t> &currentData,
    std::vector<int32_t> &mergeData, int32_t userId)
{
    EDMLOGI("DisallowedBluetoothProtocolsPlugin OnSetPolicy");
    if (data.empty()) {
        EDMLOGE("DisallowedBluetoothProtocolsPlugin OnSetPolicy data is empty");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    if (data.size() > EdmConstants::DEFAULT_LOOP_MAX_SIZE) {
        EDMLOGE("DisallowedBluetoothProtocolsPlugin OnSetPolicy size is over limit");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    bool isExist = false;
    ErrCode ret = std::make_shared<EdmOsAccountManagerImpl>()->IsOsAccountExists(userId, isExist);
    if (FAILED(ret) || !isExist) {
        EDMLOGE("DisallowedBluetoothProtocolsPlugin OnSetPolicy userId is not exist");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::vector<int32_t> afterHandle = ArrayIntSerializer::GetInstance()->SetUnionPolicyData(data, currentData);
    std::vector<int32_t> afterMerge = ArrayIntSerializer::GetInstance()->SetUnionPolicyData(mergeData, afterHandle);
    BluetoothConfigUtils bluetoothConfigUtils;
    for (size_t i = 0; i < afterMerge.size(); ++i) {
        std::string protocol;
        if (!BtProtocolUtils::IntToProtocolStr(afterMerge[i], protocol)) {
            return EdmReturnErrCode::PARAM_ERROR;
        }
        if (!bluetoothConfigUtils.UpdateProtocol(std::to_string(userId), protocol, true)) {
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    currentData = afterHandle;
    mergeData = afterMerge;
    return ERR_OK;
}

ErrCode DisallowedBluetoothProtocolsPlugin::OnRemovePolicy(std::vector<int32_t> &data,
    std::vector<int32_t> &currentData, std::vector<int32_t> &mergeData, int32_t userId)
{
    EDMLOGI("DisallowedBluetoothProtocolsPlugin OnRemovePolicy");
    if (data.empty()) {
        EDMLOGE("DisallowedBluetoothProtocolsPlugin OnRemovePolicy data is empty");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    if (data.size() > EdmConstants::DEFAULT_LOOP_MAX_SIZE) {
        EDMLOGE("DisallowedBluetoothProtocolsPlugin OnRemovePolicy size is over limit");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::vector<int32_t> needRemovePolicy =
        ArrayIntSerializer::GetInstance()->SetIntersectionPolicyData(data, currentData);
    std::vector<int32_t> afterHandle =
        ArrayIntSerializer::GetInstance()->SetDifferencePolicyData(needRemovePolicy, currentData);
    std::vector<int32_t> afterMerge = ArrayIntSerializer::GetInstance()->SetUnionPolicyData(mergeData, afterHandle);
    BluetoothConfigUtils bluetoothConfigUtils;
    if (!bluetoothConfigUtils.RemoveUserIdItem(std::to_string(userId))) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    for (size_t i = 0; i < afterMerge.size(); ++i) {
        std::string protocol;
        if (!BtProtocolUtils::IntToProtocolStr(afterMerge[i], protocol)) {
            return EdmReturnErrCode::PARAM_ERROR;
        }
        if (!bluetoothConfigUtils.UpdateProtocol(std::to_string(userId), protocol, true)) {
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    currentData = afterHandle;
    mergeData = afterMerge;
    return ERR_OK;
}

ErrCode DisallowedBluetoothProtocolsPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data,
    MessageParcel &reply, int32_t userId)
{
    EDMLOGI("DisallowedBluetoothProtocolsPlugin OnGetPolicy");
    std::vector<int32_t> protocols;
    BluetoothConfigUtils bluetoothConfigUtils;
    if (!bluetoothConfigUtils.QueryProtocols(std::to_string(userId), protocols)) {
        reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteInt32Vector(protocols);
    return ERR_OK;
}

ErrCode DisallowedBluetoothProtocolsPlugin::OnAdminRemove(const std::string &adminName,
    std::vector<int32_t> &policyData, std::vector<int32_t> &mergeData, int32_t userId)
{
    EDMLOGI("DisallowedBluetoothProtocolsPlugin OnAdminRemove");
    BluetoothConfigUtils bluetoothConfigUtils;
    if (!bluetoothConfigUtils.RemoveUserIdItem(std::to_string(userId))) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    for (size_t i = 0; i < mergeData.size(); ++i) {
        std::string protocol;
        if (!BtProtocolUtils::IntToProtocolStr(mergeData[i], protocol)) {
            return EdmReturnErrCode::PARAM_ERROR;
        }
        if (!bluetoothConfigUtils.UpdateProtocol(std::to_string(userId), protocol, true)) {
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    NotifyBluetoothProtocolsChanged();
    return ERR_OK;
}

void DisallowedBluetoothProtocolsPlugin::OnChangedPolicyDone(bool isGlobalChanged)
{
    if (!isGlobalChanged) {
        return;
    }
    NotifyBluetoothProtocolsChanged();
}

void DisallowedBluetoothProtocolsPlugin::NotifyBluetoothProtocolsChanged()
{
    EDMLOGI("DisallowedBluetoothProtocolsPlugin NotifyBluetoothProtocolsChanged.");
    AAFwk::Want want;
    want.SetAction(EdmConstants::EDM_CONFIG_CHANGED_EVENT);
    EventFwk::CommonEventData eventData;
    eventData.SetWant(want);
    int32_t bluetoothUid = 1002;
    EventFwk::CommonEventPublishInfo eventInfo;
    std::vector<int32_t> subscriberUids;
    subscriberUids.push_back(bluetoothUid);
    eventInfo.SetSubscriberUid(subscriberUids);
    if (!EventFwk::CommonEventManager::PublishCommonEvent(eventData, eventInfo)) {
        EDMLOGE("NotifyBluetoothProtocolsChanged failed.");
    }
}
} // namespace EDM
} // namespace OHOS