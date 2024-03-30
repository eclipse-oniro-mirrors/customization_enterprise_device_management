/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "allowed_bluetooth_devices_plugin.h"

#include "array_string_serializer.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "parameters.h"
#include "plugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(AllowedBluetoothDevicesPlugin::GetPlugin());
const char *const PERSIST_BLUETOOTH_CONTROL = "persist.edm.prohibit_bluetooth";
const char *const BLUETOOTH_WHITELIST_CHANGED_EVENT = "com.ohos.edm.bluetoothdeviceschanged";

void AllowedBluetoothDevicesPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<AllowedBluetoothDevicesPlugin, std::vector<std::string>>> ptr)

{
    EDMLOGI("AllowedBluetoothDevicesPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::ALLOWED_BLUETOOTH_DEVICES, "allowed_bluetooth_devices",
        "ohos.permission.ENTERPRISE_MANAGE_BLUETOOTH", IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(ArrayStringSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&AllowedBluetoothDevicesPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnHandlePolicyDoneListener(&AllowedBluetoothDevicesPlugin::OnChangedPolicyDone, FuncOperateType::SET);
    ptr->SetOnHandlePolicyListener(&AllowedBluetoothDevicesPlugin::OnRemovePolicy, FuncOperateType::REMOVE);
    ptr->SetOnHandlePolicyDoneListener(&AllowedBluetoothDevicesPlugin::OnChangedPolicyDone, FuncOperateType::REMOVE);
}

ErrCode AllowedBluetoothDevicesPlugin::OnSetPolicy(std::vector<std::string> &data,
    std::vector<std::string> &currentData, int32_t userId)
{
    EDMLOGI("AllowedBluetoothDevicesPlugin OnSetPolicy userId = %{public}d", userId);
    bool isDisabled = system::GetBoolParameter(PERSIST_BLUETOOTH_CONTROL, false);
    if (isDisabled) {
        EDMLOGE("AllowedBluetoothDevicesPlugin OnSetPolicy failed, because bluetooth disabled.");
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }
    if (data.empty()) {
        EDMLOGW("AllowedBluetoothDevicesPlugin OnSetPolicy data is empty.");
        return ERR_OK;
    }

    std::vector<std::string> mergeData = ArrayStringSerializer::GetInstance()->SetUnionPolicyData(data, currentData);
    if (mergeData.size() > EdmConstants::BLUETOOTH_WHITELIST_MAX_SIZE) {
        EDMLOGE("AllowedBluetoothDevicesPlugin OnSetPolicy data is too large.");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    currentData = mergeData;
    return ERR_OK;
}

ErrCode AllowedBluetoothDevicesPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("AllowedBluetoothDevicesPlugin OnGetPolicy policyData : %{public}s, userId : %{public}d",
        policyData.c_str(), userId);
    std::vector<std::string> deviceIds;
    pluginInstance_->serializer_->Deserialize(policyData, deviceIds);
    reply.WriteInt32(ERR_OK);
    reply.WriteInt32(deviceIds.size());
    reply.WriteStringVector(deviceIds);
    return ERR_OK;
}

ErrCode AllowedBluetoothDevicesPlugin::OnRemovePolicy(std::vector<std::string> &data,
    std::vector<std::string> &currentData, int32_t userId)
{
    EDMLOGD("AllowedBluetoothDevicesPlugin OnRemovePolicy userId : %{public}d:", userId);
    if (data.empty()) {
        EDMLOGW("AllowedBluetoothDevicesPlugin OnRemovePolicy data is empty.");
        return ERR_OK;
    }
    std::vector<std::string> mergeData =
        ArrayStringSerializer::GetInstance()->SetDifferencePolicyData(data, currentData);
    currentData = mergeData;
    return ERR_OK;
}

void AllowedBluetoothDevicesPlugin::OnChangedPolicyDone(bool isGlobalChanged)
{
    if (!isGlobalChanged) {
        return;
    }
    NotifyBluetoothDevicesChanged();
}

void AllowedBluetoothDevicesPlugin::NotifyBluetoothDevicesChanged()
{
    EDMLOGD("AllowedBluetoothDevicesPlugin NotifyBluetoothDevicesChanged.");
    AAFwk::Want want;
    want.SetAction(BLUETOOTH_WHITELIST_CHANGED_EVENT);
    EventFwk::CommonEventData eventData;
    eventData.SetWant(want);
    if (!EventFwk::CommonEventManager::PublishCommonEvent(eventData)) {
        EDMLOGE("NotifyBluetoothDevicesChanged failed.");
    }
}

} // namespace EDM
} // namespace OHOS