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

#include "disallowed_bluetooth_devices_plugin.h"

#include "array_string_serializer.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "parameters.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisallowedBluetoothDevicesPlugin::GetPlugin());
const char *const PERSIST_BLUETOOTH_CONTROL = "persist.edm.prohibit_bluetooth";
const char *const BLUETOOTH_DISALLOWED_LIST_CHANGED_EVENT = "com.ohos.edm.disallowedbluetoothdeviceschanged";

void DisallowedBluetoothDevicesPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<DisallowedBluetoothDevicesPlugin, std::vector<std::string>>> ptr)
{
    EDMLOGI("DisallowedBluetoothDevicesPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::DISALLOWED_BLUETOOTH_DEVICES, PolicyName::POLICY_DISALLOWED_BLUETOOTH_DEVICES,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_BLUETOOTH, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(ArrayStringSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisallowedBluetoothDevicesPlugin::OnBasicSetPolicy, FuncOperateType::SET);
    ptr->SetOnHandlePolicyDoneListener(&DisallowedBluetoothDevicesPlugin::OnChangedPolicyDone, FuncOperateType::SET);
    ptr->SetOnHandlePolicyListener(&DisallowedBluetoothDevicesPlugin::OnBasicRemovePolicy, FuncOperateType::REMOVE);
    ptr->SetOnHandlePolicyDoneListener(&DisallowedBluetoothDevicesPlugin::OnChangedPolicyDone,
        FuncOperateType::REMOVE);
    ptr->SetOnAdminRemoveDoneListener(&DisallowedBluetoothDevicesPlugin::OnAdminRemoveDone);
    maxListSize_ = EdmConstants::BLUETOOTH_LIST_MAX_SIZE;
}

ErrCode DisallowedBluetoothDevicesPlugin::SetOtherModulePolicy(const std::vector<std::string> &data, int32_t userId,
    std::vector<std::string> &failedData)
{
    EDMLOGI("DisallowedBluetoothDevicesPlugin OnSetPolicy");
    bool isDisabled = system::GetBoolParameter(PERSIST_BLUETOOTH_CONTROL, false);
    if (isDisabled) {
        EDMLOGE("DisallowedBluetoothDevicesPlugin OnSetPolicy failed, because bluetooth disabled.");
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }
    auto policyManager = IPolicyManager::GetInstance();
    std::string bluetoothDevicesPolicy;
    policyManager->GetPolicy("", PolicyName::POLICY_ALLOWED_BLUETOOTH_DEVICES, bluetoothDevicesPolicy);
    if (!bluetoothDevicesPolicy.empty()) {
        EDMLOGE("bluetoothDevices policy conflict! Has another bluetoothDevicesPolicy");
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }
    return ERR_OK;
}

void DisallowedBluetoothDevicesPlugin::OnChangedPolicyDone(bool isGlobalChanged)
{
    if (!isGlobalChanged) {
        return;
    }
    NotifyBluetoothDevicesChanged();
}

void DisallowedBluetoothDevicesPlugin::NotifyBluetoothDevicesChanged()
{
    EDMLOGD("DisallowedBluetoothDevicesPlugin NotifyBluetoothDevicesChanged.");
    AAFwk::Want want;
    want.SetAction(BLUETOOTH_DISALLOWED_LIST_CHANGED_EVENT);
    EventFwk::CommonEventData eventData;
    eventData.SetWant(want);
    if (!EventFwk::CommonEventManager::PublishCommonEvent(eventData)) {
        EDMLOGE("NotifyBluetoothDevicesChanged failed.");
    }
}

void DisallowedBluetoothDevicesPlugin::OnAdminRemoveDone()
{
    EDMLOGI("DisallowedBluetoothDevicesPlugin OnAdminRemoveDone NotifyBluetoothDevicesChanged.");
    NotifyBluetoothDevicesChanged();
}

} // namespace EDM
} // namespace OHOS