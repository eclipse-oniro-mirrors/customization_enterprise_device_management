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

#include "disallowed_usb_devices_plugin.h"

#include <algorithm>
#include <system_ability_definition.h>
#include "array_usb_device_type_serializer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "usb_policy_utils.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisallowedUsbDevicesPlugin::GetPlugin());
constexpr int32_t USB_DEVICE_TYPE_BASE_CLASS_STORAGE = 8;

void DisallowedUsbDevicesPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<DisallowedUsbDevicesPlugin, std::vector<USB::UsbDeviceType>>> ptr)
{
    EDMLOGI("DisallowedUsbDevicesPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::DISALLOWED_USB_DEVICES, "disallowed_usb_devices",
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_USB, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(ArrayUsbDeviceTypeSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisallowedUsbDevicesPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnHandlePolicyListener(&DisallowedUsbDevicesPlugin::OnRemovePolicy, FuncOperateType::REMOVE);
    ptr->SetOnAdminRemoveListener(&DisallowedUsbDevicesPlugin::OnAdminRemove);
}

ErrCode DisallowedUsbDevicesPlugin::OnSetPolicy(std::vector<USB::UsbDeviceType> &data,
    std::vector<USB::UsbDeviceType> &currentData, std::vector<USB::UsbDeviceType> &mergeData, int32_t userId)
{
    EDMLOGI("AllowUsbDevicesPlugin OnSetPolicy userId = %{public}d", userId);
    if (data.empty()) {
        EDMLOGW("AllowUsbDevicesPlugin OnSetPolicy data is empty");
        return ERR_OK;
    }
    if (data.size() > EdmConstants::DISALLOWED_USB_DEVICES_TYPES_MAX_SIZE) {
        EDMLOGE("AllowUsbDevicesPlugin OnSetPolicy data size=[%{public}zu] is too large", data.size());
        return EdmReturnErrCode::PARAM_ERROR;
    }
    if (HasConflictPolicy()) {
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }

    std::vector<USB::UsbDeviceType> afterHandle =
        ArrayUsbDeviceTypeSerializer::GetInstance()->SetUnionPolicyData(currentData, data);
    std::vector<USB::UsbDeviceType> afterMerge =
        ArrayUsbDeviceTypeSerializer::GetInstance()->SetUnionPolicyData(mergeData, afterHandle);

    if (afterMerge.size() > EdmConstants::DISALLOWED_USB_DEVICES_TYPES_MAX_SIZE) {
        EDMLOGE("AllowUsbDevicesPlugin OnSetPolicy union data size=[%{public}zu] is too large", mergeData.size());
        return EdmReturnErrCode::PARAM_ERROR;
    }

    std::vector<USB::UsbDeviceType> disallowedUsbDeviceTypes;
    CombineDataWithStorageAccessPolicy(afterMerge, disallowedUsbDeviceTypes);
    ErrCode ret = UsbPolicyUtils::SetDisallowedUsbDevices(disallowedUsbDeviceTypes);
    if (ret != ERR_OK) {
        return ret;
    }
    currentData = afterHandle;
    mergeData = afterMerge;
    return ERR_OK;
}

ErrCode DisallowedUsbDevicesPlugin::OnRemovePolicy(std::vector<USB::UsbDeviceType> &data,
    std::vector<USB::UsbDeviceType> &currentData, std::vector<USB::UsbDeviceType> &mergeData, int32_t userId)
{
    EDMLOGD("DisallowedUsbDevicesPlugin OnRemovePolicy userId : %{public}d:", userId);
    if (data.empty()) {
        EDMLOGW("DisallowedUsbDevicesPlugin OnRemovePolicy data is empty:");
        return ERR_OK;
    }
    if (data.size() > EdmConstants::DISALLOWED_USB_DEVICES_TYPES_MAX_SIZE) {
        EDMLOGE("DisallowedUsbDevicesPlugin OnRemovePolicy input data is too large");
        return EdmReturnErrCode::PARAM_ERROR;
    }

    std::vector<USB::UsbDeviceType> afterHandle =
        ArrayUsbDeviceTypeSerializer::GetInstance()->SetDifferencePolicyData(data, currentData);
    std::vector<USB::UsbDeviceType> afterMerge =
        ArrayUsbDeviceTypeSerializer::GetInstance()->SetUnionPolicyData(mergeData, afterHandle);
    std::vector<USB::UsbDeviceType> disallowedUsbDeviceTypes;
    CombineDataWithStorageAccessPolicy(afterMerge, disallowedUsbDeviceTypes);
    ErrCode ret = ERR_OK;
    if (disallowedUsbDeviceTypes.empty() && !currentData.empty()) {
        ret = UsbPolicyUtils::SetUsbDisabled(false);
        if (ret != ERR_OK) {
            return ret;
        }
    }
    ret = UsbPolicyUtils::SetDisallowedUsbDevices(disallowedUsbDeviceTypes);
    if (ret != ERR_OK) {
        return ret;
    }
    currentData = afterHandle;
    mergeData = afterMerge;
    return ERR_OK;
}

bool DisallowedUsbDevicesPlugin::HasConflictPolicy()
{
    auto policyManager = IPolicyManager::GetInstance();
    std::string disableUsb;
    policyManager->GetPolicy("", "disable_usb", disableUsb);
    if (disableUsb == "true") {
        EDMLOGE("DisallowedUsbDevicesPlugin policy conflict! Usb is disabled.");
        return true;
    }
    std::string allowUsbDevice;
    policyManager->GetPolicy("", "allowed_usb_devices", allowUsbDevice);
    if (!allowUsbDevice.empty()) {
        EDMLOGE("DisallowedUsbDevicesPlugin policy conflict! AllowedUsbDevice: %{public}s", allowUsbDevice.c_str());
        return true;
    }
    return false;
}

void DisallowedUsbDevicesPlugin::CombineDataWithStorageAccessPolicy(std::vector<USB::UsbDeviceType> policyData,
    std::vector<USB::UsbDeviceType> &combineData)
{
    auto policyManager = IPolicyManager::GetInstance();
    std::string usbStoragePolicy;
    policyManager->GetPolicy("", "usb_read_only", usbStoragePolicy);
    std::vector<USB::UsbDeviceType> usbStorageTypes;
    if (usbStoragePolicy == std::to_string(EdmConstants::STORAGE_USB_POLICY_DISABLED)) {
        USB::UsbDeviceType storageType;
        storageType.baseClass = USB_DEVICE_TYPE_BASE_CLASS_STORAGE;
        storageType.subClass = USB_DEVICE_TYPE_BASE_CLASS_STORAGE;
        storageType.protocol = USB_DEVICE_TYPE_BASE_CLASS_STORAGE;
        storageType.isDeviceType = false;
        usbStorageTypes.emplace_back(storageType);
    }
    combineData = ArrayUsbDeviceTypeSerializer::GetInstance()->SetUnionPolicyData(policyData, usbStorageTypes);
}

ErrCode DisallowedUsbDevicesPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("DisallowedUsbDevicesPlugin OnGetPolicy: policyData: %{public}s", policyData.c_str());
    if (policyData.empty()) {
        EDMLOGW("DisallowedUsbDevicesPlugin OnGetPolicy data is empty:");
        reply.WriteInt32(ERR_OK);
        reply.WriteUint32(0);
        return ERR_OK;
    }
    std::vector<USB::UsbDeviceType> disallowedDevices;
    ArrayUsbDeviceTypeSerializer::GetInstance()->Deserialize(policyData, disallowedDevices);
    reply.WriteInt32(ERR_OK);
    reply.WriteUint32(disallowedDevices.size());
    for (const auto &usbDeviceType : disallowedDevices) {
        if (!usbDeviceType.Marshalling(reply)) {
            EDMLOGE("DisallowedUsbDevicesPlugin OnGetPolicy: write parcel failed!");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    return ERR_OK;
}

ErrCode DisallowedUsbDevicesPlugin::OnAdminRemove(const std::string &adminName, std::vector<USB::UsbDeviceType> &data,
    std::vector<USB::UsbDeviceType> &mergeData, int32_t userId)
{
    EDMLOGD("DisallowedUsbDevicesPlugin OnAdminRemove");
    std::vector<USB::UsbDeviceType> disallowedUsbDeviceTypes;
    CombineDataWithStorageAccessPolicy(mergeData, disallowedUsbDeviceTypes);
    if (disallowedUsbDeviceTypes.empty()) {
        return UsbPolicyUtils::SetUsbDisabled(false);
    }
    return UsbPolicyUtils::SetDisallowedUsbDevices(disallowedUsbDeviceTypes);
}
} // namespace EDM
} // namespace OHOS
