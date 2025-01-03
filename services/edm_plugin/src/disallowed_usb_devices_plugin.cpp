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
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<DisallowedUsbDevicesPlugin>());
constexpr int32_t USB_DEVICE_TYPE_BASE_CLASS_STORAGE = 8;

DisallowedUsbDevicesPlugin::DisallowedUsbDevicesPlugin()
{
    policyCode_ = EdmInterfaceCode::DISALLOWED_USB_DEVICES;
    policyName_ = "disallowed_usb_devices";
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        "ohos.permission.ENTERPRISE_MANAGE_USB");
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = true;
}

ErrCode DisallowedUsbDevicesPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    uint32_t typeCode = FUNC_TO_OPERATE(funcCode);
    FuncOperateType type = FuncCodeUtils::ConvertOperateType(typeCode);
    EDMLOGI("DisallowedUsbDevicesPlugin OnHandlePolicy: type: %{public}u", static_cast<uint32_t>(type));
    if (type != FuncOperateType::SET && type != FuncOperateType::REMOVE) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (HasConflictPolicy(type)) {
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }
    auto serializer_ = ArrayUsbDeviceTypeSerializer::GetInstance();
    std::string beforeHandle = policyData.policyData;
    std::vector<USB::UsbDeviceType> beforeDevices;
    serializer_->Deserialize(beforeHandle, beforeDevices);
    std::vector<USB::UsbDeviceType> policyDevices;
    if (!serializer_->GetPolicy(data, policyDevices)) {
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::vector<USB::UsbDeviceType> mergeData;
    if (!CombinePolicyDataAndBeforeData(type, policyDevices, beforeDevices, mergeData)) {
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::vector<USB::UsbDeviceType> disallowedUsbDeviceTypes;
    CombineDataWithStorageAccessPolicy(mergeData, disallowedUsbDeviceTypes);
    ErrCode ret = ERR_OK;
    if (disallowedUsbDeviceTypes.empty() && !beforeDevices.empty()) {
        ret = UsbPolicyUtils::SetUsbDisabled(false);
        if (ret != ERR_OK) {
            return ret;
        }
    }
    ret = UsbPolicyUtils::SetDisallowedUsbDevices(disallowedUsbDeviceTypes);
    if (ret != ERR_OK) {
        return ret;
    }
    std::string afterHandle;
    serializer_->Serialize(mergeData, afterHandle);
    policyData.isChanged = afterHandle != beforeHandle;
    if (policyData.isChanged) {
        policyData.policyData = afterHandle;
    }
    return ERR_OK;
}

bool DisallowedUsbDevicesPlugin::HasConflictPolicy(const FuncOperateType type)
{
    if (type != FuncOperateType::SET) {
        return false;
    }
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

bool DisallowedUsbDevicesPlugin::CombinePolicyDataAndBeforeData(const FuncOperateType type,
    std::vector<USB::UsbDeviceType> policyDevices, std::vector<USB::UsbDeviceType> beforeDevices,
    std::vector<USB::UsbDeviceType> &mergeDevices)
{
    auto serializer_ = ArrayUsbDeviceTypeSerializer::GetInstance();
    if (type == FuncOperateType::SET) {
        mergeDevices = serializer_->SetUnionPolicyData(policyDevices, beforeDevices);
    } else {
        mergeDevices = serializer_->SetDifferencePolicyData(policyDevices, beforeDevices);
    }
    if (mergeDevices.size() > EdmConstants::DISALLOWED_USB_DEVICES_TYPES_MAX_SIZE) {
        EDMLOGE("DisallowedUsbDevicesPlugin: OnHandlePolicy union data size=[%{public}zu] is too large",
            mergeDevices.size());
        return false;
    }
    return true;
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
    auto serializer_ = ArrayUsbDeviceTypeSerializer::GetInstance();
    std::vector<USB::UsbDeviceType> disallowedDevices;
    serializer_->Deserialize(policyData, disallowedDevices);
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

ErrCode DisallowedUsbDevicesPlugin::OnAdminRemove(const std::string &adminName, const std::string &policyData,
    int32_t userId)
{
    EDMLOGD("DisallowedUsbDevicesPlugin OnAdminRemove");
    if (policyData.empty()) {
        EDMLOGW("DisallowedUsbDevicesPlugin OnRemovePolicy data is empty:");
        return ERR_OK;
    }
    return UsbPolicyUtils::SetUsbDisabled(false);
}
} // namespace EDM
} // namespace OHOS
