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
    ptr->InitAttribute(EdmInterfaceCode::DISALLOWED_USB_DEVICES, PolicyName::POLICY_DISALLOWED_USB_DEVICES,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_USB, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(ArrayUsbDeviceTypeSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisallowedUsbDevicesPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnHandlePolicyListener(&DisallowedUsbDevicesPlugin::OnRemovePolicy, FuncOperateType::REMOVE);
    ptr->SetOnAdminRemoveListener(&DisallowedUsbDevicesPlugin::OnAdminRemove);
    ptr->SetOtherServiceStartListener(&DisallowedUsbDevicesPlugin::OnOtherServiceStart);
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
    bool hasConflict = false;
#ifdef FEATURE_PC_ONLY
    if (FAILED(HasConflictPolicy(hasConflict, data))) {
#else
    std::vector<USB::UsbDeviceType> emptyData;
    if (FAILED(HasConflictPolicy(hasConflict, emptyData))) {
#endif
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (hasConflict) {
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

ErrCode DisallowedUsbDevicesPlugin::HasConflictPolicy(bool &hasConflict,
    std::vector<USB::UsbDeviceType> &usbDeviceTypes)
{
    auto policyManager = IPolicyManager::GetInstance();
    std::string disableUsb;
    policyManager->GetPolicy("", PolicyName::POLICY_DISABLE_USB, disableUsb);
    if (disableUsb == "true") {
        EDMLOGE("DisallowedUsbDevicesPlugin policy conflict! Usb is disabled.");
        hasConflict = true;
        return ERR_OK;
    }
    std::string allowUsbDevice;
    policyManager->GetPolicy("", PolicyName::POLICY_ALLOWED_USB_DEVICES, allowUsbDevice);
    if (!allowUsbDevice.empty()) {
        EDMLOGE("DisallowedUsbDevicesPlugin policy conflict! AllowedUsbDevice: %{public}s", allowUsbDevice.c_str());
        hasConflict = true;
        return ERR_OK;
    }
#ifdef FEATURE_PC_ONLY
    bool isDisallowed = false;
    if (FAILED(UsbPolicyUtils::IsUsbStorageDeviceWriteDisallowed(isDisallowed))) {
        EDMLOGE("DisallowedUsbDevicesPlugin HasConflictPolicy, IsUsbStorageDeviceWriteDisallowed failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    bool IsUsbStorageDeviceDisallowed =
        std::find_if(usbDeviceTypes.begin(), usbDeviceTypes.end(), [&](USB::UsbDeviceType disallowedType) {
            return disallowedType.baseClass == USB_DEVICE_TYPE_BASE_CLASS_STORAGE;
        }) != usbDeviceTypes.end();
    if (isDisallowed && IsUsbStorageDeviceDisallowed) {
        EDMLOGE("DisallowedUsbDevicesPlugin policy conflict! usbStorageDeviceWrite and usbStorageDevice disallowed");
        hasConflict = true;
        return ERR_OK;
    }
#endif
    return ERR_OK;
}

void DisallowedUsbDevicesPlugin::CombineDataWithStorageAccessPolicy(std::vector<USB::UsbDeviceType> policyData,
    std::vector<USB::UsbDeviceType> &combineData)
{
    auto policyManager = IPolicyManager::GetInstance();
    std::string usbStoragePolicy;
    policyManager->GetPolicy("", PolicyName::POLICY_USB_READ_ONLY, usbStoragePolicy);
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

void DisallowedUsbDevicesPlugin::OnOtherServiceStart(int32_t systemAbilityId)
{
    std::string disallowUsbDevicePolicy;
    IPolicyManager::GetInstance()->GetPolicy("", PolicyName::POLICY_DISALLOWED_USB_DEVICES, disallowUsbDevicePolicy,
        EdmConstants::DEFAULT_USER_ID);
    std::vector<USB::UsbDeviceType> disallowedDevices;
    ArrayUsbDeviceTypeSerializer::GetInstance()->Deserialize(disallowUsbDevicePolicy, disallowedDevices);
#ifdef USB_STORAGE_SERVICE_EDM_ENABLE
    std::string usbStoragePolicy;
    IPolicyManager::GetInstance()->GetPolicy("", PolicyName::POLICY_USB_READ_ONLY,
        usbStoragePolicy, EdmConstants::DEFAULT_USER_ID);
    if (usbStoragePolicy == std::to_string(EdmConstants::STORAGE_USB_POLICY_DISABLED)) {
        USB::UsbDeviceType storageType;
        storageType.baseClass = USB_DEVICE_TYPE_BASE_CLASS_STORAGE;
        storageType.subClass = USB_DEVICE_TYPE_BASE_CLASS_STORAGE;
        storageType.protocol = USB_DEVICE_TYPE_BASE_CLASS_STORAGE;
        storageType.isDeviceType = false;
        disallowedDevices.emplace_back(storageType);
    }
#endif
    if (!disallowedDevices.empty()) {
        ErrCode disallowedUsbRet = UsbPolicyUtils::SetDisallowedUsbDevices(disallowedDevices);
        if (disallowedUsbRet != ERR_OK) {
            EDMLOGW("SetDisallowedUsbDevices Error: %{public}d", disallowedUsbRet);
        }
    }
}
} // namespace EDM
} // namespace OHOS
