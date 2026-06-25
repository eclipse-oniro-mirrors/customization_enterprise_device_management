/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "disallowed_usb_devices_plugin_base.h"

#include <algorithm>
#include <system_ability_definition.h>
#include "edm_constants.h"
#include "ipolicy_manager.h"
#include "usb_policy_utils.h"

namespace OHOS {
namespace EDM {
constexpr int32_t USB_DEVICE_TYPE_BASE_CLASS_STORAGE = 8;

ErrCode DisallowedUsbDevicesPluginBase::OnSetPolicy(std::vector<USB::UsbDeviceType> &data,
    std::vector<USB::UsbDeviceType> &currentData, std::vector<USB::UsbDeviceType> &mergeData, int32_t userId)
{
    EDMLOGI("%{public}s OnSetPolicy", GetPluginName().c_str());
    if (data.empty()) {
        EDMLOGW("%{public}s OnSetPolicy data is empty", GetPluginName().c_str());
        return ERR_OK;
    }
    if (data.size() > GetDisallowedUsbDevicesTypeMaxSize()) {
        EDMLOGE("%{public}s OnSetPolicy data size=[%{public}zu] is too large", GetPluginName().c_str(), data.size());
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    bool hasConflict = false;
#ifdef FEATURE_PC_ONLY
    if (FAILED(HasConflictPolicy(hasConflict, data))) {
#else
    std::vector<USB::UsbDeviceType> emptyData;
    if (FAILED(HasConflictPolicy(hasConflict, emptyData))) {
#endif
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    if (hasConflict) {
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }

    std::vector<USB::UsbDeviceType> afterHandle =
        GetSerializer()->SetUnionPolicyData(currentData, data);
    std::vector<USB::UsbDeviceType> afterMerge =
        GetSerializer()->SetUnionPolicyData(mergeData, afterHandle);

    if (afterMerge.size() > GetDisallowedUsbDevicesTypeMaxSize()) {
        EDMLOGE("%{public}s OnSetPolicy union data size=[%{public}zu] is too large",
            GetPluginName().c_str(), mergeData.size());
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }

    std::vector<USB::UsbDeviceType> disallowedUsbDeviceTypes;
    CombineDataWithStorageAccessPolicy(afterMerge, disallowedUsbDeviceTypes);
    ErrCode ret = SetDisallowedDevices(disallowedUsbDeviceTypes);
    if (ret != ERR_OK) {
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    currentData = afterHandle;
    mergeData = afterMerge;
    return ERR_OK;
}

ErrCode DisallowedUsbDevicesPluginBase::OnRemovePolicy(std::vector<USB::UsbDeviceType> &data,
    std::vector<USB::UsbDeviceType> &currentData, std::vector<USB::UsbDeviceType> &mergeData, int32_t userId)
{
    EDMLOGI("%{public}s OnRemovePolicy", GetPluginName().c_str());
    if (data.empty()) {
        EDMLOGW("%{public}s OnRemovePolicy data is empty:", GetPluginName().c_str());
        return ERR_OK;
    }
    if (data.size() > GetDisallowedUsbDevicesTypeMaxSize()) {
        EDMLOGE("%{public}s OnRemovePolicy input data is too large", GetPluginName().c_str());
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }

    std::vector<USB::UsbDeviceType> afterHandle =
        GetSerializer()->SetDifferencePolicyData(data, currentData);
    std::vector<USB::UsbDeviceType> afterMerge =
        GetSerializer()->SetUnionPolicyData(mergeData, afterHandle);
    std::vector<USB::UsbDeviceType> disallowedUsbDeviceTypes;
    CombineDataWithStorageAccessPolicy(afterMerge, disallowedUsbDeviceTypes);

    ErrCode ret = ERR_OK;
    if (disallowedUsbDeviceTypes.empty() && !currentData.empty()) {
        ret = UsbPolicyUtils::SetUsbDisabled(false);
        if (ret != ERR_OK) {
            return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
        }
    }
    ret = SetDisallowedDevices(disallowedUsbDeviceTypes);
    if (ret != ERR_OK) {
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    currentData = afterHandle;
    mergeData = afterMerge;
    return ERR_OK;
}

ErrCode DisallowedUsbDevicesPluginBase::OnBaseGetPolicy(std::string &policyData, MessageParcel &data,
    MessageParcel &reply, int32_t userId)
{
    EDMLOGI("%{public}s OnBaseGetPolicy: policyData: %{public}s", GetPluginName().c_str(), policyData.c_str());
    if (policyData.empty()) {
        EDMLOGW("%{public}s OnBaseGetPolicy data is empty:", GetPluginName().c_str());
        reply.WriteInt32(ERR_OK);
        reply.WriteUint32(0);
        return ERR_OK;
    }
    std::vector<USB::UsbDeviceType> disallowedDevices;
    GetSerializer()->Deserialize(policyData, disallowedDevices);
    reply.WriteInt32(ERR_OK);
    reply.WriteUint32(disallowedDevices.size());
    for (const auto &usbDeviceType : disallowedDevices) {
        if (!usbDeviceType.Marshalling(reply)) {
            EDMLOGE("%{public}s OnBaseGetPolicy: write parcel failed!", GetPluginName().c_str());
            return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
        }
    }
    return ERR_OK;
}

ErrCode DisallowedUsbDevicesPluginBase::OnAdminRemove(const std::string &adminName,
    std::vector<USB::UsbDeviceType> &data, std::vector<USB::UsbDeviceType> &mergeData, int32_t userId)
{
    EDMLOGD("%{public}s OnAdminRemove", GetPluginName().c_str());
    std::vector<USB::UsbDeviceType> disallowedUsbDeviceTypes;
    CombineDataWithStorageAccessPolicy(mergeData, disallowedUsbDeviceTypes);
    if (disallowedUsbDeviceTypes.empty()) {
        return UsbPolicyUtils::SetUsbDisabled(false);
    }
    return SetDisallowedDevices(disallowedUsbDeviceTypes);
}

void DisallowedUsbDevicesPluginBase::OnOtherServiceStart(int32_t systemAbilityId)
{
    std::string disallowUsbDevicePolicy;
    IPolicyManager::GetInstance()->GetPolicy("", GetPolicyName(),
        disallowUsbDevicePolicy, EdmConstants::DEFAULT_USER_ID);
    std::vector<USB::UsbDeviceType> disallowedDevices;
    GetSerializer()->Deserialize(disallowUsbDevicePolicy, disallowedDevices);
#ifdef USB_DISK_MANAGER_EDM_ENABLE
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
        ErrCode disallowedUsbRet = SetDisallowedDevices(disallowedDevices);
        if (disallowedUsbRet != ERR_OK) {
            EDMLOGW("SetDisallowedUsbDevices Error: %{public}d", disallowedUsbRet);
        }
    }
}

void DisallowedUsbDevicesPluginBase::CombineDataWithStorageAccessPolicy(std::vector<USB::UsbDeviceType> policyData,
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
    combineData = GetSerializer()->SetUnionPolicyData(policyData, usbStorageTypes);
}

ErrCode DisallowedUsbDevicesPluginBase::HasConflictPolicy(bool &hasConflict,
    std::vector<USB::UsbDeviceType> &usbDeviceTypes)
{
    auto policyManager = IPolicyManager::GetInstance();
    std::string disableUsb;
    policyManager->GetPolicy("", PolicyName::POLICY_DISABLE_USB, disableUsb);
    if (disableUsb == "true") {
        EDMLOGE("%{public}s policy conflict! Usb is disabled.", GetPluginName().c_str());
        hasConflict = true;
        return ERR_OK;
    }
    std::string allowUsbDevice;
    policyManager->GetPolicy("", PolicyName::POLICY_ALLOWED_USB_DEVICES, allowUsbDevice);
    if (!allowUsbDevice.empty()) {
        EDMLOGE("%{public}s policy conflict! AllowedUsbDevice: %{public}s",
            GetPluginName().c_str(), allowUsbDevice.c_str());
        hasConflict = true;
        return ERR_OK;
    }
    std::string conflictPolicy;
    policyManager->GetPolicy("", GetConflictPolicyName(), conflictPolicy);
    if (!conflictPolicy.empty()) {
        EDMLOGE("%{public}s policy conflict! ConflictPolicy: %{public}s",
            GetPluginName().c_str(), conflictPolicy.c_str());
        hasConflict = true;
        return ERR_OK;
    }
#ifdef FEATURE_PC_ONLY
    bool isDisallowed = false;
    if (FAILED(UsbPolicyUtils::IsUsbStorageDeviceWriteDisallowed(isDisallowed))) {
        EDMLOGE("%{public}s HasConflictPolicy, IsUsbStorageDeviceWriteDisallowed failed", GetPluginName().c_str());
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    bool IsUsbStorageDeviceDisallowed =
        std::find_if(usbDeviceTypes.begin(), usbDeviceTypes.end(), [&](USB::UsbDeviceType disallowedType) {
            return disallowedType.baseClass == USB_DEVICE_TYPE_BASE_CLASS_STORAGE;
        }) != usbDeviceTypes.end();
    if (isDisallowed && IsUsbStorageDeviceDisallowed) {
        EDMLOGE("%{public}s policy conflict! usbStorageDeviceWrite and usbStorageDevice disallowed",
            GetPluginName().c_str());
        hasConflict = true;
        return ERR_OK;
    }
#endif
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
