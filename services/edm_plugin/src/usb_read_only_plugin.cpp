/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "usb_read_only_plugin.h"

#include <algorithm>
#include "array_usb_device_type_serializer.h"
#include "int_serializer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_utils.h"
#include "iservice_registry.h"
#include "parameters.h"
#include "usb_policy_utils.h"
#include "usb_srv_client.h"
#include "volume_external.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<UsbReadOnlyPlugin>());
constexpr int32_t STORAGE_MANAGER_MANAGER_ID = 5003;
constexpr int32_t USB_DEVICE_TYPE_BASE_CLASS_STORAGE = 8;
const std::string PARAM_USB_READ_ONLY_KEY = "persist.filemanagement.usb.readonly";

UsbReadOnlyPlugin::UsbReadOnlyPlugin()
{
    policyCode_ = EdmInterfaceCode::USB_READ_ONLY;
    policyName_ = "usb_read_only";
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        "ohos.permission.ENTERPRISE_MANAGE_USB");
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = true;
}

ErrCode UsbReadOnlyPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    uint32_t typeCode = FUNC_TO_OPERATE(funcCode);
    FuncOperateType type = FuncCodeUtils::ConvertOperateType(typeCode);
    if (type == FuncOperateType::SET) {
        std::string beforeHandle = policyData.policyData;
        int32_t accessPolicy = data.ReadInt32();
        EDMLOGI("UsbReadOnlyPlugin OnHandlePolicy: %{public}d", accessPolicy);
        std::string afterHandle = std::to_string(accessPolicy);
        ErrCode ret = SetUsbStorageAccessPolicy(accessPolicy, userId);
        if (ret != ERR_OK) {
            return ret;
        }
        policyData.isChanged = afterHandle != beforeHandle;
        if (policyData.isChanged) {
            policyData.policyData = afterHandle;
        }
        return ERR_OK;
    }
    return EdmReturnErrCode::SYSTEM_ABNORMALLY;
}

ErrCode UsbReadOnlyPlugin::SetUsbStorageAccessPolicy(int32_t accessPolicy, int32_t userId)
{
    auto policyManager = IPolicyManager::GetInstance();
    std::string allowUsbDevicePolicy;
    policyManager->GetPolicy("", "allowed_usb_devices", allowUsbDevicePolicy);
    if (HasConflictPolicy(accessPolicy, allowUsbDevicePolicy)) {
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }
    std::vector<USB::UsbDeviceType> usbDeviceTypes;
    GetDisallowedUsbDeviceTypes(usbDeviceTypes);
    if (accessPolicy == EdmConstants::STORAGE_USB_POLICY_DISABLED) {
        return DealDisablePolicy(usbDeviceTypes);
    }
    return DealReadPolicy(accessPolicy, allowUsbDevicePolicy, usbDeviceTypes);
}

bool UsbReadOnlyPlugin::HasConflictPolicy(int32_t accessPolicy, const std::string &allowUsbDevice)
{
    if (accessPolicy == EdmConstants::STORAGE_USB_POLICY_DISABLED && !allowUsbDevice.empty()) {
        EDMLOGE("UsbReadOnlyPlugin policy conflict! AllowedUsbDevice: %{public}s", allowUsbDevice.c_str());
        return true;
    }
    if (IsStorageDisabledByDisallowedPolicy() &&
        (accessPolicy == EdmConstants::STORAGE_USB_POLICY_READ_WRITE ||
        accessPolicy == EdmConstants::STORAGE_USB_POLICY_READ_ONLY)) {
        EDMLOGE("UsbReadOnlyPlugin policy conflict! Storage is disabled by disallowed policy.");
        return true;
    }
    auto policyManager = IPolicyManager::GetInstance();
    std::string disableUsb;
    policyManager->GetPolicy("", "disable_usb", disableUsb);
    if (disableUsb == "true") {
        EDMLOGE("UsbReadOnlyPlugin policy conflict! Usb is disabled.");
        return true;
    }
    return false;
}

void UsbReadOnlyPlugin::GetDisallowedUsbDeviceTypes(std::vector<USB::UsbDeviceType> &usbDeviceTypes)
{
    auto policyManager = IPolicyManager::GetInstance();
    std::string disallowUsbDevicePolicy;
    policyManager->GetPolicy("", "disallowed_usb_devices", disallowUsbDevicePolicy);
    ArrayUsbDeviceTypeSerializer::GetInstance()->Deserialize(disallowUsbDevicePolicy, usbDeviceTypes);
    EDMLOGI("UsbReadOnlyPlugin GetDisallowedUsbDeviceTypes: size: %{public}zu", usbDeviceTypes.size());
}

ErrCode UsbReadOnlyPlugin::DealDisablePolicy(std::vector<USB::UsbDeviceType> usbDeviceTypes)
{
    USB::UsbDeviceType storageType;
    storageType.baseClass = USB_DEVICE_TYPE_BASE_CLASS_STORAGE;
    storageType.subClass = USB_DEVICE_TYPE_BASE_CLASS_STORAGE;
    storageType.protocol = USB_DEVICE_TYPE_BASE_CLASS_STORAGE;
    storageType.isDeviceType = false;
    std::vector<USB::UsbDeviceType> usbStorageTypes;
    usbStorageTypes.emplace_back(storageType);
    std::vector<USB::UsbDeviceType> disallowedUsbDeviceTypes =
        ArrayUsbDeviceTypeSerializer::GetInstance()->SetUnionPolicyData(usbDeviceTypes, usbStorageTypes);
    EDMLOGI("UsbReadOnlyPlugin OnHandlePolicy: ManageInterfaceType disallowed size: %{public}zu",
        disallowedUsbDeviceTypes.size());
    return UsbPolicyUtils::SetDisallowedUsbDevices(disallowedUsbDeviceTypes);
}

ErrCode UsbReadOnlyPlugin::DealReadPolicy(int32_t accessPolicy, const std::string &allowUsbDevice,
    std::vector<USB::UsbDeviceType> usbDeviceTypes)
{
    std::string usbValue = (accessPolicy == EdmConstants::STORAGE_USB_POLICY_READ_ONLY) ? "true" : "false";
    bool ret = OHOS::system::SetParameter(PARAM_USB_READ_ONLY_KEY, usbValue);
    if (!ret) {
        EDMLOGE("UsbReadOnlyPlugin OnHandlePolicy failed! readonly value: %{public}s", usbValue.c_str());
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }

    int32_t usbRet = ERR_OK;
    if (allowUsbDevice.empty()) {
        usbDeviceTypes.erase(std::remove_if(usbDeviceTypes.begin(), usbDeviceTypes.end(),
            [&](const auto usbDeviceType) { return usbDeviceType.baseClass == USB_DEVICE_TYPE_BASE_CLASS_STORAGE; }),
            usbDeviceTypes.end());
        EDMLOGI("UsbReadOnlyPlugin OnHandlePolicy: ManageInterfaceType disallowed size: %{public}zu",
            usbDeviceTypes.size());
        usbRet = USB::UsbSrvClient::GetInstance().ManageInterfaceType(usbDeviceTypes, true);
    }
    EDMLOGI("UsbReadOnlyPlugin OnHandlePolicy sysParam: readonly value:%{public}s  ret:%{public}d usbRet:%{public}d",
        usbValue.c_str(), ret, usbRet);
    if (usbRet == EdmConstants::USB_ERRCODE_INTERFACE_NO_INIT) {
        EDMLOGW("UsbReadOnlyPlugin OnHandlePolicy: ManageInterfaceType failed! USB interface not init!");
    }
    if (usbRet != ERR_OK && usbRet != EdmConstants::USB_ERRCODE_INTERFACE_NO_INIT) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    ErrCode reloadRet = ReloadUsbDevice();
    if (reloadRet != ERR_OK) {
        return reloadRet;
    }
    return ERR_OK;
}

OHOS::sptr<OHOS::StorageManager::IStorageManager> UsbReadOnlyPlugin::GetStorageManager()
{
    auto saMgr = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saMgr == nullptr) {
        EDMLOGE("UsbReadOnlyPlugin GetStorageManager:get saMgr fail");
        return nullptr;
    }
    sptr<IRemoteObject> obj = saMgr->GetSystemAbility(STORAGE_MANAGER_MANAGER_ID);
    if (obj == nullptr) {
        EDMLOGE("UsbReadOnlyPlugin GetStorageManager:get storage manager client fail");
        return nullptr;
    }
    auto storageMgrProxy = iface_cast<OHOS::StorageManager::IStorageManager>(obj);
    if (storageMgrProxy == nullptr) {
        EDMLOGE("UsbReadOnlyPlugin GetStorageManager:get storageMgrProxy fail");
    }
    return storageMgrProxy;
}

ErrCode UsbReadOnlyPlugin::ReloadUsbDevice()
{
    auto storageMgrProxy = GetStorageManager();
    if (storageMgrProxy == nullptr) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::vector<StorageManager::VolumeExternal> volList;
    int32_t storageRet = storageMgrProxy->GetAllVolumes(volList);
    if (storageRet != ERR_OK) {
        EDMLOGE("UsbReadOnlyPlugin SetPolicy storageMgrProxy GetAllVolumes failed! ret:%{public}d", storageRet);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (volList.empty()) {
        return ERR_OK;
    }
    for (auto &vol : volList) {
        if (storageMgrProxy->Unmount(vol.GetId()) != ERR_OK) {
            EDMLOGE("UsbReadOnlyPlugin SetPolicy storageMgrProxy Unmount failed!");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        if (storageMgrProxy->Mount(vol.GetId()) != ERR_OK) {
            EDMLOGE("UsbReadOnlyPlugin SetPolicy storageMgrProxy Mount failed!");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    return ERR_OK;
}

ErrCode UsbReadOnlyPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    return ERR_OK;
}

bool UsbReadOnlyPlugin::IsStorageDisabledByDisallowedPolicy()
{
    std::vector<USB::UsbDeviceType> usbDeviceTypes;
    GetDisallowedUsbDeviceTypes(usbDeviceTypes);
    return usbDeviceTypes.size() <= EdmConstants::DISALLOWED_USB_DEVICES_TYPES_MAX_SIZE &&
        (std::find_if(usbDeviceTypes.begin(), usbDeviceTypes.end(), [&](USB::UsbDeviceType disallowedType) {
            return disallowedType.baseClass == USB_DEVICE_TYPE_BASE_CLASS_STORAGE;
        }) != usbDeviceTypes.end());
}

ErrCode UsbReadOnlyPlugin::OnAdminRemove(const std::string &adminName, const std::string &policyData, int32_t userId)
{
    EDMLOGI("UsbReadOnlyPlugin OnAdminRemove adminName: %{public}s, userId: %{public}d, value: %{public}s",
        adminName.c_str(), userId, policyData.c_str());
    char* endptr;
    errno = 0;
    int32_t data = strtol(policyData.c_str(), &endptr, EdmConstants::DECIMAL);
    if (errno == ERANGE || endptr == policyData.c_str() || *endptr != '\0') {
        EDMLOGE("UsbReadOnlyPlugin strtol Error, policyData: %{public}s", policyData.c_str());
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (data == EdmConstants::STORAGE_USB_POLICY_DISABLED) {
        ErrCode disableUsbRet = UsbPolicyUtils::SetUsbDisabled(false);
        if (disableUsbRet != ERR_OK) {
            EDMLOGW("UsbReadOnlyPlugin OnAdminRemove SetUsbDisabled Error: %{public}d", disableUsbRet);
            return disableUsbRet;
        }
    }
    std::string usbValue = "false";
    bool ret = OHOS::system::SetParameter(PARAM_USB_READ_ONLY_KEY, usbValue);
    return ret ? ERR_OK : EdmReturnErrCode::SYSTEM_ABNORMALLY;
}
} // namespace EDM
} // namespace OHOS
