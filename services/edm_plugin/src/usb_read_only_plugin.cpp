/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "int_serializer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_utils.h"
#include "iservice_registry.h"
#include "parameters.h"
#include "usb_srv_client.h"
#include "volume_external.h"
#include "plugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(UsbReadOnlyPlugin::GetPlugin());
constexpr int32_t STORAGE_MANAGER_MANAGER_ID = 5003;

void UsbReadOnlyPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<UsbReadOnlyPlugin, int32_t>> ptr)
{
    EDMLOGI("UsbReadOnlyPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::USB_READ_ONLY, "usb_read_only", "ohos.permission.ENTERPRISE_MANAGE_USB",
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(IntSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&UsbReadOnlyPlugin::SetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&UsbReadOnlyPlugin::OnAdminRemove);
}

ErrCode UsbReadOnlyPlugin::SetPolicy(int32_t &policyValue)
{
    EDMLOGI("UsbReadOnlyPlugin SetPolicy: %{public}d", policyValue);
    auto &srvClient = OHOS::USB::UsbSrvClient::GetInstance();
    auto policyManager = IPolicyManager::GetInstance();
    std::string disableUsbPolicy;
    policyManager->GetPolicy("", "disable_usb", disableUsbPolicy);
    std::string allowUsbDevicePolicy;
    policyManager->GetPolicy("", "allowed_usb_devices", allowUsbDevicePolicy);
    if (disableUsbPolicy == "true") {
        EDMLOGE("OnSetPolicy: CONFLICT! isUsbDisabled: %{public}s", disableUsbPolicy.c_str());
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }
    if (policyValue == EdmConstants::STORAGE_USB_POLICY_DISABLED) {
        if (!allowUsbDevicePolicy.empty()) {
            EDMLOGE("OnSetPolicy: CONFLICT! allowedUsbDevice: %{public}s", allowUsbDevicePolicy.c_str());
            return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
        }
        int32_t usbRet = srvClient.ManageInterfaceType(OHOS::USB::InterfaceType::TYPE_STORAGE, true);
        if (usbRet != ERR_OK) {
            EDMLOGE("UsbReadOnlyPlugin SetPolicy: ManageInterfaceType failed! ret:%{public}d", usbRet);
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        return ERR_OK;
    }
    std::string usbKey = "persist.filemanagement.usb.readonly";
    std::string usbValue = (policyValue == EdmConstants::STORAGE_USB_POLICY_READ_ONLY) ? "true" : "false";
    bool ret = OHOS::system::SetParameter(usbKey, usbValue);
    int32_t usbRet = ERR_OK;
    if (allowUsbDevicePolicy.empty()) {
        usbRet = srvClient.ManageInterfaceType(OHOS::USB::InterfaceType::TYPE_STORAGE, false);
    }
    EDMLOGI("UsbReadOnlyPlugin SetPolicy sysParam: readonly value:%{public}s  ret:%{public}d usbRet:%{public}d",
        usbValue.c_str(), ret, usbRet);
    return (ret && usbRet == ERR_OK) ? ReloadUsbDevice() : EdmReturnErrCode::SYSTEM_ABNORMALLY;
}

ErrCode UsbReadOnlyPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("UsbReadOnlyPlugin OnGetPolicy: %{public}s", policyData.c_str());
    policyData = policyData.empty() ? "0" : policyData;
    int32_t result = EdmConstants::STORAGE_USB_POLICY_READ_ONLY;
    ErrCode parseRet = EdmUtils::ParseStringToInt(policyData, result);
    if (FAILED(parseRet)) {
        reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteInt32(result);
    return ERR_OK;
}

ErrCode UsbReadOnlyPlugin::OnAdminRemove(const std::string &adminName, int32_t &data, int32_t userId)
{
    EDMLOGI("UsbReadOnlyPlugin OnAdminRemove adminName: %{public}s, userId: %{public}d, value: %{public}d",
        adminName.c_str(), userId, data);
    if (data == EdmConstants::STORAGE_USB_POLICY_DISABLED) {
        auto &srvClient = OHOS::USB::UsbSrvClient::GetInstance();
        int32_t usbRet = srvClient.ManageInterfaceType(OHOS::USB::InterfaceType::TYPE_STORAGE, false);
        if (usbRet != ERR_OK) {
            EDMLOGE("UsbReadOnlyPlugin OnAdminRemove: ManageInterfaceType failed! ret:%{public}d", usbRet);
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        return ERR_OK;
    }
    std::string usbKey = "persist.filemanagement.usb.readonly";
    std::string usbValue = "false";
    bool ret = OHOS::system::SetParameter(usbKey, usbValue);
    return ret ? ERR_OK : EdmReturnErrCode::SYSTEM_ABNORMALLY;
}

OHOS::sptr<OHOS::StorageManager::IStorageManager> UsbReadOnlyPlugin::GetStorageManager()
{
    auto samgr = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        EDMLOGE("UsbReadOnlyPlugin GetStorageManager:get samgr fail");
        return nullptr;
    }
    sptr<IRemoteObject> obj = samgr->GetSystemAbility(STORAGE_MANAGER_MANAGER_ID);
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
} // namespace EDM
} // namespace OHOS
