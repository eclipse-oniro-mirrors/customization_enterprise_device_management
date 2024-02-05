/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "allowed_usb_devices_plugin.h"

#include <algorithm>
#include <system_ability_definition.h>
#include "array_usb_device_id_serializer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_sys_manager.h"
#include "edm_utils.h"
#include "usb_device.h"
#include "usb_device_id.h"
#include "usb_srv_client.h"
#include "plugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(AllowUsbDevicesPlugin::GetPlugin());

void AllowUsbDevicesPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<AllowUsbDevicesPlugin, std::vector<UsbDeviceId>>> ptr)
{
    EDMLOGI("AllowUsbDevicesPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::ALLOWED_USB_DEVICES, "allowed_usb_devices",
        "ohos.permission.ENTERPRISE_MANAGE_USB", IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(ArrayUsbDeviceIdSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&AllowUsbDevicesPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnHandlePolicyListener(&AllowUsbDevicesPlugin::OnRemovePolicy, FuncOperateType::REMOVE);
    ptr->SetOnAdminRemoveListener(&AllowUsbDevicesPlugin::OnAdminRemove);
}

ErrCode AllowUsbDevicesPlugin::OnSetPolicy(std::vector<UsbDeviceId> &data,
    std::vector<UsbDeviceId> &currentData, int32_t userId)
{
    EDMLOGI("AllowUsbDevicesPlugin OnSetPolicy userId = %{public}d", userId);
    if (data.empty()) {
        EDMLOGW("AllowUsbDevicesPlugin OnSetPolicy data is empty");
        return ERR_OK;
    }

    auto policyManager = IPolicyManager::GetInstance();
    std::string disableUsbPolicy;
    policyManager->GetPolicy("", "disable_usb", disableUsbPolicy);
    std::string usbStoragePolicy;
    policyManager->GetPolicy("", "usb_read_only", usbStoragePolicy);
    if (disableUsbPolicy == "true" || usbStoragePolicy == std::to_string(EdmConstants::STORAGE_USB_POLICY_DISABLED)) {
        EDMLOGE("AllowUsbDevicesPlugin OnSetPolicy: CONFLICT! isUsbDisabled: %{public}s, usbStoragePolicy: %{public}s",
            disableUsbPolicy.c_str(), usbStoragePolicy.c_str());
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }

    std::vector<UsbDeviceId> mergeData = ArrayUsbDeviceIdSerializer::GetInstance()->SetUnionPolicyData(data,
        currentData);
    if (mergeData.size() > EdmConstants::ALLOWED_USB_DEVICES_MAX_SIZE) {
        EDMLOGE("AllowUsbDevicesPlugin OnSetPolicy data is too large");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    auto &srvClient = OHOS::USB::UsbSrvClient::GetInstance();
    std::vector<OHOS::USB::UsbDevice> allDevices;
    int32_t getRet = srvClient.GetDevices(allDevices);
    if (getRet != ERR_OK) {
        EDMLOGE("AllowUsbDevicesPlugin OnSetPolicy getDevices failed: %{public}d", getRet);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    for (const auto &item : allDevices) {
        bool isAllowed = (std::find_if(mergeData.begin(), mergeData.end(), [item](UsbDeviceId trustItem) {
            return item.GetVendorId() == trustItem.GetVendorId() && item.GetProductId() == trustItem.GetProductId();
        }) != mergeData.end());
        if (srvClient.ManageDevice(item.GetVendorId(), item.GetProductId(), !isAllowed) != ERR_OK) {
            EDMLOGW("AllowUsbDevicesPlugin SetPolicy ManageDevice: vid:%{public}d pid:%{public}d, %{public}d failed!",
                item.GetVendorId(), item.GetProductId(), isAllowed);
        }
    }
    currentData = mergeData;
    return ERR_OK;
}

ErrCode AllowUsbDevicesPlugin::OnRemovePolicy(std::vector<UsbDeviceId> &data,
    std::vector<UsbDeviceId> &currentData, int32_t userId)
{
    EDMLOGD("AllowUsbDevicesPlugin OnRemovePolicy userId : %{public}d:", userId);
    if (data.empty()) {
        EDMLOGW("AllowUsbDevicesPlugin OnRemovePolicy data is empty:");
        return ERR_OK;
    }
    std::vector<UsbDeviceId> mergeData =
        ArrayUsbDeviceIdSerializer::GetInstance()->SetDifferencePolicyData(data, currentData);
    if (mergeData.empty()) {
        auto &srvClient = OHOS::USB::UsbSrvClient::GetInstance();
        std::vector<OHOS::USB::UsbDevice> allDevices;
        int32_t getRet = srvClient.GetDevices(allDevices);
        if (getRet != ERR_OK) {
            EDMLOGE("AllowUsbDevicesPlugin OnSetPolicy getDevices failed: %{public}d", getRet);
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        EDMLOGI("AllowUsbDevicesPlugin OnRemovePolicy: clear to empty, enable all.");
        std::for_each(allDevices.begin(), allDevices.end(), [&](const auto usbDevice) {
            if (srvClient.ManageDevice(usbDevice.GetVendorId(), usbDevice.GetProductId(), false) != ERR_OK) {
                EDMLOGW("AllowUsbDevicesPlugin OnRemovePolicy ManageDevice vid: %{public}d, pid: %{public}d failed!",
                    usbDevice.GetVendorId(), usbDevice.GetProductId());
            }
        });
        currentData = mergeData;
        return ERR_OK;
    }
    EDMLOGI("AllowUsbDevicesPlugin OnRemovePolicy: remove data size: %{public}zu", data.size());
    auto &srvClient = OHOS::USB::UsbSrvClient::GetInstance();
    std::for_each(data.begin(), data.end(), [&](const auto usbDeviceId) {
        if (srvClient.ManageDevice(usbDeviceId.GetVendorId(), usbDeviceId.GetProductId(), true) != ERR_OK) {
            EDMLOGW("AllowUsbDevicesPlugin OnRemovePolicy ManageDevice vid: %{public}d, pid: %{public}d failed!",
                usbDeviceId.GetVendorId(), usbDeviceId.GetProductId());
        }
    });
    currentData = mergeData;
    return ERR_OK;
}

ErrCode AllowUsbDevicesPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("AllowUsbDevicesPlugin OnGetPolicy policyData : %{public}s, userId : %{public}d",
        policyData.c_str(), userId);
    std::vector<UsbDeviceId> usbDeviceIds;
    ArrayUsbDeviceIdSerializer::GetInstance()->Deserialize(policyData, usbDeviceIds);
    reply.WriteInt32(ERR_OK);
    reply.WriteInt32(usbDeviceIds.size());
    std::for_each(usbDeviceIds.begin(), usbDeviceIds.end(), [&](const auto usbDeviceId) {
        EDMLOGD("AllowUsbDevicesPlugin OnGetPolicy: currentData: vid: %{public}d, pid: %{public}d",
            usbDeviceId.GetVendorId(), usbDeviceId.GetProductId());
        usbDeviceId.Marshalling(reply);
    });
    return ERR_OK;
}

ErrCode AllowUsbDevicesPlugin::OnAdminRemove(const std::string &adminName, std::vector<UsbDeviceId> &data,
    int32_t userId)
{
    EDMLOGD("AllowUsbDevicesPlugin OnAdminRemove");
    if (data.empty()) {
        EDMLOGW("AllowUsbDevicesPlugin OnRemovePolicy data is empty:");
        return ERR_OK;
    }
    std::vector<OHOS::USB::UsbDevice> allDevices;
    auto &srvClient = OHOS::USB::UsbSrvClient::GetInstance();
    int32_t getRet = srvClient.GetDevices(allDevices);
    if (getRet != ERR_OK) {
        EDMLOGE("AllowUsbDevicesPlugin OnAdminRemove getDevices failed: %{public}d", getRet);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    EDMLOGI("AllowUsbDevicesPlugin OnAdminRemove: ManageDevice which is not in the list of allowed usb device.");
    for (const auto &item : allDevices) {
        if (std::find_if(data.begin(), data.end(), [item](UsbDeviceId trustItem) {
            return item.GetVendorId() == trustItem.GetVendorId() && item.GetProductId() == trustItem.GetProductId();
        }) == data.end()) {
            if (srvClient.ManageDevice(item.GetVendorId(), item.GetProductId(), false) != ERR_OK) {
                EDMLOGW("AllowUsbDevicesPlugin OnAdminRemove: ManageDevice vid:%{public}d pid:%{public}d failed!",
                    item.GetVendorId(), item.GetProductId());
            }
        }
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
