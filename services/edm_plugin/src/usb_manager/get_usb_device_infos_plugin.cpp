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

#include "get_usb_device_infos_plugin.h"

#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
namespace {
constexpr int32_t USB_SYNTHETIC_CONFIG_ID = 1;
}

const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(
    std::make_shared<GetUsbDeviceInfosPlugin>());

GetUsbDeviceInfosPlugin::GetUsbDeviceInfosPlugin()
{
    EDMLOGI("GetUsbDeviceInfosPlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::GET_USB_DEVICE_INFOS;
    policyName_ = PolicyName::POLICY_USB_DEVICE_INFOS;
    permissionConfig_ = IPlugin::PolicyPermissionConfig(EdmPermission::PERMISSION_ENTERPRISE_MANAGE_USB,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
    needSave_ = false;
}

ErrCode GetUsbDeviceInfosPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("GetUsbDeviceInfosPlugin OnGetPolicy.");
    std::vector<UsbDeviceInfo> deviceInfos;
    ErrCode ret = QueryUsbDeviceInfos(deviceInfos);
    if (ret != ERR_OK) {
        EDMLOGE("GetUsbDeviceInfosPlugin QueryUsbDeviceInfos failed, ret=%{public}d", ret);
        reply.WriteInt32(ret);
        return ret;
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteUint32(static_cast<uint32_t>(deviceInfos.size()));
    for (const auto &deviceInfo : deviceInfos) {
        if (!deviceInfo.Marshalling(reply)) {
            EDMLOGE("GetUsbDeviceInfosPlugin Marshalling failed");
            return EdmReturnErrCode::EXECUTE_TIME_OUT;
        }
    }
    return ERR_OK;
}

ErrCode GetUsbDeviceInfosPlugin::QueryUsbDeviceInfos(std::vector<UsbDeviceInfo> &infos)
{
    std::vector<USB::UsbDeviceInfo> usbInfos;
    int32_t usbRet = USB::UsbSrvClient::GetInstance().GetAllDevices(usbInfos);
    if (usbRet == EdmConstants::USB_ERRCODE_INTERFACE_NO_INIT) {
        EDMLOGW("GetUsbDeviceInfosPlugin USB not init, return empty list");
        infos.clear();
        return ERR_OK;
    }
    if (usbRet != ERR_OK) {
        EDMLOGE("GetUsbDeviceInfosPlugin GetAllDevices failed, ret=%{public}d", usbRet);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    infos.clear();
    infos.reserve(usbInfos.size());
    for (const auto &usbInfo : usbInfos) {
        infos.emplace_back(ToKitDeviceInfo(usbInfo));
    }
    return ERR_OK;
}

USBInterfaceInfo GetUsbDeviceInfosPlugin::ToKitInterfaceInfo(const USB::UsbInterfaceInfo &usbIface)
{
    USBInterfaceInfo iface;
    iface.id = usbIface.interfaceId;
    iface.protocol = usbIface.protocol;
    iface.clazz = usbIface.interfaceClass;
    iface.subClass = usbIface.subClass;
    iface.name = "";
    iface.isMount = usbIface.authorized;
    return iface;
}

USBConfigurationInfo GetUsbDeviceInfosPlugin::BuildSyntheticConfig(const USB::UsbDeviceInfo &usbInfo)
{
    USBConfigurationInfo config;
    config.id = USB_SYNTHETIC_CONFIG_ID;
    config.name = "";
    config.isMount = usbInfo.authorized;
    config.interfaces.reserve(usbInfo.interfaces.size());
    for (const auto &usbIface : usbInfo.interfaces) {
        config.interfaces.emplace_back(ToKitInterfaceInfo(usbIface));
    }
    return config;
}

UsbDeviceInfo GetUsbDeviceInfosPlugin::ToKitDeviceInfo(const USB::UsbDeviceInfo &usbInfo)
{
    UsbDeviceInfo info;
    info.busNum = static_cast<int32_t>(usbInfo.busNum);
    info.devAddress = static_cast<int32_t>(usbInfo.devAddr);
    info.serial = usbInfo.serial;
    info.name = "";
    info.manufacturerName = usbInfo.manufacturerName;
    info.productName = usbInfo.productName;
    info.version = "";
    info.vendorId = usbInfo.vendorId;
    info.productId = usbInfo.productId;
    info.clazz = usbInfo.deviceClass;
    info.subClass = usbInfo.subClass;
    info.protocol = usbInfo.protocol;
    info.isMount = usbInfo.authorized;
    info.configs = {BuildSyntheticConfig(usbInfo)};
    return info;
}
} // namespace EDM
} // namespace OHOS
