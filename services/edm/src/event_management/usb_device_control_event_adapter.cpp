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

#include "usb_device_control_event_adapter.h"

#include "edm_constants.h"
#include "edm_log.h"
#include "managed_event.h"
#include "usb_config.h"
#include "usb_interface.h"
#include "usb_srv_client.h"

namespace OHOS {
namespace EDM {
UsbDeviceControlEventAdapter::DeviceControlCallbackStub::DeviceControlCallbackStub(
    UsbDeviceControlEventAdapter &owner)
    : IPCObjectStub(u"ohos.edm.UsbDeviceControlCallback"), owner_(owner)
{
}

int UsbDeviceControlEventAdapter::DeviceControlCallbackStub::OnRemoteRequest(uint32_t code,
    MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (code != USB_DEVICE_CONTROL_EVENT_CODE) {
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    // USB #1458: parcel = UsbDevice.Marshalling + AuthorizeStatus(int32) + attached(bool)
    USB::UsbDevice *device = USB::UsbDevice::Unmarshalling(data);
    if (device == nullptr) {
        EDMLOGE("UsbDeviceControlEventAdapter Unmarshalling UsbDevice failed");
        return ERR_INVALID_VALUE;
    }
    int32_t statusRaw = data.ReadInt32();
    bool attached = data.ReadBool();
    auto status = static_cast<USB::AuthorizeStatus>(statusRaw);
    owner_.OnDeviceControlEvent(*device, status, attached);
    delete device;
    return ERR_OK;
}

UsbDeviceControlEventAdapter::UsbDeviceControlEventAdapter(EventSubscriptionManager &manager)
    : manager_(manager)
{
    callback_ = new (std::nothrow) DeviceControlCallbackStub(*this);
}

UsbDeviceControlEventAdapter::~UsbDeviceControlEventAdapter()
{
    if (registered_) {
        UnsubscribeEvent();
    }
}

bool UsbDeviceControlEventAdapter::SubscribeEvent()
{
    if (callback_ == nullptr) {
        EDMLOGE("UsbDeviceControlEventAdapter::SubscribeEvent callback is null");
        return false;
    }
    if (registered_) {
        return true;
    }
    int32_t ret = USB::UsbSrvClient::GetInstance().RegDeviceControlCallback(callback_);
    if (ret == EdmConstants::USB_ERRCODE_INTERFACE_NO_INIT) {
        EDMLOGW("UsbDeviceControlEventAdapter::SubscribeEvent USB not init");
        return false;
    }
    if (ret != ERR_OK) {
        EDMLOGE("UsbDeviceControlEventAdapter::SubscribeEvent Reg failed, ret=%{public}d", ret);
        return false;
    }
    registered_ = true;
    EDMLOGI("UsbDeviceControlEventAdapter::SubscribeEvent success");
    return true;
}

bool UsbDeviceControlEventAdapter::UnsubscribeEvent()
{
    if (callback_ == nullptr || !registered_) {
        registered_ = false;
        return true;
    }
    int32_t ret = USB::UsbSrvClient::GetInstance().UnRegDeviceControlCallback(callback_);
    if (ret != ERR_OK && ret != EdmConstants::USB_ERRCODE_INTERFACE_NO_INIT) {
        EDMLOGE("UsbDeviceControlEventAdapter::UnsubscribeEvent UnReg failed, ret=%{public}d", ret);
        return false;
    }
    registered_ = false;
    EDMLOGI("UsbDeviceControlEventAdapter::UnsubscribeEvent success");
    return true;
}

void UsbDeviceControlEventAdapter::OnDeviceControlEvent(USB::UsbDevice &device,
    USB::AuthorizeStatus status, bool attached)
{
    if (!attached) {
        return;
    }
    if (device.GetClass() == USB_BASE_CLASS_HUB) {
        EDMLOGI("UsbDeviceControlEventAdapter skip hub device");
        return;
    }
    EdmEventData edmData;
    edmData.eventId = {static_cast<uint32_t>(ManagedEvent::USB_DEVICE_ADDED)};
    edmData.usbDeviceInfo = ToKitDeviceInfo(device, status);
    manager_.DispatchEvent(edmData);
}

UsbDeviceInfo UsbDeviceControlEventAdapter::ToKitDeviceInfo(const USB::UsbDevice &device,
    USB::AuthorizeStatus status)
{
    UsbDeviceInfo info;
    info.busNum = static_cast<int32_t>(device.GetBusNum());
    info.devAddress = static_cast<int32_t>(device.GetDevAddr());
    info.serial = device.GetmSerial();
    info.name = device.GetName();
    info.manufacturerName = device.GetManufacturerName();
    info.productName = device.GetProductName();
    info.version = device.GetVersion();
    info.vendorId = device.GetVendorId();
    info.productId = device.GetProductId();
    info.clazz = device.GetClass();
    info.subClass = device.GetSubclass();
    info.protocol = device.GetProtocol();
    info.states = (status != USB::AuthorizeStatus::DISABLED);

    int32_t configCount = device.GetConfigCount();
    info.configs.reserve(static_cast<size_t>(configCount));
    for (int32_t i = 0; i < configCount; ++i) {
        USB::USBConfig usbConfig;
        if (device.GetConfig(static_cast<uint32_t>(i), usbConfig) != ERR_OK) {
            continue;
        }
        USBConfigurationInfo kitConfig;
        kitConfig.id = usbConfig.GetId();
        kitConfig.name = usbConfig.GetName();
        kitConfig.states = info.states;
        for (auto &usbIface : usbConfig.GetInterfaces()) {
            USBInterfaceInfo kitIface;
            kitIface.id = usbIface.GetId();
            kitIface.clazz = usbIface.GetClass();
            kitIface.subClass = usbIface.GetSubClass();
            kitIface.protocol = usbIface.GetProtocol();
            kitIface.name = "";
            kitIface.states = usbIface.GetAuthorizeStatus();
            kitConfig.interfaces.emplace_back(kitIface);
        }
        info.configs.emplace_back(std::move(kitConfig));
    }
    return info;
}
} // namespace EDM
} // namespace OHOS
