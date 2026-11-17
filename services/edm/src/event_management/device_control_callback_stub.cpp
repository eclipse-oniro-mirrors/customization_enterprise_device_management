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

#include "device_control_callback_stub.h"

#include "edm_errors.h"
#include "edm_log.h"
#include "usb_device.h"
#include "usb_device_control_event_adapter.h"

namespace OHOS {
namespace EDM {
DeviceControlCallbackStub::DeviceControlCallbackStub(UsbDeviceControlEventAdapter &owner)
    : IPCObjectStub(u"ohos.edm.UsbDeviceControlCallback"), owner_(owner)
{
}

int DeviceControlCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    if (code != USB_DEVICE_CONTROL_EVENT_CODE) {
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    USB::UsbDevice *device = USB::UsbDevice::Unmarshalling(data);
    if (device == nullptr) {
        EDMLOGE("DeviceControlCallbackStub Unmarshalling UsbDevice failed");
        return ERR_INVALID_VALUE;
    }
    int32_t statusRaw = data.ReadInt32();
    bool attached = data.ReadBool();
    auto status = static_cast<USB::AuthorizeStatus>(statusRaw);
    owner_.OnDeviceControlEvent(*device, status, attached);
    delete device;
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
