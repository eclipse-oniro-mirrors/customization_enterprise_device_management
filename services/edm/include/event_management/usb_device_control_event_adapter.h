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

#ifndef SERVICES_EDM_INCLUDE_EVENT_MANAGEMENT_USB_DEVICE_CONTROL_EVENT_ADAPTER_H
#define SERVICES_EDM_INCLUDE_EVENT_MANAGEMENT_USB_DEVICE_CONTROL_EVENT_ADAPTER_H

#include "device_control_callback_stub.h"
#include "event_subscription_manager.h"
#include "i_event_source_adapter.h"
#include "usb_device.h"

namespace OHOS {
namespace EDM {
constexpr int32_t USB_BASE_CLASS_HUB = 0x09;

class UsbDeviceControlEventAdapter : public IEventSourceAdapter {
public:
    explicit UsbDeviceControlEventAdapter(EventSubscriptionManager &manager);
    ~UsbDeviceControlEventAdapter() override;

    bool SubscribeEvent() override;
    bool UnsubscribeEvent() override;
    AdapterType GetAdapterType() const override { return AdapterType::USB_DEVICE_CONTROL; }

private:
    friend class DeviceControlCallbackStub;
    void OnDeviceControlEvent(USB::UsbDevice &device, USB::AuthorizeStatus status, bool attached);
    static UsbDeviceInfo ToKitDeviceInfo(const USB::UsbDevice &device, USB::AuthorizeStatus status);

    EventSubscriptionManager &manager_;
    sptr<DeviceControlCallbackStub> callback_;
    bool registered_{false};
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_EVENT_MANAGEMENT_USB_DEVICE_CONTROL_EVENT_ADAPTER_H
