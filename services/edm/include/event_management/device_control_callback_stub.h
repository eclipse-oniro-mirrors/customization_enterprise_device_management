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

#ifndef SERVICES_EDM_INCLUDE_EVENT_MANAGEMENT_DEVICE_CONTROL_CALLBACK_STUB_H
#define SERVICES_EDM_INCLUDE_EVENT_MANAGEMENT_DEVICE_CONTROL_CALLBACK_STUB_H

#include "iremote_stub.h"

namespace OHOS {
namespace EDM {
class UsbDeviceControlEventAdapter;

constexpr uint32_t USB_DEVICE_CONTROL_EVENT_CODE = 1;

class DeviceControlCallbackStub : public IPCObjectStub {
public:
    explicit DeviceControlCallbackStub(UsbDeviceControlEventAdapter &owner);
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option) override;

private:
    UsbDeviceControlEventAdapter &owner_;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_EVENT_MANAGEMENT_DEVICE_CONTROL_CALLBACK_STUB_H
