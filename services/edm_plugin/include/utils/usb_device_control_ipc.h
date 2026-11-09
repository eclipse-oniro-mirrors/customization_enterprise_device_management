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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_UTILS_USB_DEVICE_CONTROL_IPC_H
#define SERVICES_EDM_PLUGIN_INCLUDE_UTILS_USB_DEVICE_CONTROL_IPC_H

#include <cstdint>
#include <vector>

#include "iremote_object.h"
#include "refbase.h"
#include "usb_flat_device_info.h"

namespace OHOS {
namespace EDM {

/**
 * Soft IPC client for USB #1458 device-control APIs.
 * Does not call UsbSrvClient new methods, so EDM compiles whether or not USB
 * has landed the client symbols. When the USB client .so lacks the API,
 * calls return INTERFACE_UNSUPPORTED without sending a shifted IPC code.
 *
 * IPC codes match busmanager_usb_manager MR1458 IDL order (inserted after
 * GetDevices). Keep in sync when USB adjusts IUsbServer.idl.
 */
class UsbDeviceControlIpc {
public:
    static bool IsApiAvailable();

    static int32_t GetAllDevices(std::vector<UsbFlatDeviceInfo> &deviceInfos);
    static int32_t UsbDeviceAuthorize(uint8_t busNum, uint8_t devAddr, bool authorized);
    static int32_t UsbInterfaceAuthorize(uint8_t busNum, uint8_t devAddr, uint8_t configId,
        uint8_t interfaceId, bool authorized);
    static int32_t RegDeviceControlCallback(const sptr<IRemoteObject> &cb);
    static int32_t UnRegDeviceControlCallback(const sptr<IRemoteObject> &cb);
};

} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_INCLUDE_UTILS_USB_DEVICE_CONTROL_IPC_H
