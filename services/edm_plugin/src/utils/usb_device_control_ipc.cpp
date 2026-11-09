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

#include "usb_device_control_ipc.h"

#include <dlfcn.h>
#include <mutex>

#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_log.h"
#include "ipc_types.h"
#include "iservice_registry.h"
#include "message_option.h"
#include "message_parcel.h"
#include "string_ex.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace EDM {
namespace {
constexpr const char *USB_SRV_CLIENT_SO = "libusbsrv_client.z.so";
constexpr const char *USB_IFACE_TOKEN = "OHOS.USB.IUsbServer";
// IUsbServerIpcCode: COMMAND_GET_DEVICES = MIN_TRANSACTION_ID(0x1).
// MR1458 inserts the five device-control commands immediately after GetDevices.
constexpr uint32_t USB_CMD_GET_ALL_DEVICES = static_cast<uint32_t>(MIN_TRANSACTION_ID) + 1;
constexpr uint32_t USB_CMD_DEVICE_AUTHORIZE = static_cast<uint32_t>(MIN_TRANSACTION_ID) + 2;
constexpr uint32_t USB_CMD_INTERFACE_AUTHORIZE = static_cast<uint32_t>(MIN_TRANSACTION_ID) + 3;
constexpr uint32_t USB_CMD_REG_DEVICE_CONTROL_CB = static_cast<uint32_t>(MIN_TRANSACTION_ID) + 4;
constexpr uint32_t USB_CMD_UNREG_DEVICE_CONTROL_CB = static_cast<uint32_t>(MIN_TRANSACTION_ID) + 5;
constexpr int32_t VECTOR_MAX_SIZE = 102400;

// Probe UsbSrvClient symbols added by USB MR1458 (libc++ / libstdc++ mangling).
const char *USB_API_SYMBOL_CANDIDATES[] = {
    "_ZN4OHOS3USB12UsbSrvClient24RegDeviceControlCallbackERKNS_3sptrINS_13IRemoteObjectEEE",
    "_ZN4OHOS3USB12UsbSrvClient13GetAllDevicesERNSt3__h6vectorINS0_13UsbDeviceInfoENS2_9allocatorIS4_EEEE",
    "_ZN4OHOS3USB12UsbSrvClient13GetAllDevicesERNSt3__16vectorINS0_13UsbDeviceInfoENS2_9allocatorIS4_EEEE",
    "_ZN4OHOS3USB12UsbSrvClient13GetAllDevicesERSt6vectorINS0_13UsbDeviceInfoESaIS3_EE",
};

struct UsbInterfaceInfoPod {
    int32_t interfaceId = 0;
    int32_t interfaceClass = 0;
    int32_t subClass = 0;
    int32_t protocol = 0;
    int32_t alternateSetting = 0;
    bool authorized = false;
};

bool ProbeUsbDeviceControlSymbol()
{
    void *handle = dlopen(USB_SRV_CLIENT_SO, RTLD_NOW | RTLD_NOLOAD);
    if (handle == nullptr) {
        handle = dlopen(USB_SRV_CLIENT_SO, RTLD_LAZY);
    }
    if (handle == nullptr) {
        EDMLOGW("UsbDeviceControlIpc: %{public}s not loaded, API unavailable", USB_SRV_CLIENT_SO);
        return false;
    }
    for (const char *sym : USB_API_SYMBOL_CANDIDATES) {
        if (dlsym(handle, sym) != nullptr) {
            return true;
        }
    }
    EDMLOGW("UsbDeviceControlIpc: USB device-control client symbol not found");
    return false;
}

sptr<IRemoteObject> GetUsbRemote()
{
    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        EDMLOGE("UsbDeviceControlIpc: GetSystemAbilityManager failed");
        return nullptr;
    }
    sptr<IRemoteObject> remote = sam->CheckSystemAbility(USB_SYSTEM_ABILITY_ID);
    if (remote == nullptr) {
        remote = sam->GetSystemAbility(USB_SYSTEM_ABILITY_ID);
    }
    if (remote == nullptr) {
        EDMLOGE("UsbDeviceControlIpc: USB SA %{public}d unavailable", USB_SYSTEM_ABILITY_ID);
    }
    return remote;
}

bool ReadInterfaceInfo(MessageParcel &reply, UsbFlatInterfaceInfo &iface)
{
    const auto *pod = reinterpret_cast<const UsbInterfaceInfoPod *>(
        reply.ReadUnpadBuffer(sizeof(UsbInterfaceInfoPod)));
    if (pod == nullptr) {
        return false;
    }
    iface.interfaceId = pod->interfaceId;
    iface.interfaceClass = pod->interfaceClass;
    iface.subClass = pod->subClass;
    iface.protocol = pod->protocol;
    iface.alternateSetting = pod->alternateSetting;
    iface.authorized = pod->authorized;
    return true;
}

bool ReadDeviceInfo(MessageParcel &reply, UsbFlatDeviceInfo &info)
{
    info.deviceId = Str16ToStr8(reply.ReadString16());
    info.busNum = reply.ReadUint8();
    info.devAddr = reply.ReadUint8();
    info.vendorId = reply.ReadInt32();
    info.productId = reply.ReadInt32();
    info.deviceClass = reply.ReadInt32();
    info.subClass = reply.ReadInt32();
    info.protocol = reply.ReadInt32();
    info.serial = Str16ToStr8(reply.ReadString16());
    info.manufacturerName = Str16ToStr8(reply.ReadString16());
    info.productName = Str16ToStr8(reply.ReadString16());
    info.isHub = reply.ReadInt32() == 1;
    info.authorized = reply.ReadInt32() == 1;

    int32_t ifaceSize = reply.ReadInt32();
    if (ifaceSize < 0 || ifaceSize > VECTOR_MAX_SIZE) {
        EDMLOGE("UsbDeviceControlIpc: invalid interfaces size %{public}d", ifaceSize);
        return false;
    }
    info.interfaces.clear();
    info.interfaces.reserve(static_cast<size_t>(ifaceSize));
    for (int32_t i = 0; i < ifaceSize; ++i) {
        UsbFlatInterfaceInfo iface;
        if (!ReadInterfaceInfo(reply, iface)) {
            EDMLOGE("UsbDeviceControlIpc: read UsbInterfaceInfo failed");
            return false;
        }
        info.interfaces.emplace_back(std::move(iface));
    }
    return true;
}

int32_t SendAuthorizeRequest(uint32_t code, MessageParcel &data)
{
    sptr<IRemoteObject> remote = GetUsbRemote();
    if (remote == nullptr) {
        return EdmConstants::USB_ERRCODE_INTERFACE_NO_INIT;
    }
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    int32_t result = remote->SendRequest(code, data, reply, option);
    if (result != ERR_OK) {
        EDMLOGE("UsbDeviceControlIpc: SendRequest code=%{public}u failed, ret=%{public}d", code, result);
        return result;
    }
    ErrCode errCode = reply.ReadInt32();
    if (errCode != ERR_OK) {
        return errCode;
    }
    return reply.ReadInt32();
}
} // namespace

bool UsbDeviceControlIpc::IsApiAvailable()
{
    static std::once_flag once;
    static bool available = false;
    std::call_once(once, []() { available = ProbeUsbDeviceControlSymbol(); });
    return available;
}

int32_t UsbDeviceControlIpc::GetAllDevices(std::vector<UsbFlatDeviceInfo> &deviceInfos)
{
    deviceInfos.clear();
    if (!IsApiAvailable()) {
        return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
    }
    sptr<IRemoteObject> remote = GetUsbRemote();
    if (remote == nullptr) {
        return EdmConstants::USB_ERRCODE_INTERFACE_NO_INIT;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    if (!data.WriteInterfaceToken(Str8ToStr16(USB_IFACE_TOKEN))) {
        return ERR_INVALID_VALUE;
    }
    int32_t result = remote->SendRequest(USB_CMD_GET_ALL_DEVICES, data, reply, option);
    if (result != ERR_OK) {
        EDMLOGE("UsbDeviceControlIpc::GetAllDevices SendRequest failed, ret=%{public}d", result);
        return result;
    }
    ErrCode errCode = reply.ReadInt32();
    if (errCode != ERR_OK) {
        return errCode;
    }

    int32_t size = reply.ReadInt32();
    if (size < 0 || size > VECTOR_MAX_SIZE) {
        EDMLOGE("UsbDeviceControlIpc::GetAllDevices invalid size %{public}d", size);
        return ERR_INVALID_DATA;
    }
    deviceInfos.reserve(static_cast<size_t>(size));
    for (int32_t i = 0; i < size; ++i) {
        UsbFlatDeviceInfo info;
        if (!ReadDeviceInfo(reply, info)) {
            deviceInfos.clear();
            return ERR_INVALID_DATA;
        }
        deviceInfos.emplace_back(std::move(info));
    }
    return ERR_OK;
}

int32_t UsbDeviceControlIpc::UsbDeviceAuthorize(uint8_t busNum, uint8_t devAddr, bool authorized)
{
    if (!IsApiAvailable()) {
        return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(Str8ToStr16(USB_IFACE_TOKEN)) ||
        !data.WriteUint8(busNum) || !data.WriteUint8(devAddr) ||
        !data.WriteInt32(authorized ? 1 : 0)) {
        return ERR_INVALID_DATA;
    }
    return SendAuthorizeRequest(USB_CMD_DEVICE_AUTHORIZE, data);
}

int32_t UsbDeviceControlIpc::UsbInterfaceAuthorize(uint8_t busNum, uint8_t devAddr, uint8_t configId,
    uint8_t interfaceId, bool authorized)
{
    if (!IsApiAvailable()) {
        return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(Str8ToStr16(USB_IFACE_TOKEN)) ||
        !data.WriteUint8(busNum) || !data.WriteUint8(devAddr) ||
        !data.WriteUint8(configId) || !data.WriteUint8(interfaceId) ||
        !data.WriteInt32(authorized ? 1 : 0)) {
        return ERR_INVALID_DATA;
    }
    return SendAuthorizeRequest(USB_CMD_INTERFACE_AUTHORIZE, data);
}

int32_t UsbDeviceControlIpc::RegDeviceControlCallback(const sptr<IRemoteObject> &cb)
{
    if (!IsApiAvailable()) {
        return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
    }
    if (cb == nullptr) {
        return ERR_INVALID_VALUE;
    }
    sptr<IRemoteObject> remote = GetUsbRemote();
    if (remote == nullptr) {
        return EdmConstants::USB_ERRCODE_INTERFACE_NO_INIT;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    if (!data.WriteInterfaceToken(Str8ToStr16(USB_IFACE_TOKEN)) || !data.WriteRemoteObject(cb)) {
        return ERR_INVALID_DATA;
    }
    int32_t result = remote->SendRequest(USB_CMD_REG_DEVICE_CONTROL_CB, data, reply, option);
    if (result != ERR_OK) {
        EDMLOGE("UsbDeviceControlIpc::RegDeviceControlCallback SendRequest failed, ret=%{public}d", result);
        return result;
    }
    return reply.ReadInt32();
}

int32_t UsbDeviceControlIpc::UnRegDeviceControlCallback(const sptr<IRemoteObject> &cb)
{
    if (!IsApiAvailable()) {
        return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
    }
    if (cb == nullptr) {
        return ERR_INVALID_VALUE;
    }
    sptr<IRemoteObject> remote = GetUsbRemote();
    if (remote == nullptr) {
        return EdmConstants::USB_ERRCODE_INTERFACE_NO_INIT;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    if (!data.WriteInterfaceToken(Str8ToStr16(USB_IFACE_TOKEN)) || !data.WriteRemoteObject(cb)) {
        return ERR_INVALID_DATA;
    }
    int32_t result = remote->SendRequest(USB_CMD_UNREG_DEVICE_CONTROL_CB, data, reply, option);
    if (result != ERR_OK) {
        EDMLOGE("UsbDeviceControlIpc::UnRegDeviceControlCallback SendRequest failed, ret=%{public}d", result);
        return result;
    }
    return reply.ReadInt32();
}
} // namespace EDM
} // namespace OHOS
