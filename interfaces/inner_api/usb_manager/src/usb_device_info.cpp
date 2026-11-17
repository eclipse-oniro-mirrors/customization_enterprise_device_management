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

#include "usb_device_info.h"

#include "edm_constants.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
namespace {
bool WriteVectorSize(Parcel &parcel, size_t size)
{
    if (size > EdmConstants::DEFAULT_LOOP_MAX_SIZE) {
        EDMLOGE("UsbDeviceInfo vector size over limit: %{public}zu", size);
        return false;
    }
    return parcel.WriteUint32(static_cast<uint32_t>(size));
}

bool ReadVectorSize(Parcel &parcel, uint32_t &size)
{
    if (!parcel.ReadUint32(size)) {
        return false;
    }
    if (size > EdmConstants::DEFAULT_LOOP_MAX_SIZE) {
        EDMLOGE("UsbDeviceInfo vector size over limit: %{public}u", size);
        return false;
    }
    return true;
}
} // namespace

bool USBInterfaceInfo::Marshalling(Parcel &parcel) const
{
    return parcel.WriteInt32(id) && parcel.WriteInt32(protocol) && parcel.WriteInt32(clazz) &&
        parcel.WriteInt32(subClass) && parcel.WriteString(name) && parcel.WriteBool(isMount);
}

bool USBInterfaceInfo::Unmarshalling(Parcel &parcel, USBInterfaceInfo &info)
{
    return parcel.ReadInt32(info.id) && parcel.ReadInt32(info.protocol) && parcel.ReadInt32(info.clazz) &&
        parcel.ReadInt32(info.subClass) && parcel.ReadString(info.name) && parcel.ReadBool(info.isMount);
}

bool USBConfigurationInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(id) || !parcel.WriteString(name) || !parcel.WriteBool(isMount)) {
        return false;
    }
    if (!WriteVectorSize(parcel, interfaces.size())) {
        return false;
    }
    for (const auto &iface : interfaces) {
        if (!iface.Marshalling(parcel)) {
            return false;
        }
    }
    return true;
}

bool USBConfigurationInfo::Unmarshalling(Parcel &parcel, USBConfigurationInfo &info)
{
    if (!parcel.ReadInt32(info.id) || !parcel.ReadString(info.name) || !parcel.ReadBool(info.isMount)) {
        return false;
    }
    uint32_t size = 0;
    if (!ReadVectorSize(parcel, size)) {
        return false;
    }
    info.interfaces.clear();
    info.interfaces.reserve(size);
    for (uint32_t i = 0; i < size; ++i) {
        USBInterfaceInfo iface;
        if (!USBInterfaceInfo::Unmarshalling(parcel, iface)) {
            return false;
        }
        info.interfaces.emplace_back(std::move(iface));
    }
    return true;
}

bool USBDeviceConfigInfo::Marshalling(Parcel &parcel) const
{
    return parcel.WriteInt32(busNum) && parcel.WriteInt32(devAddress) && parcel.WriteBool(hasConfigId) &&
        parcel.WriteInt32(configId) && parcel.WriteBool(hasInterfaceId) && parcel.WriteInt32(interfaceId);
}

bool USBDeviceConfigInfo::Unmarshalling(Parcel &parcel, USBDeviceConfigInfo &info)
{
    return parcel.ReadInt32(info.busNum) && parcel.ReadInt32(info.devAddress) && parcel.ReadBool(info.hasConfigId) &&
        parcel.ReadInt32(info.configId) && parcel.ReadBool(info.hasInterfaceId) &&
        parcel.ReadInt32(info.interfaceId);
}

bool UsbDeviceInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(busNum) || !parcel.WriteInt32(devAddress) || !parcel.WriteString(serial) ||
        !parcel.WriteString(name) || !parcel.WriteString(manufacturerName) || !parcel.WriteString(productName) ||
        !parcel.WriteString(version) || !parcel.WriteInt32(vendorId) || !parcel.WriteInt32(productId) ||
        !parcel.WriteInt32(clazz) || !parcel.WriteInt32(subClass) || !parcel.WriteInt32(protocol) ||
        !parcel.WriteBool(isMount)) {
        return false;
    }
    if (!WriteVectorSize(parcel, configs.size())) {
        return false;
    }
    for (const auto &config : configs) {
        if (!config.Marshalling(parcel)) {
            return false;
        }
    }
    return true;
}

bool UsbDeviceInfo::Unmarshalling(Parcel &parcel, UsbDeviceInfo &info)
{
    if (!parcel.ReadInt32(info.busNum) || !parcel.ReadInt32(info.devAddress) || !parcel.ReadString(info.serial) ||
        !parcel.ReadString(info.name) || !parcel.ReadString(info.manufacturerName) ||
        !parcel.ReadString(info.productName) || !parcel.ReadString(info.version) ||
        !parcel.ReadInt32(info.vendorId) || !parcel.ReadInt32(info.productId) || !parcel.ReadInt32(info.clazz) ||
        !parcel.ReadInt32(info.subClass) || !parcel.ReadInt32(info.protocol) || !parcel.ReadBool(info.isMount)) {
        return false;
    }
    uint32_t size = 0;
    if (!ReadVectorSize(parcel, size)) {
        return false;
    }
    info.configs.clear();
    info.configs.reserve(size);
    for (uint32_t i = 0; i < size; ++i) {
        USBConfigurationInfo config;
        if (!USBConfigurationInfo::Unmarshalling(parcel, config)) {
            return false;
        }
        info.configs.emplace_back(std::move(config));
    }
    return true;
}
} // namespace EDM
} // namespace OHOS
