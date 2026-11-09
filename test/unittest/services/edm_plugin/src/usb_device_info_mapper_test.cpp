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

#include <gtest/gtest.h>

#include "usb_device_info_mapper.h"
#include "usb_flat_device_info.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
namespace {
UsbFlatDeviceInfo BuildFlatSample()
{
    UsbFlatDeviceInfo flat;
    flat.deviceId = "1-2";
    flat.busNum = 1;
    flat.devAddr = 2;
    flat.vendorId = 0x1234;
    flat.productId = 0x5678;
    flat.deviceClass = 8;
    flat.subClass = 6;
    flat.protocol = 80;
    flat.serial = "SN001";
    flat.manufacturerName = "Vendor";
    flat.productName = "Disk";
    flat.isHub = false;
    flat.authorized = true;
    UsbFlatInterfaceInfo iface;
    iface.interfaceId = 0;
    iface.interfaceClass = 8;
    iface.subClass = 6;
    iface.protocol = 80;
    iface.alternateSetting = 0;
    iface.authorized = true;
    flat.interfaces = {iface};
    return flat;
}
}

class UsbDeviceInfoMapperTest : public testing::Test {};

/**
 * @tc.name: ToKitDeviceInfo_FlatFields_Mapped
 * @tc.desc: Map USB flat device to Kit tree with synthetic configs layer.
 * @tc.type: FUNC
 */
HWTEST_F(UsbDeviceInfoMapperTest, ToKitDeviceInfo_FlatFields_Mapped, TestSize.Level1)
{
    UsbFlatDeviceInfo flat = BuildFlatSample();
    UsbDeviceInfo kit = UsbDeviceInfoMapper::ToKitDeviceInfo(flat);
    EXPECT_EQ(kit.busNum, 1);
    EXPECT_EQ(kit.devAddress, 2);
    EXPECT_EQ(kit.serial, "SN001");
    EXPECT_TRUE(kit.name.empty());
    EXPECT_TRUE(kit.version.empty());
    EXPECT_EQ(kit.manufacturerName, "Vendor");
    EXPECT_EQ(kit.productName, "Disk");
    EXPECT_EQ(kit.vendorId, 0x1234);
    EXPECT_EQ(kit.productId, 0x5678);
    EXPECT_EQ(kit.clazz, 8);
    EXPECT_EQ(kit.subClass, 6);
    EXPECT_EQ(kit.protocol, 80);
    EXPECT_TRUE(kit.states);
    ASSERT_EQ(kit.configs.size(), 1u);
    EXPECT_EQ(kit.configs[0].id, USB_SYNTHETIC_CONFIG_ID);
    EXPECT_TRUE(kit.configs[0].states);
    ASSERT_EQ(kit.configs[0].interfaces.size(), 1u);
    EXPECT_EQ(kit.configs[0].interfaces[0].id, 0);
    EXPECT_EQ(kit.configs[0].interfaces[0].clazz, 8);
    EXPECT_TRUE(kit.configs[0].interfaces[0].states);
}

/**
 * @tc.name: ToKitDeviceInfos_Empty_Success
 * @tc.desc: Empty flat list maps to empty kit list.
 * @tc.type: FUNC
 */
HWTEST_F(UsbDeviceInfoMapperTest, ToKitDeviceInfos_Empty_Success, TestSize.Level1)
{
    std::vector<UsbFlatDeviceInfo> flatList;
    std::vector<UsbDeviceInfo> kitList;
    UsbDeviceInfoMapper::ToKitDeviceInfos(flatList, kitList);
    EXPECT_TRUE(kitList.empty());
}

/**
 * @tc.name: IsInterfaceAuthorize_Flags
 * @tc.desc: Interface authorize requires both optional ids.
 * @tc.type: FUNC
 */
HWTEST_F(UsbDeviceInfoMapperTest, IsInterfaceAuthorize_Flags, TestSize.Level1)
{
    USBDeviceConfigInfo deviceOnly;
    EXPECT_FALSE(UsbDeviceInfoMapper::IsInterfaceAuthorize(deviceOnly));
    USBDeviceConfigInfo ifaceLevel;
    ifaceLevel.hasConfigId = true;
    ifaceLevel.hasInterfaceId = true;
    EXPECT_TRUE(UsbDeviceInfoMapper::IsInterfaceAuthorize(ifaceLevel));
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
