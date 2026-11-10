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
#include <string>
#include <vector>

#include "edm_constants.h"
#include "message_parcel.h"
#include "usb_device_info.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
namespace {
const std::string TEST_SERIAL = "SN123456";
const std::string TEST_NAME = "USB Disk";
}

class UsbDeviceInfoTest : public testing::Test {
protected:
    UsbDeviceInfo BuildValidUsbDeviceInfo() const;
};

UsbDeviceInfo UsbDeviceInfoTest::BuildValidUsbDeviceInfo() const
{
    UsbDeviceInfo info;
    info.busNum = 1;
    info.devAddress = 2;
    info.serial = TEST_SERIAL;
    info.name = TEST_NAME;
    info.manufacturerName = "Vendor";
    info.productName = "Product";
    info.version = "1.0";
    info.vendorId = 0x1234;
    info.productId = 0x5678;
    info.clazz = 8;
    info.subClass = 6;
    info.protocol = 80;
    info.states = true;
    USBInterfaceInfo iface;
    iface.id = 0;
    iface.protocol = 80;
    iface.clazz = 8;
    iface.subClass = 6;
    iface.name = "ifc";
    iface.states = true;
    USBConfigurationInfo config;
    config.id = 1;
    config.name = "cfg";
    config.states = true;
    config.interfaces = {iface};
    info.configs = {config};
    return info;
}

/**
 * @tc.name: Marshalling_ValidUsbDeviceInfo_Success
 * @tc.desc: Test UsbDeviceInfo marshalling and unmarshalling with valid fields.
 * @tc.type: FUNC
 */
HWTEST_F(UsbDeviceInfoTest, Marshalling_ValidUsbDeviceInfo_Success, TestSize.Level1)
{
    UsbDeviceInfo src = BuildValidUsbDeviceInfo();
    MessageParcel parcel;
    ASSERT_TRUE(src.Marshalling(parcel));
    UsbDeviceInfo dst;
    ASSERT_TRUE(UsbDeviceInfo::Unmarshalling(parcel, dst));
    EXPECT_EQ(dst.busNum, 1);
    EXPECT_EQ(dst.devAddress, 2);
    EXPECT_EQ(dst.serial, TEST_SERIAL);
    EXPECT_EQ(dst.name, TEST_NAME);
    EXPECT_TRUE(dst.states);
    ASSERT_EQ(dst.configs.size(), 1u);
    ASSERT_EQ(dst.configs[0].interfaces.size(), 1u);
    EXPECT_EQ(dst.configs[0].interfaces[0].id, 0);
    EXPECT_TRUE(dst.configs[0].interfaces[0].states);
}

/**
 * @tc.name: Marshalling_EmptyFields_Success
 * @tc.desc: Test UsbDeviceInfo marshalling with empty/default fields.
 * @tc.type: FUNC
 */
HWTEST_F(UsbDeviceInfoTest, Marshalling_EmptyFields_Success, TestSize.Level1)
{
    UsbDeviceInfo src;
    MessageParcel parcel;
    ASSERT_TRUE(src.Marshalling(parcel));
    UsbDeviceInfo dst;
    ASSERT_TRUE(UsbDeviceInfo::Unmarshalling(parcel, dst));
    EXPECT_TRUE(dst.serial.empty());
    EXPECT_TRUE(dst.configs.empty());
    EXPECT_FALSE(dst.states);
}

/**
 * @tc.name: Unmarshalling_IncompleteParcel_Fail
 * @tc.desc: Test Unmarshalling fails when parcel data is incomplete.
 * @tc.type: FUNC
 */
HWTEST_F(UsbDeviceInfoTest, Unmarshalling_IncompleteParcel_Fail, TestSize.Level1)
{
    MessageParcel parcel;
    ASSERT_TRUE(parcel.WriteInt32(1));
    UsbDeviceInfo dst;
    EXPECT_FALSE(UsbDeviceInfo::Unmarshalling(parcel, dst));
}

/**
 * @tc.name: Unmarshalling_ConfigsSizeWithoutPayload_Fail
 * @tc.desc: Test Unmarshalling fails when configs size written without payload.
 * @tc.type: FUNC
 */
HWTEST_F(UsbDeviceInfoTest, Unmarshalling_ConfigsSizeWithoutPayload_Fail, TestSize.Level1)
{
    MessageParcel bad;
    UsbDeviceInfo empty;
    ASSERT_TRUE(empty.Marshalling(bad));
    // Rewrite configs size=1 with no interface payload by building truncated parcel.
    MessageParcel truncated;
    ASSERT_TRUE(truncated.WriteInt32(0));
    ASSERT_TRUE(truncated.WriteInt32(0));
    for (int i = 0; i < 5; ++i) {
        ASSERT_TRUE(truncated.WriteString(""));
    }
    for (int i = 0; i < 5; ++i) {
        ASSERT_TRUE(truncated.WriteInt32(0));
    }
    ASSERT_TRUE(truncated.WriteBool(false));
    ASSERT_TRUE(truncated.WriteUint32(1));
    UsbDeviceInfo dst;
    EXPECT_FALSE(UsbDeviceInfo::Unmarshalling(truncated, dst));
}

/**
 * @tc.name: Marshalling_ConfigsOverLimit_Fail
 * @tc.desc: Test Marshalling fails when configs exceed DEFAULT_LOOP_MAX_SIZE.
 * @tc.type: FUNC
 */
HWTEST_F(UsbDeviceInfoTest, Marshalling_ConfigsOverLimit_Fail, TestSize.Level1)
{
    UsbDeviceInfo info;
    info.configs.assign(EdmConstants::DEFAULT_LOOP_MAX_SIZE + 1, USBConfigurationInfo{});
    MessageParcel parcel;
    EXPECT_FALSE(info.Marshalling(parcel));
}

/**
 * @tc.name: Marshalling_ValidUsbDeviceConfigInfo_Success
 * @tc.desc: Test USBDeviceConfigInfo round-trip with optional interface fields.
 * @tc.type: FUNC
 */
HWTEST_F(UsbDeviceInfoTest, Marshalling_ValidUsbDeviceConfigInfo_Success, TestSize.Level1)
{
    USBDeviceConfigInfo src;
    src.busNum = 1;
    src.devAddr = 2;
    src.hasConfigId = true;
    src.configId = 3;
    src.hasInterfaceId = true;
    src.interfaceId = 4;
    MessageParcel parcel;
    ASSERT_TRUE(src.Marshalling(parcel));
    USBDeviceConfigInfo dst;
    ASSERT_TRUE(USBDeviceConfigInfo::Unmarshalling(parcel, dst));
    EXPECT_EQ(dst.busNum, 1);
    EXPECT_EQ(dst.devAddr, 2);
    EXPECT_TRUE(dst.hasConfigId);
    EXPECT_EQ(dst.configId, 3);
    EXPECT_TRUE(dst.hasInterfaceId);
    EXPECT_EQ(dst.interfaceId, 4);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
