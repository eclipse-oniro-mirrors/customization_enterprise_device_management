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

#include "odd_burn_usb_device.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {

const int32_t TEST_VID = 111;
const int32_t TEST_PID = 222;
const std::string TEST_SERIAL = "serial123";

class OddBurnUsbDeviceTest : public testing::Test {};

/**
 * @tc.name: TestSettersAndGetters
 * @tc.desc: Test setters and getters of OddBurnUsbDevice.
 * @tc.type: FUNC
 */
HWTEST_F(OddBurnUsbDeviceTest, TestSettersAndGetters, TestSize.Level1)
{
    OddBurnUsbDevice device;
    device.SetVendorId(TEST_VID);
    device.SetProductId(TEST_PID);
    device.SetSerial(TEST_SERIAL);
    ASSERT_EQ(device.GetVendorId(), TEST_VID);
    ASSERT_EQ(device.GetProductId(), TEST_PID);
    ASSERT_EQ(device.GetSerial(), TEST_SERIAL);
}

/**
 * @tc.name: TestDefaultValues
 * @tc.desc: Test default values of OddBurnUsbDevice.
 * @tc.type: FUNC
 */
HWTEST_F(OddBurnUsbDeviceTest, TestDefaultValues, TestSize.Level1)
{
    OddBurnUsbDevice device;
    ASSERT_EQ(device.GetVendorId(), -1);
    ASSERT_EQ(device.GetProductId(), -1);
    ASSERT_TRUE(device.GetSerial().empty());
}

/**
 * @tc.name: TestMarshallingAndUnmarshalling
 * @tc.desc: Test Marshalling and Unmarshalling round-trip with all fields.
 * @tc.type: FUNC
 */
HWTEST_F(OddBurnUsbDeviceTest, TestMarshallingAndUnmarshalling, TestSize.Level1)
{
    OddBurnUsbDevice device;
    device.SetVendorId(TEST_VID);
    device.SetProductId(TEST_PID);
    device.SetSerial(TEST_SERIAL);

    MessageParcel parcel;
    ASSERT_TRUE(device.Marshalling(parcel));

    OddBurnUsbDevice result;
    ASSERT_TRUE(OddBurnUsbDevice::Unmarshalling(parcel, result));
    ASSERT_EQ(result.GetVendorId(), TEST_VID);
    ASSERT_EQ(result.GetProductId(), TEST_PID);
    ASSERT_EQ(result.GetSerial(), TEST_SERIAL);
}

/**
 * @tc.name: TestMarshallingWithEmptySerial
 * @tc.desc: Test Marshalling and Unmarshalling when serial is empty.
 * @tc.type: FUNC
 */
HWTEST_F(OddBurnUsbDeviceTest, TestMarshallingWithEmptySerial, TestSize.Level1)
{
    OddBurnUsbDevice device;
    device.SetVendorId(TEST_VID);
    device.SetProductId(TEST_PID);

    MessageParcel parcel;
    ASSERT_TRUE(device.Marshalling(parcel));

    OddBurnUsbDevice result;
    ASSERT_TRUE(OddBurnUsbDevice::Unmarshalling(parcel, result));
    ASSERT_EQ(result.GetVendorId(), TEST_VID);
    ASSERT_EQ(result.GetProductId(), TEST_PID);
    ASSERT_TRUE(result.GetSerial().empty());
}

/**
 * @tc.name: TestOperatorEqual
 * @tc.desc: Test operator== for OddBurnUsbDevice.
 * @tc.type: FUNC
 */
HWTEST_F(OddBurnUsbDeviceTest, TestOperatorEqual, TestSize.Level1)
{
    OddBurnUsbDevice device1;
    device1.SetVendorId(TEST_VID);
    device1.SetProductId(TEST_PID);
    device1.SetSerial(TEST_SERIAL);

    OddBurnUsbDevice device2;
    device2.SetVendorId(TEST_VID);
    device2.SetProductId(TEST_PID);
    device2.SetSerial(TEST_SERIAL);
    ASSERT_TRUE(device1 == device2);

    OddBurnUsbDevice device3;
    device3.SetVendorId(TEST_VID);
    device3.SetProductId(TEST_PID);
    device3.SetSerial("different");
    ASSERT_FALSE(device1 == device3);

    OddBurnUsbDevice device4;
    device4.SetVendorId(999);
    device4.SetProductId(TEST_PID);
    device4.SetSerial(TEST_SERIAL);
    ASSERT_FALSE(device1 == device4);

    OddBurnUsbDevice device5;
    device5.SetVendorId(TEST_VID);
    device5.SetProductId(999);
    device5.SetSerial(TEST_SERIAL);
    ASSERT_FALSE(device1 == device5);
}

/**
 * @tc.name: TestOperatorLessThan
 * @tc.desc: Test operator< for OddBurnUsbDevice.
 * @tc.type: FUNC
 */
HWTEST_F(OddBurnUsbDeviceTest, TestOperatorLessThan, TestSize.Level1)
{
    OddBurnUsbDevice device1;
    device1.SetVendorId(100);
    device1.SetProductId(200);
    device1.SetSerial("aaa");

    OddBurnUsbDevice device2;
    device2.SetVendorId(200);
    device2.SetProductId(100);
    device2.SetSerial("zzz");
    ASSERT_TRUE(device1 < device2);

    OddBurnUsbDevice device3;
    device3.SetVendorId(100);
    device3.SetProductId(300);
    device3.SetSerial("aaa");
    ASSERT_TRUE(device1 < device3);

    OddBurnUsbDevice device4;
    device4.SetVendorId(100);
    device4.SetProductId(200);
    device4.SetSerial("bbb");
    ASSERT_TRUE(device1 < device4);

    OddBurnUsbDevice device5;
    device5.SetVendorId(100);
    device5.SetProductId(200);
    device5.SetSerial("aaa");
    ASSERT_FALSE(device1 < device5);
    ASSERT_FALSE(device5 < device1);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
