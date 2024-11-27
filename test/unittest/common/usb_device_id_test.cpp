/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "usb_device_id.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class UsbDeviceIdTest : public testing::Test {};
/**
 * @tc.name: TestMarshalling
 * @tc.desc: Test Test Marshalling function.
 * @tc.type: FUNC
 */
HWTEST_F(UsbDeviceIdTest, TestMarshalling, TestSize.Level1)
{
    std::shared_ptr<UsbDeviceId> usbDeviceId = std::make_shared<UsbDeviceId>();
    MessageParcel parcel;
    ASSERT_TRUE(usbDeviceId->Marshalling(parcel));
}

/**
 * @tc.name: TestUnmarshallingWithDataEmpty
 * @tc.desc: Test Test Unmarshalling function when input data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(UsbDeviceIdTest, TestUnmarshallingWithDataEmpty, TestSize.Level1)
{
    std::shared_ptr<UsbDeviceId> usbDeviceId = std::make_shared<UsbDeviceId>();
    MessageParcel parcel;
    UsbDeviceId usbDeviceId2;
    ASSERT_TRUE(usbDeviceId->Unmarshalling(parcel, usbDeviceId2));
    ASSERT_TRUE(usbDeviceId2.GetVendorId() == 0);
    ASSERT_TRUE(usbDeviceId2.GetProductId() == 0);
}

/**
 * @tc.name: TestUnmarshalling
 * @tc.desc: Test Test Unmarshalling function.
 * @tc.type: FUNC
 */
HWTEST_F(UsbDeviceIdTest, TestUnmarshalling, TestSize.Level1)
{
    std::shared_ptr<UsbDeviceId> usbDeviceId = std::make_shared<UsbDeviceId>();
    MessageParcel parcel;
    parcel.WriteInt32(111);
    parcel.WriteInt32(222);
    UsbDeviceId usbDeviceId2;
    ASSERT_TRUE(usbDeviceId->Unmarshalling(parcel, usbDeviceId2));
    ASSERT_TRUE(usbDeviceId2.GetVendorId() == 111);
    ASSERT_TRUE(usbDeviceId2.GetProductId() == 222);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
