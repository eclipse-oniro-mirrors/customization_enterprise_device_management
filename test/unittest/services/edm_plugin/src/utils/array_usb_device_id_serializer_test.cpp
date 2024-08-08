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

#include "array_usb_device_id_serializer_test.h"
#include "edm_constants.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
void ArrayUsbDeviceIdSerializerTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void ArrayUsbDeviceIdSerializerTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestSerializeEmpty
 * @tc.desc: Test ClipboardSerializer::Serialize when jsonString is empty
 * @tc.type: FUNC
 */
HWTEST_F(ArrayUsbDeviceIdSerializerTest, TestSerializeEmpty, TestSize.Level1)
{
    auto serializer = ArrayUsbDeviceIdSerializer::GetInstance();
    std::string jsonString;
    std::vector<UsbDeviceId> dataObj;
    bool ret = serializer->Serialize(dataObj, jsonString);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(jsonString.empty());
}

/**
 * @tc.name: TestSerializeSuc
 * @tc.desc: Test ClipboardSerializer::Serialize
 * @tc.type: FUNC
 */
HWTEST_F(ArrayUsbDeviceIdSerializerTest, TestSerializeSuc, TestSize.Level1)
{
    auto serializer = ArrayUsbDeviceIdSerializer::GetInstance();
    std::string jsonString;
    std::vector<UsbDeviceId> dataObj;
    UsbDeviceId id1;
    id1.SetVendorId(111);
    id1.SetProductId(222);
    dataObj.push_back(id1);
    bool ret = serializer->Serialize(dataObj, jsonString);
    ASSERT_TRUE(ret);
    ASSERT_FALSE(jsonString.empty());
}

/**
 * @tc.name: TestGetPolicyOutOfRange
 * @tc.desc: Test ClipboardSerializer::GetPolicy out of range
 * @tc.type: FUNC
 */
HWTEST_F(ArrayUsbDeviceIdSerializerTest, TestGetPolicyOutOfRange, TestSize.Level1)
{
    auto serializer = ArrayUsbDeviceIdSerializer::GetInstance();
    MessageParcel data;
    data.WriteInt32(EdmConstants::ALLOWED_USB_DEVICES_MAX_SIZE + 1);
    std::vector<UsbDeviceId> dataObj;
    bool ret = serializer->GetPolicy(data, dataObj);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TestGetPolicy
 * @tc.desc: Test ClipboardSerializer::GetPolicy
 * @tc.type: FUNC
 */
HWTEST_F(ArrayUsbDeviceIdSerializerTest, TestGetPolicy, TestSize.Level1)
{
    auto serializer = ArrayUsbDeviceIdSerializer::GetInstance();
    MessageParcel data;
    std::vector<UsbDeviceId> dataObj;
    data.WriteInt32(1);
    data.WriteInt32(111);
    data.WriteInt32(222);
    bool ret = serializer->GetPolicy(data, dataObj);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(dataObj[0].GetVendorId() == 111);
    ASSERT_TRUE(dataObj[0].GetProductId() == 222);
}

/**
 * @tc.name: TestWritePolicy
 * @tc.desc: Test ClipboardSerializer::WritePolicy
 * @tc.type: FUNC
 */
HWTEST_F(ArrayUsbDeviceIdSerializerTest, TestWritePolicy, TestSize.Level1)
{
    auto serializer = ArrayUsbDeviceIdSerializer::GetInstance();
    MessageParcel reply;
    std::vector<UsbDeviceId> dataObj;
    UsbDeviceId id1;
    id1.SetVendorId(111);
    id1.SetProductId(222);
    dataObj.push_back(id1);
    bool ret = serializer->WritePolicy(reply, dataObj);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(reply.ReadInt32() == 111);
    ASSERT_TRUE(reply.ReadInt32() == 222);
}

/**
 * @tc.name: TestMergePolicy
 * @tc.desc: Test ClipboardSerializer::MergePolicy
 * @tc.type: FUNC
 */
HWTEST_F(ArrayUsbDeviceIdSerializerTest, TestMergePolicy, TestSize.Level1)
{
    auto serializer = ArrayUsbDeviceIdSerializer::GetInstance();
    std::vector<std::vector<UsbDeviceId>> dataObj;
    std::vector<UsbDeviceId> data;
    UsbDeviceId id1;
    id1.SetVendorId(111);
    id1.SetProductId(222);
    data.push_back(id1);
    dataObj.push_back(data);
    std::vector<UsbDeviceId> result;
    bool ret = serializer->MergePolicy(dataObj, result);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(result.size() == 1);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS