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
 * @tc.name: TestSetDifferencePolicyDataEmpty
 * @tc.desc: Test ArrayUsbDeviceIdSerializerTest::SetDifferencePolicy when data is empty
 * @tc.type: FUNC
 */
HWTEST_F(ArrayUsbDeviceIdSerializerTest, TestSetDifferencePolicyDataEmpty, TestSize.Level1)
{
    auto serializer = ArrayUsbDeviceIdSerializer::GetInstance();
    std::vector<UsbDeviceId> data;
    std::vector<UsbDeviceId> currentData;
    std::vector<UsbDeviceId> res = serializer->SetDifferencePolicyData(data, currentData);
    ASSERT_TRUE(res.empty());
}

/**
 * @tc.name: TestSerializeEmpty
 * @tc.desc: Test ArrayUsbDeviceIdSerializerTest::Serialize when jsonString is empty
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
 * @tc.desc: Test ArrayUsbDeviceIdSerializerTest::Serialize
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
 * @tc.name: TestDeserializeWithEmptyString
 * @tc.desc: Test ArrayUsbDeviceIdSerializerTest::Deserialize jsonString is empty
 * @tc.type: FUNC
 */
HWTEST_F(ArrayUsbDeviceIdSerializerTest, TestDeserializeWithEmptyString, TestSize.Level1)
{
    auto serializer = ArrayUsbDeviceIdSerializer::GetInstance();
    std::string jsonString = "";
    std::vector<UsbDeviceId> dataObj;
    bool ret = serializer->Deserialize(jsonString, dataObj);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: TestDeserializeRootIsNotArray
 * @tc.desc: Test ArrayUsbDeviceIdSerializerTest::Deserialize RootIsNotArray
 * @tc.type: FUNC
 */
HWTEST_F(ArrayUsbDeviceIdSerializerTest, TestDeserializeRootIsNotArray, TestSize.Level1)
{
    auto serializer = ArrayUsbDeviceIdSerializer::GetInstance();
    std::string jsonString = R"({"key": "value"})";
    std::vector<UsbDeviceId> dataObj;
    bool ret = serializer->Deserialize(jsonString, dataObj);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TestDeserializeSuc
 * @tc.desc: Test ArrayUsbDeviceIdSerializerTest::Deserialize
 * @tc.type: FUNC
 */
HWTEST_F(ArrayUsbDeviceIdSerializerTest, TestDeserializeSuc, TestSize.Level1)
{
    auto serializer = ArrayUsbDeviceIdSerializer::GetInstance();
    std::string jsonString = R"([{"vendorId": 1234, "productId": 5678}])";
    std::vector<UsbDeviceId> dataObj;
    bool ret = serializer->Deserialize(jsonString, dataObj);
    ASSERT_TRUE(ret);
    ASSERT_EQ(dataObj.size(), 1);
    ASSERT_EQ(dataObj[0].GetVendorId(), 1234);
    ASSERT_EQ(dataObj[0].GetProductId(), 5678);
}

/**
 * @tc.name: TestDeserializeMalformedJson
 * @tc.desc: Test ArrayUsbDeviceIdSerializerTest::Deserialize MalformedJson
 * @tc.type: FUNC
 */
HWTEST_F(ArrayUsbDeviceIdSerializerTest, TestDeserializeMalformedJson, TestSize.Level1)
{
    auto serializer = ArrayUsbDeviceIdSerializer::GetInstance();
    std::string jsonString = R"([
        {"vendorId": 1234, "productId": 5678,
        {"vendorId": 4321, "productId": 8765}
    ])";
    std::vector<UsbDeviceId> dataObj;
    bool ret = serializer->Deserialize(jsonString, dataObj);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TestGetPolicyOutOfRange
 * @tc.desc: Test ArrayUsbDeviceIdSerializerTest::GetPolicy out of range
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
 * @tc.desc: Test ArrayUsbDeviceIdSerializerTest::GetPolicy
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
 * @tc.desc: Test ArrayUsbDeviceIdSerializerTest::WritePolicy
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
 * @tc.desc: Test ArrayUsbDeviceIdSerializerTest::MergePolicy
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
    serializer->MergePolicy(dataObj, result);
    ASSERT_TRUE(result.size() == 1);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS