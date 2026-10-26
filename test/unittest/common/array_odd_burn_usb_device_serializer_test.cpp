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

#include "array_odd_burn_usb_device_serializer.h"
#include "edm_constants.h"
#include "odd_burn_usb_device.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {

const int32_t VID_1 = 111;
const int32_t PID_1 = 222;
const int32_t VID_2 = 333;
const int32_t PID_2 = 444;
const std::string SERIAL_1 = "serial1";
const std::string SERIAL_2 = "serial2";

class ArrayOddBurnUsbDeviceSerializerTest : public testing::Test {
protected:
    void SetUp() override
    {
        serializer_ = ArrayOddBurnUsbDeviceSerializer::GetInstance();
        ASSERT_NE(serializer_, nullptr);

        device1_.SetVendorId(VID_1);
        device1_.SetProductId(PID_1);
        device1_.SetSerial(SERIAL_1);

        device2_.SetVendorId(VID_2);
        device2_.SetProductId(PID_2);
        device2_.SetSerial(SERIAL_2);
    }

    std::shared_ptr<ArrayOddBurnUsbDeviceSerializer> serializer_ = nullptr;
    OddBurnUsbDevice device1_;
    OddBurnUsbDevice device2_;
};

/**
 * @tc.name: TestSerializeWithData
 * @tc.desc: Test Serialize with valid device data.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayOddBurnUsbDeviceSerializerTest, TestSerializeWithData, TestSize.Level1)
{
    std::vector<OddBurnUsbDevice> devices{device1_, device2_};
    std::string jsonString;
    ASSERT_TRUE(serializer_->Serialize(devices, jsonString));
    ASSERT_FALSE(jsonString.empty());
}

/**
 * @tc.name: TestSerializeEmpty
 * @tc.desc: Test Serialize with empty device list.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayOddBurnUsbDeviceSerializerTest, TestSerializeEmpty, TestSize.Level1)
{
    std::vector<OddBurnUsbDevice> devices;
    std::string jsonString;
    ASSERT_TRUE(serializer_->Serialize(devices, jsonString));
    ASSERT_TRUE(jsonString.empty());
}

/**
 * @tc.name: TestDeserializeValid
 * @tc.desc: Test Deserialize with valid JSON.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayOddBurnUsbDeviceSerializerTest, TestDeserializeValid, TestSize.Level1)
{
    std::string jsonString = R"([
        {"vendorId":111, "productId":222, "serial":"serial1"},
        {"vendorId":333, "productId":444, "serial":"serial2"}
    ])";
    std::vector<OddBurnUsbDevice> devices;
    ASSERT_TRUE(serializer_->Deserialize(jsonString, devices));
    ASSERT_EQ(devices.size(), 2u);
    ASSERT_EQ(devices[0].GetVendorId(), VID_1);
    ASSERT_EQ(devices[0].GetProductId(), PID_1);
    ASSERT_EQ(devices[0].GetSerial(), SERIAL_1);
    ASSERT_EQ(devices[1].GetVendorId(), VID_2);
    ASSERT_EQ(devices[1].GetProductId(), PID_2);
    ASSERT_EQ(devices[1].GetSerial(), SERIAL_2);
}

/**
 * @tc.name: TestDeserializeWithoutSerial
 * @tc.desc: Test Deserialize with JSON that has no serial field.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayOddBurnUsbDeviceSerializerTest, TestDeserializeWithoutSerial, TestSize.Level1)
{
    std::string jsonString = R"([{"vendorId":111,"productId":222}])";
    std::vector<OddBurnUsbDevice> devices;
    ASSERT_TRUE(serializer_->Deserialize(jsonString, devices));
    ASSERT_EQ(devices.size(), 1u);
    ASSERT_EQ(devices[0].GetVendorId(), VID_1);
    ASSERT_EQ(devices[0].GetProductId(), PID_1);
    ASSERT_TRUE(devices[0].GetSerial().empty());
}

/**
 * @tc.name: TestDeserializeEmptyString
 * @tc.desc: Test Deserialize with empty string.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayOddBurnUsbDeviceSerializerTest, TestDeserializeEmptyString, TestSize.Level1)
{
    std::string jsonString;
    std::vector<OddBurnUsbDevice> devices;
    ASSERT_TRUE(serializer_->Deserialize(jsonString, devices));
    ASSERT_TRUE(devices.empty());
}

/**
 * @tc.name: TestDeserializeInvalidJson
 * @tc.desc: Test Deserialize with invalid JSON.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayOddBurnUsbDeviceSerializerTest, TestDeserializeInvalidJson, TestSize.Level1)
{
    std::string jsonString = "invalid_json";
    std::vector<OddBurnUsbDevice> devices;
    ASSERT_FALSE(serializer_->Deserialize(jsonString, devices));
}

/**
 * @tc.name: TestDeserializeNotArray
 * @tc.desc: Test Deserialize with JSON that is not an array.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayOddBurnUsbDeviceSerializerTest, TestDeserializeNotArray, TestSize.Level1)
{
    std::string jsonString = R"({"vendorId":111,"productId":222})";
    std::vector<OddBurnUsbDevice> devices;
    ASSERT_FALSE(serializer_->Deserialize(jsonString, devices));
}

/**
 * @tc.name: TestDeserializeMissingRequiredFields
 * @tc.desc: Test Deserialize with JSON missing required vendorId/productId fields.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayOddBurnUsbDeviceSerializerTest, TestDeserializeMissingRequiredFields, TestSize.Level1)
{
    std::string jsonString = R"([{"vendorId":111}])";
    std::vector<OddBurnUsbDevice> devices;
    ASSERT_FALSE(serializer_->Deserialize(jsonString, devices));
}

/**
 * @tc.name: TestSerializeDeserializeRoundTrip
 * @tc.desc: Test Serialize then Deserialize round-trip.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayOddBurnUsbDeviceSerializerTest, TestSerializeDeserializeRoundTrip, TestSize.Level1)
{
    std::vector<OddBurnUsbDevice> original{device1_, device2_};
    std::string jsonString;
    ASSERT_TRUE(serializer_->Serialize(original, jsonString));
    ASSERT_FALSE(jsonString.empty());

    std::vector<OddBurnUsbDevice> result;
    ASSERT_TRUE(serializer_->Deserialize(jsonString, result));
    ASSERT_EQ(result.size(), original.size());
}

/**
 * @tc.name: TestSetUnionPolicyData
 * @tc.desc: Test SetUnionPolicyData with non-overlapping and overlapping data.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayOddBurnUsbDeviceSerializerTest, TestSetUnionPolicyData, TestSize.Level1)
{
    std::vector<OddBurnUsbDevice> data{device1_};
    std::vector<OddBurnUsbDevice> currentData{device2_};
    std::vector<OddBurnUsbDevice> result = serializer_->SetUnionPolicyData(data, currentData);
    ASSERT_EQ(result.size(), 2u);
}

/**
 * @tc.name: TestSetUnionPolicyDataWithOverlap
 * @tc.desc: Test SetUnionPolicyData with overlapping data.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayOddBurnUsbDeviceSerializerTest, TestSetUnionPolicyDataWithOverlap, TestSize.Level1)
{
    std::vector<OddBurnUsbDevice> data{device1_, device2_};
    std::vector<OddBurnUsbDevice> currentData{device1_};
    std::vector<OddBurnUsbDevice> result = serializer_->SetUnionPolicyData(data, currentData);
    ASSERT_EQ(result.size(), 2u);
}

/**
 * @tc.name: TestSetDifferencePolicyData
 * @tc.desc: Test SetDifferencePolicyData removing a subset.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayOddBurnUsbDeviceSerializerTest, TestSetDifferencePolicyData, TestSize.Level1)
{
    std::vector<OddBurnUsbDevice> data{device1_};
    std::vector<OddBurnUsbDevice> currentData{device1_, device2_};
    std::vector<OddBurnUsbDevice> result = serializer_->SetDifferencePolicyData(data, currentData);
    ASSERT_EQ(result.size(), 1u);
    ASSERT_EQ(result[0].GetVendorId(), VID_2);
}

/**
 * @tc.name: TestSetDifferencePolicyDataNonExistent
 * @tc.desc: Test SetDifferencePolicyData removing a device not in current data.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayOddBurnUsbDeviceSerializerTest, TestSetDifferencePolicyDataNonExistent, TestSize.Level1)
{
    std::vector<OddBurnUsbDevice> data{device1_};
    std::vector<OddBurnUsbDevice> currentData{device2_};
    std::vector<OddBurnUsbDevice> result = serializer_->SetDifferencePolicyData(data, currentData);
    ASSERT_EQ(result.size(), 1u);
    ASSERT_EQ(result[0].GetVendorId(), VID_2);
}

/**
 * @tc.name: TestMergePolicy
 * @tc.desc: Test MergePolicy with multiple admin data.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayOddBurnUsbDeviceSerializerTest, TestMergePolicy, TestSize.Level1)
{
    std::vector<std::vector<OddBurnUsbDevice>> allData;
    allData.push_back({device1_});
    allData.push_back({device1_, device2_});
    std::vector<OddBurnUsbDevice> result;
    ASSERT_TRUE(serializer_->MergePolicy(allData, result));
    ASSERT_EQ(result.size(), 2u);
}

/**
 * @tc.name: TestMergePolicyEmpty
 * @tc.desc: Test MergePolicy with empty input.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayOddBurnUsbDeviceSerializerTest, TestMergePolicyEmpty, TestSize.Level1)
{
    std::vector<std::vector<OddBurnUsbDevice>> allData;
    std::vector<OddBurnUsbDevice> result;
    ASSERT_TRUE(serializer_->MergePolicy(allData, result));
    ASSERT_TRUE(result.empty());
}

/**
 * @tc.name: TestWriteAndReadRawDataRoundTrip
 * @tc.desc: Test WriteRawDataToParcel and ReadRawDataFromParcel round-trip.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayOddBurnUsbDeviceSerializerTest, TestWriteAndReadRawDataRoundTrip, TestSize.Level1)
{
    std::vector<OddBurnUsbDevice> devices{device1_, device2_};
    MessageParcel parcel;
    ASSERT_TRUE(serializer_->WriteRawDataToParcel(parcel, devices));

    std::vector<OddBurnUsbDevice> result;
    ASSERT_TRUE(serializer_->ReadRawDataFromParcel(parcel, result));
    ASSERT_EQ(result.size(), 2u);
}

/**
 * @tc.name: TestWriteRawDataEmpty
 * @tc.desc: Test WriteRawDataToParcel and ReadRawDataFromParcel with empty list.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayOddBurnUsbDeviceSerializerTest, TestWriteRawDataEmpty, TestSize.Level1)
{
    std::vector<OddBurnUsbDevice> devices;
    MessageParcel parcel;
    ASSERT_TRUE(serializer_->WriteRawDataToParcel(parcel, devices));

    std::vector<OddBurnUsbDevice> result;
    ASSERT_TRUE(serializer_->ReadRawDataFromParcel(parcel, result));
    ASSERT_TRUE(result.empty());
}

/**
 * @tc.name: TestGetPolicy
 * @tc.desc: Test GetPolicy delegates to ReadRawDataFromParcel.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayOddBurnUsbDeviceSerializerTest, TestGetPolicy, TestSize.Level1)
{
    std::vector<OddBurnUsbDevice> devices{device1_};
    MessageParcel parcel;
    ASSERT_TRUE(serializer_->WriteRawDataToParcel(parcel, devices));

    std::vector<OddBurnUsbDevice> result;
    ASSERT_TRUE(serializer_->GetPolicy(parcel, result));
    ASSERT_EQ(result.size(), 1u);
}

/**
 * @tc.name: TestWritePolicy
 * @tc.desc: Test WritePolicy delegates to WriteRawDataToParcel.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayOddBurnUsbDeviceSerializerTest, TestWritePolicy, TestSize.Level1)
{
    std::vector<OddBurnUsbDevice> devices{device1_, device2_};
    MessageParcel parcel;
    ASSERT_TRUE(serializer_->WritePolicy(parcel, devices));

    std::vector<OddBurnUsbDevice> result;
    ASSERT_TRUE(serializer_->ReadRawDataFromParcel(parcel, result));
    ASSERT_EQ(result.size(), 2u);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
