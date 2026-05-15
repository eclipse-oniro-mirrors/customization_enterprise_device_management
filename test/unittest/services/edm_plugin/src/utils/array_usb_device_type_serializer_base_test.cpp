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

#include "array_usb_device_type_serializer.h"
#include "array_usb_device_type_serializer_base.h"
#include "edm_constants.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string TEST_POLICY_DATA =
    "[{\"baseClass\":3,\"subClass\":1,\"protocol\":2,\"isDeviceType\":false,\"isDeviceTypeAllMatch\":false}]";

class ArrayUsbDeviceTypeSerializerBaseTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);
    static void TearDownTestSuite(void);
};

void ArrayUsbDeviceTypeSerializerBaseTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void ArrayUsbDeviceTypeSerializerBaseTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is original ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: ArrayUsbDeviceTypeSerializerBase_SetUnionPolicyData_EmptyData_Success
 * @tc.desc: Test SetUnionPolicyData when both data and currentData are empty.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayUsbDeviceTypeSerializerBaseTest,
    ArrayUsbDeviceTypeSerializerBase_SetUnionPolicyData_EmptyData_Success, TestSize.Level1)
{
    auto serializer = ArrayUsbDeviceTypeSerializer::GetInstance();
    std::vector<USB::UsbDeviceType> data;
    std::vector<USB::UsbDeviceType> currentData;
    std::vector<USB::UsbDeviceType> res = serializer->SetUnionPolicyData(data, currentData);
    ASSERT_TRUE(res.empty());
}

/**
 * @tc.name: ArrayUsbDeviceTypeSerializerBase_SetUnionPolicyData_WithData_Success
 * @tc.desc: Test SetUnionPolicyData with non-empty data.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayUsbDeviceTypeSerializerBaseTest,
    ArrayUsbDeviceTypeSerializerBase_SetUnionPolicyData_WithData_Success, TestSize.Level1)
{
    auto serializer = ArrayUsbDeviceTypeSerializer::GetInstance();
    std::vector<USB::UsbDeviceType> data;
    USB::UsbDeviceType type1;
    type1.baseClass = 1;
    type1.subClass = 2;
    type1.protocol = 3;
    type1.isDeviceType = false;
    type1.isDeviceTypeAllMatch = false;
    data.push_back(type1);

    std::vector<USB::UsbDeviceType> currentData;
    USB::UsbDeviceType type2;
    type2.baseClass = 4;
    type2.subClass = 5;
    type2.protocol = 6;
    type2.isDeviceType = true;
    type2.isDeviceTypeAllMatch = false;
    currentData.push_back(type2);

    std::vector<USB::UsbDeviceType> res = serializer->SetUnionPolicyData(data, currentData);
    ASSERT_EQ(res.size(), 2);
}

/**
 * @tc.name: ArrayUsbDeviceTypeSerializerBase_SetUnionPolicyData_DuplicateData_Success
 * @tc.desc: Test SetUnionPolicyData with duplicate data.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayUsbDeviceTypeSerializerBaseTest,
    ArrayUsbDeviceTypeSerializerBase_SetUnionPolicyData_DuplicateData_Success, TestSize.Level1)
{
    auto serializer = ArrayUsbDeviceTypeSerializer::GetInstance();
    std::vector<USB::UsbDeviceType> data;
    USB::UsbDeviceType type1;
    type1.baseClass = 1;
    type1.subClass = 2;
    type1.protocol = 3;
    type1.isDeviceType = false;
    type1.isDeviceTypeAllMatch = false;
    data.push_back(type1);

    std::vector<USB::UsbDeviceType> currentData;
    USB::UsbDeviceType type2;
    type2.baseClass = 1;
    type2.subClass = 2;
    type2.protocol = 3;
    type2.isDeviceType = false;
    type2.isDeviceTypeAllMatch = false;
    currentData.push_back(type2);

    std::vector<USB::UsbDeviceType> res = serializer->SetUnionPolicyData(data, currentData);
    ASSERT_EQ(res.size(), 1);
}

/**
 * @tc.name: ArrayUsbDeviceTypeSerializerBase_SetDifferencePolicyData_EmptyData_Success
 * @tc.desc: Test SetDifferencePolicyData when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayUsbDeviceTypeSerializerBaseTest,
    ArrayUsbDeviceTypeSerializerBase_SetDifferencePolicyData_EmptyData_Success, TestSize.Level1)
{
    auto serializer = ArrayUsbDeviceTypeSerializer::GetInstance();
    std::vector<USB::UsbDeviceType> data;
    std::vector<USB::UsbDeviceType> currentData;
    USB::UsbDeviceType type;
    type.baseClass = 1;
    type.subClass = 2;
    type.protocol = 3;
    type.isDeviceType = false;
    type.isDeviceTypeAllMatch = false;
    currentData.push_back(type);

    std::vector<USB::UsbDeviceType> res = serializer->SetDifferencePolicyData(data, currentData);
    ASSERT_EQ(res.size(), 1);
}

/**
 * @tc.name: ArrayUsbDeviceTypeSerializerBase_SetDifferencePolicyData_WithData_Success
 * @tc.desc: Test SetDifferencePolicyData with non-empty data.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayUsbDeviceTypeSerializerBaseTest,
    ArrayUsbDeviceTypeSerializerBase_SetDifferencePolicyData_WithData_Success, TestSize.Level1)
{
    auto serializer = ArrayUsbDeviceTypeSerializer::GetInstance();
    std::vector<USB::UsbDeviceType> data;
    USB::UsbDeviceType type1;
    type1.baseClass = 1;
    type1.subClass = 2;
    type1.protocol = 3;
    type1.isDeviceType = false;
    type1.isDeviceTypeAllMatch = false;
    data.push_back(type1);

    std::vector<USB::UsbDeviceType> currentData;
    USB::UsbDeviceType type2;
    type2.baseClass = 1;
    type2.subClass = 2;
    type2.protocol = 3;
    type2.isDeviceType = false;
    type2.isDeviceTypeAllMatch = false;
    currentData.push_back(type2);

    USB::UsbDeviceType type3;
    type3.baseClass = 4;
    type3.subClass = 5;
    type3.protocol = 6;
    type3.isDeviceType = true;
    type3.isDeviceTypeAllMatch = false;
    currentData.push_back(type3);

    std::vector<USB::UsbDeviceType> res = serializer->SetDifferencePolicyData(data, currentData);
    ASSERT_EQ(res.size(), 1);
    ASSERT_EQ(res[0].baseClass, 4);
}

/**
 * @tc.name: ArrayUsbDeviceTypeSerializerBase_Serialize_EmptyData_Success
 * @tc.desc: Test Serialize when dataObj is empty.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayUsbDeviceTypeSerializerBaseTest,
    ArrayUsbDeviceTypeSerializerBase_Serialize_EmptyData_Success, TestSize.Level1)
{
    auto serializer = ArrayUsbDeviceTypeSerializer::GetInstance();
    std::string jsonString;
    std::vector<USB::UsbDeviceType> dataObj;
    bool ret = serializer->Serialize(dataObj, jsonString);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(jsonString.empty());
}

/**
 * @tc.name: ArrayUsbDeviceTypeSerializerBase_Serialize_WithData_Success
 * @tc.desc: Test Serialize with non-empty dataObj.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayUsbDeviceTypeSerializerBaseTest,
    ArrayUsbDeviceTypeSerializerBase_Serialize_WithData_Success, TestSize.Level1)
{
    auto serializer = ArrayUsbDeviceTypeSerializer::GetInstance();
    std::string jsonString;
    std::vector<USB::UsbDeviceType> dataObj;
    USB::UsbDeviceType type;
    type.baseClass = 1;
    type.subClass = 2;
    type.protocol = 3;
    type.isDeviceType = false;
    type.isDeviceTypeAllMatch = false;
    dataObj.push_back(type);

    bool ret = serializer->Serialize(dataObj, jsonString);
    ASSERT_TRUE(ret);
    ASSERT_FALSE(jsonString.empty());
}

/**
 * @tc.name: ArrayUsbDeviceTypeSerializerBase_Serialize_ExceedMaxSize_Fail
 * @tc.desc: Test Serialize when dataObj size exceeds max size.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayUsbDeviceTypeSerializerBaseTest,
    ArrayUsbDeviceTypeSerializerBase_Serialize_ExceedMaxSize_Fail, TestSize.Level1)
{
    auto serializer = ArrayUsbDeviceTypeSerializer::GetInstance();
    std::string jsonString;
    std::vector<USB::UsbDeviceType> dataObj;
    for (uint32_t i = 0; i <= EdmConstants::DISALLOWED_USB_DEVICES_TYPES_MAX_SIZE; i++) {
        USB::UsbDeviceType type;
        type.baseClass = i % 256;
        type.subClass = (i + 1) % 256;
        type.protocol = (i + 2) % 256;
        type.isDeviceType = false;
        type.isDeviceTypeAllMatch = false;
        dataObj.push_back(type);
    }

    bool ret = serializer->Serialize(dataObj, jsonString);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: ArrayUsbDeviceTypeSerializerBase_Deserialize_EmptyString_Success
 * @tc.desc: Test Deserialize when jsonString is empty.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayUsbDeviceTypeSerializerBaseTest,
    ArrayUsbDeviceTypeSerializerBase_Deserialize_EmptyString_Success, TestSize.Level1)
{
    auto serializer = ArrayUsbDeviceTypeSerializer::GetInstance();
    std::string jsonString = "";
    std::vector<USB::UsbDeviceType> dataObj;
    bool ret = serializer->Deserialize(jsonString, dataObj);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: ArrayUsbDeviceTypeSerializerBase_Deserialize_InvalidJson_Fail
 * @tc.desc: Test Deserialize with invalid JSON string.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayUsbDeviceTypeSerializerBaseTest,
    ArrayUsbDeviceTypeSerializerBase_Deserialize_InvalidJson_Fail, TestSize.Level1)
{
    auto serializer = ArrayUsbDeviceTypeSerializer::GetInstance();
    std::string jsonString = "invalid json";
    std::vector<USB::UsbDeviceType> dataObj;
    bool ret = serializer->Deserialize(jsonString, dataObj);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: ArrayUsbDeviceTypeSerializerBase_Deserialize_RootNotArray_Fail
 * @tc.desc: Test Deserialize when root is not an array.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayUsbDeviceTypeSerializerBaseTest,
    ArrayUsbDeviceTypeSerializerBase_Deserialize_RootNotArray_Fail, TestSize.Level1)
{
    auto serializer = ArrayUsbDeviceTypeSerializer::GetInstance();
    std::string jsonString = R"({"key": "value"})";
    std::vector<USB::UsbDeviceType> dataObj;
    bool ret = serializer->Deserialize(jsonString, dataObj);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: ArrayUsbDeviceTypeSerializerBase_Deserialize_Success
 * @tc.desc: Test Deserialize with valid JSON string.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayUsbDeviceTypeSerializerBaseTest,
    ArrayUsbDeviceTypeSerializerBase_Deserialize_Success, TestSize.Level1)
{
    auto serializer = ArrayUsbDeviceTypeSerializer::GetInstance();
    std::string jsonString =
        R"([{"baseClass":1,"subClass":2,"protocol":3,"isDeviceType":false,"isDeviceTypeAllMatch":false}])";
    std::vector<USB::UsbDeviceType> dataObj;
    bool ret = serializer->Deserialize(jsonString, dataObj);
    ASSERT_TRUE(ret);
    ASSERT_EQ(dataObj.size(), 1);
    ASSERT_EQ(dataObj[0].baseClass, 1);
    ASSERT_EQ(dataObj[0].subClass, 2);
    ASSERT_EQ(dataObj[0].protocol, 3);
    ASSERT_FALSE(dataObj[0].isDeviceType);
    ASSERT_FALSE(dataObj[0].isDeviceTypeAllMatch);
}

/**
 * @tc.name: ArrayUsbDeviceTypeSerializerBase_Deserialize_MissingField_Fail
 * @tc.desc: Test Deserialize when JSON is missing required field.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayUsbDeviceTypeSerializerBaseTest,
    ArrayUsbDeviceTypeSerializerBase_Deserialize_MissingField_Fail, TestSize.Level1)
{
    auto serializer = ArrayUsbDeviceTypeSerializer::GetInstance();
    std::string jsonString = R"([{"baseClass":1,"subClass":2,"protocol":3,"isDeviceType":false}])";
    std::vector<USB::UsbDeviceType> dataObj;
    bool ret = serializer->Deserialize(jsonString, dataObj);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: ArrayUsbDeviceTypeSerializerBase_Deserialize_MalformedJson_Fail
 * @tc.desc: Test Deserialize with malformed JSON.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayUsbDeviceTypeSerializerBaseTest,
    ArrayUsbDeviceTypeSerializerBase_Deserialize_MalformedJson_Fail, TestSize.Level1)
{
    auto serializer = ArrayUsbDeviceTypeSerializer::GetInstance();
    std::string jsonString = R"([
        {"baseClass": 1, "subClass": 2,
        {"baseClass": 3, "subClass": 4}
    ])";
    std::vector<USB::UsbDeviceType> dataObj;
    bool ret = serializer->Deserialize(jsonString, dataObj);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: ArrayUsbDeviceTypeSerializerBase_GetPolicy_OutOfRange_Fail
 * @tc.desc: Test GetPolicy when size exceeds max size.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayUsbDeviceTypeSerializerBaseTest,
    ArrayUsbDeviceTypeSerializerBase_GetPolicy_OutOfRange_Fail, TestSize.Level1)
{
    auto serializer = ArrayUsbDeviceTypeSerializer::GetInstance();
    MessageParcel data;
    data.WriteUint32(EdmConstants::DISALLOWED_USB_DEVICES_TYPES_MAX_SIZE + 1);
    std::vector<USB::UsbDeviceType> dataObj;
    bool ret = serializer->GetPolicy(data, dataObj);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: ArrayUsbDeviceTypeSerializerBase_GetPolicy_Success
 * @tc.desc: Test GetPolicy with valid data.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayUsbDeviceTypeSerializerBaseTest,
    ArrayUsbDeviceTypeSerializerBase_GetPolicy_Success, TestSize.Level1)
{
    auto serializer = ArrayUsbDeviceTypeSerializer::GetInstance();
    MessageParcel data;
    std::vector<USB::UsbDeviceType> dataObj;
    data.WriteUint32(1);
    USB::UsbDeviceType type;
    type.baseClass = 1;
    type.subClass = 2;
    type.protocol = 3;
    type.isDeviceType = false;
    type.isDeviceTypeAllMatch = false;
    type.Marshalling(data);
    bool ret = serializer->GetPolicy(data, dataObj);
    ASSERT_TRUE(ret);
    ASSERT_EQ(dataObj.size(), 1);
    ASSERT_EQ(dataObj[0].baseClass, 1);
}

/**
 * @tc.name: ArrayUsbDeviceTypeSerializerBase_GetPolicy_InvalidBaseClass_Fail
 * @tc.desc: Test GetPolicy when baseClass is invalid (negative).
 * @tc.type: FUNC
 */
HWTEST_F(ArrayUsbDeviceTypeSerializerBaseTest,
    ArrayUsbDeviceTypeSerializerBase_GetPolicy_InvalidBaseClass_Fail, TestSize.Level1)
{
    auto serializer = ArrayUsbDeviceTypeSerializer::GetInstance();
    MessageParcel data;
    std::vector<USB::UsbDeviceType> dataObj;
    data.WriteUint32(1);
    USB::UsbDeviceType type;
    type.baseClass = -1;
    type.subClass = 2;
    type.protocol = 3;
    type.isDeviceType = false;
    type.isDeviceTypeAllMatch = false;
    type.Marshalling(data);
    bool ret = serializer->GetPolicy(data, dataObj);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: ArrayUsbDeviceTypeSerializerBase_GetPolicy_InvalidSubClass_Fail
 * @tc.desc: Test GetPolicy when subClass is invalid (negative).
 * @tc.type: FUNC
 */
HWTEST_F(ArrayUsbDeviceTypeSerializerBaseTest,
    ArrayUsbDeviceTypeSerializerBase_GetPolicy_InvalidSubClass_Fail, TestSize.Level1)
{
    auto serializer = ArrayUsbDeviceTypeSerializer::GetInstance();
    MessageParcel data;
    std::vector<USB::UsbDeviceType> dataObj;
    data.WriteUint32(1);
    USB::UsbDeviceType type;
    type.baseClass = 1;
    type.subClass = -1;
    type.protocol = 3;
    type.isDeviceType = false;
    type.isDeviceTypeAllMatch = false;
    type.Marshalling(data);
    bool ret = serializer->GetPolicy(data, dataObj);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: ArrayUsbDeviceTypeSerializerBase_GetPolicy_InvalidProtocol_Fail
 * @tc.desc: Test GetPolicy when protocol is invalid (negative).
 * @tc.type: FUNC
 */
HWTEST_F(ArrayUsbDeviceTypeSerializerBaseTest,
    ArrayUsbDeviceTypeSerializerBase_GetPolicy_InvalidProtocol_Fail, TestSize.Level1)
{
    auto serializer = ArrayUsbDeviceTypeSerializer::GetInstance();
    MessageParcel data;
    std::vector<USB::UsbDeviceType> dataObj;
    data.WriteUint32(1);
    USB::UsbDeviceType type;
    type.baseClass = 1;
    type.subClass = 2;
    type.protocol = -1;
    type.isDeviceType = false;
    type.isDeviceTypeAllMatch = false;
    type.Marshalling(data);
    bool ret = serializer->GetPolicy(data, dataObj);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: ArrayUsbDeviceTypeSerializerBase_WritePolicy_Success
 * @tc.desc: Test WritePolicy always returns true.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayUsbDeviceTypeSerializerBaseTest,
    ArrayUsbDeviceTypeSerializerBase_WritePolicy_Success, TestSize.Level1)
{
    auto serializer = ArrayUsbDeviceTypeSerializer::GetInstance();
    MessageParcel reply;
    std::vector<USB::UsbDeviceType> dataObj;
    bool ret = serializer->WritePolicy(reply, dataObj);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: ArrayUsbDeviceTypeSerializerBase_MergePolicy_Success
 * @tc.desc: Test MergePolicy with multiple data vectors.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayUsbDeviceTypeSerializerBaseTest,
    ArrayUsbDeviceTypeSerializerBase_MergePolicy_Success, TestSize.Level1)
{
    auto serializer = ArrayUsbDeviceTypeSerializer::GetInstance();
    std::vector<std::vector<USB::UsbDeviceType>> dataObj;
    std::vector<USB::UsbDeviceType> data1;
    USB::UsbDeviceType type1;
    type1.baseClass = 1;
    type1.subClass = 2;
    type1.protocol = 3;
    type1.isDeviceType = false;
    type1.isDeviceTypeAllMatch = false;
    data1.push_back(type1);
    dataObj.push_back(data1);

    std::vector<USB::UsbDeviceType> data2;
    USB::UsbDeviceType type2;
    type2.baseClass = 4;
    type2.subClass = 5;
    type2.protocol = 6;
    type2.isDeviceType = true;
    type2.isDeviceTypeAllMatch = false;
    data2.push_back(type2);
    dataObj.push_back(data2);

    std::vector<USB::UsbDeviceType> result;
    serializer->MergePolicy(dataObj, result);
    ASSERT_EQ(result.size(), 2);
}

/**
 * @tc.name: ArrayUsbDeviceTypeSerializerBase_MergePolicy_Duplicate_Success
 * @tc.desc: Test MergePolicy with duplicate data vectors.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayUsbDeviceTypeSerializerBaseTest,
    ArrayUsbDeviceTypeSerializerBase_MergePolicy_Duplicate_Success, TestSize.Level1)
{
    auto serializer = ArrayUsbDeviceTypeSerializer::GetInstance();
    std::vector<std::vector<USB::UsbDeviceType>> dataObj;
    std::vector<USB::UsbDeviceType> data1;
    USB::UsbDeviceType type1;
    type1.baseClass = 1;
    type1.subClass = 2;
    type1.protocol = 3;
    type1.isDeviceType = false;
    type1.isDeviceTypeAllMatch = false;
    data1.push_back(type1);
    dataObj.push_back(data1);

    std::vector<USB::UsbDeviceType> data2;
    USB::UsbDeviceType type2;
    type2.baseClass = 1;
    type2.subClass = 2;
    type2.protocol = 3;
    type2.isDeviceType = false;
    type2.isDeviceTypeAllMatch = false;
    data2.push_back(type2);
    dataObj.push_back(data2);

    std::vector<USB::UsbDeviceType> result;
    serializer->MergePolicy(dataObj, result);
    ASSERT_EQ(result.size(), 1);
}

/**
 * @tc.name: ArrayUsbDeviceTypeSerializerBase_Deserialize_WrongFieldType_Fail
 * @tc.desc: Test Deserialize when JSON field has wrong type.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayUsbDeviceTypeSerializerBaseTest,
    ArrayUsbDeviceTypeSerializerBase_Deserialize_WrongFieldType_Fail, TestSize.Level1)
{
    auto serializer = ArrayUsbDeviceTypeSerializer::GetInstance();
    std::string jsonString =
        R"([{"baseClass":"invalid","subClass":2,"protocol":3,"isDeviceType":false,"isDeviceTypeAllMatch":false}])";
    std::vector<USB::UsbDeviceType> dataObj;
    bool ret = serializer->Deserialize(jsonString, dataObj);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: ArrayUsbDeviceTypeSerializerBase_GetPolicy_BaseClassExceedMaxValue_Fail
 * @tc.desc: Test GetPolicy when baseClass exceeds max value (255).
 * @tc.type: FUNC
 */
HWTEST_F(ArrayUsbDeviceTypeSerializerBaseTest,
    ArrayUsbDeviceTypeSerializerBase_GetPolicy_BaseClassExceedMaxValue_Fail, TestSize.Level1)
{
    auto serializer = ArrayUsbDeviceTypeSerializer::GetInstance();
    MessageParcel data;
    std::vector<USB::UsbDeviceType> dataObj;
    data.WriteUint32(1);
    USB::UsbDeviceType type;
    type.baseClass = 256;
    type.subClass = 2;
    type.protocol = 3;
    type.isDeviceType = false;
    type.isDeviceTypeAllMatch = false;
    type.Marshalling(data);
    bool ret = serializer->GetPolicy(data, dataObj);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: ArrayUsbDeviceTypeSerializerBase_GetPolicy_SubClassExceedMaxValue_Fail
 * @tc.desc: Test GetPolicy when subClass exceeds max value (255).
 * @tc.type: FUNC
 */
HWTEST_F(ArrayUsbDeviceTypeSerializerBaseTest,
    ArrayUsbDeviceTypeSerializerBase_GetPolicy_SubClassExceedMaxValue_Fail, TestSize.Level1)
{
    auto serializer = ArrayUsbDeviceTypeSerializer::GetInstance();
    MessageParcel data;
    std::vector<USB::UsbDeviceType> dataObj;
    data.WriteUint32(1);
    USB::UsbDeviceType type;
    type.baseClass = 1;
    type.subClass = 256;
    type.protocol = 3;
    type.isDeviceType = false;
    type.isDeviceTypeAllMatch = false;
    type.Marshalling(data);
    bool ret = serializer->GetPolicy(data, dataObj);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: ArrayUsbDeviceTypeSerializerBase_GetPolicy_ProtocolExceedMaxValue_Fail
 * @tc.desc: Test GetPolicy when protocol exceeds max value (255).
 * @tc.type: FUNC
 */
HWTEST_F(ArrayUsbDeviceTypeSerializerBaseTest,
    ArrayUsbDeviceTypeSerializerBase_GetPolicy_ProtocolExceedMaxValue_Fail, TestSize.Level1)
{
    auto serializer = ArrayUsbDeviceTypeSerializer::GetInstance();
    MessageParcel data;
    std::vector<USB::UsbDeviceType> dataObj;
    data.WriteUint32(1);
    USB::UsbDeviceType type;
    type.baseClass = 1;
    type.subClass = 2;
    type.protocol = 256;
    type.isDeviceType = false;
    type.isDeviceTypeAllMatch = false;
    type.Marshalling(data);
    bool ret = serializer->GetPolicy(data, dataObj);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: ArrayUsbDeviceTypeSerializerBase_MergePolicy_EmptyData_Success
 * @tc.desc: Test MergePolicy with empty data vectors.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayUsbDeviceTypeSerializerBaseTest,
    ArrayUsbDeviceTypeSerializerBase_MergePolicy_EmptyData_Success, TestSize.Level1)
{
    auto serializer = ArrayUsbDeviceTypeSerializer::GetInstance();
    std::vector<std::vector<USB::UsbDeviceType>> dataObj;
    std::vector<USB::UsbDeviceType> result;
    serializer->MergePolicy(dataObj, result);
    ASSERT_TRUE(result.empty());
}

/**
 * @tc.name: ArrayUsbDeviceTypeSerializerBase_SetDifferencePolicyData_AllSameData_EmptyResult
 * @tc.desc: Test SetDifferencePolicyData when all data is same, result should be empty.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayUsbDeviceTypeSerializerBaseTest,
    ArrayUsbDeviceTypeSerializerBase_SetDifferencePolicyData_AllSameData_EmptyResult, TestSize.Level1)
{
    auto serializer = ArrayUsbDeviceTypeSerializer::GetInstance();
    std::vector<USB::UsbDeviceType> data;
    USB::UsbDeviceType type1;
    type1.baseClass = 1;
    type1.subClass = 2;
    type1.protocol = 3;
    type1.isDeviceType = false;
    type1.isDeviceTypeAllMatch = false;
    data.push_back(type1);

    std::vector<USB::UsbDeviceType> currentData;
    USB::UsbDeviceType type2;
    type2.baseClass = 1;
    type2.subClass = 2;
    type2.protocol = 3;
    type2.isDeviceType = false;
    type2.isDeviceTypeAllMatch = false;
    currentData.push_back(type2);

    std::vector<USB::UsbDeviceType> res = serializer->SetDifferencePolicyData(data, currentData);
    ASSERT_TRUE(res.empty());
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
