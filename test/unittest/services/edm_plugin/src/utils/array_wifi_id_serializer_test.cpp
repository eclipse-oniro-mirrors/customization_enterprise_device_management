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

#include "array_wifi_id_serializer_test.h"
#include "edm_constants.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
void ArrayWifiIdSerializerTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void ArrayWifiIdSerializerTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestSetDifferencePolicyDataEmpty
 * @tc.desc: Test ArrayWifiIdSerializerTest::SetDifferencePolicy when data is empty
 * @tc.type: FUNC
 */
    HWTEST_F(ArrayWifiIdSerializerTest, TestSetDifferencePolicyDataEmpty, TestSize.Level1)
{
    auto serializer = ArrayWifiIdSerializer::GetInstance();
    std::vector<WifiId> data;
    std::vector<WifiId> currentData;
    std::vector<WifiId> res = serializer->SetDifferencePolicyData(data, currentData);
    ASSERT_TRUE(res.empty());
}

/**
 * @tc.name: TestSerializeEmpty
 * @tc.desc: Test ArrayWifiIdSerializerTest::Serialize when jsonString is empty
 * @tc.type: FUNC
 */
    HWTEST_F(ArrayWifiIdSerializerTest, TestSerializeEmpty, TestSize.Level1)
{
    auto serializer = ArrayWifiIdSerializer::GetInstance();
    std::string jsonString;
    std::vector<WifiId> dataObj;
    bool ret = serializer->Serialize(dataObj, jsonString);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(jsonString.empty());
}

/**
 * @tc.name: TestSerializeSuc
 * @tc.desc: Test ArrayWifiIdSerializerTest::Serialize
 * @tc.type: FUNC
 */
    HWTEST_F(ArrayWifiIdSerializerTest, TestSerializeSuc, TestSize.Level1)
{
    auto serializer = ArrayWifiIdSerializer::GetInstance();
    std::string jsonString;
    std::vector<WifiId> dataObj;
    WifiId id1;
    id1.SetSsid("wifi_name");
    id1.SetBssid("68:77:24:77:A6:D9");
    dataObj.push_back(id1);
    bool ret = serializer->Serialize(dataObj, jsonString);
    ASSERT_TRUE(ret);
    ASSERT_FALSE(jsonString.empty());
}

/**
 * @tc.name: TestDeserializeWithEmptyString
 * @tc.desc: Test ArrayWifiIdSerializerTest::Deserialize jsonString is empty
 * @tc.type: FUNC
 */
HWTEST_F(ArrayWifiIdSerializerTest, TestDeserializeWithEmptyString, TestSize.Level1)
{
    auto serializer = ArrayWifiIdSerializer::GetInstance();
    std::string jsonString = "";
    std::vector<WifiId> dataObj;
    bool ret = serializer->Deserialize(jsonString, dataObj);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: TestDeserializeRootIsNotArray
 * @tc.desc: Test ArrayWifiIdSerializerTest::Deserialize RootIsNotArray
 * @tc.type: FUNC
 */
HWTEST_F(ArrayWifiIdSerializerTest, TestDeserializeRootIsNotArray, TestSize.Level1)
{
    auto serializer = ArrayWifiIdSerializer::GetInstance();
    std::string jsonString = R"({"key": "value"})";
    std::vector<WifiId> dataObj;
    bool ret = serializer->Deserialize(jsonString, dataObj);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TestDeserializeSuc
 * @tc.desc: Test ArrayWifiIdSerializerTest::Deserialize
 * @tc.type: FUNC
 */
HWTEST_F(ArrayWifiIdSerializerTest, TestDeserializeSuc, TestSize.Level1)
{
    auto serializer = ArrayWifiIdSerializer::GetInstance();
    std::string jsonString = R"([{"ssid": "wifi_name", "bssid": "68:77:24:77:A6:D9"}])";
    std::vector<WifiId> dataObj;
    bool ret = serializer->Deserialize(jsonString, dataObj);
    ASSERT_TRUE(ret);
    ASSERT_EQ(dataObj.size(), 1);
    ASSERT_EQ(dataObj[0].GetSsid(), "wifi_name");
    ASSERT_EQ(dataObj[0].GetBssid(), "68:77:24:77:A6:D9");
}

/**
 * @tc.name: TestDeserializeMalformedJson
 * @tc.desc: Test ArrayWifiIdSerializerTest::Deserialize MalformedJson
 * @tc.type: FUNC
 */
HWTEST_F(ArrayWifiIdSerializerTest, TestDeserializeMalformedJson, TestSize.Level1)
{
    auto serializer = ArrayWifiIdSerializer::GetInstance();
    std::string jsonString = R"([
            {"ssid": "wifi_name1", "bssid": "68:77:24:77:A6:D7",
            {"ssid": "wifi_name2", "bssid": "68:77:24:77:A6:D9"}
        ])";
    std::vector<WifiId> dataObj;
    serializer->Deserialize(jsonString, dataObj);
    ASSERT_TRUE(dataObj.empty());
}

/**
 * @tc.name: TestGetPolicyOutOfRange
 * @tc.desc: Test ArrayWifiIdSerializerTest::GetPolicy out of range
 * @tc.type: FUNC
 */
HWTEST_F(ArrayWifiIdSerializerTest, TestGetPolicyOutOfRange, TestSize.Level1)
{
    auto serializer = ArrayWifiIdSerializer::GetInstance();
    MessageParcel data;
    data.WriteInt32(EdmConstants::WIFI_LIST_MAX_SIZE + 1);
    std::vector<WifiId> dataObj;
    bool ret = serializer->GetPolicy(data, dataObj);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TestGetPolicy
 * @tc.desc: Test ArrayWifiIdSerializerTest::GetPolicy
 * @tc.type: FUNC
 */
HWTEST_F(ArrayWifiIdSerializerTest, TestGetPolicy, TestSize.Level1)
{
    auto serializer = ArrayWifiIdSerializer::GetInstance();
    MessageParcel data;
    std::vector<WifiId> dataObj;
    data.WriteInt32(1);
    data.WriteString("wifi_name1");
    data.WriteString("68:77:24:77:A6:D7");
    bool ret = serializer->GetPolicy(data, dataObj);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(dataObj[0].GetSsid() == "wifi_name1");
    ASSERT_TRUE(dataObj[0].GetBssid() == "68:77:24:77:A6:D7");
}

/**
 * @tc.name: TestWritePolicy
 * @tc.desc: Test ArrayWifiIdSerializerTest::WritePolicy
 * @tc.type: FUNC
 */
HWTEST_F(ArrayWifiIdSerializerTest, TestWritePolicy, TestSize.Level1)
{
    auto serializer = ArrayWifiIdSerializer::GetInstance();
    MessageParcel reply;
    std::vector<WifiId> dataObj;
    bool ret = serializer->WritePolicy(reply, dataObj);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: TestMergePolicy
 * @tc.desc: Test ArrayWifiIdSerializerTest::MergePolicy
 * @tc.type: FUNC
 */
HWTEST_F(ArrayWifiIdSerializerTest, TestMergePolicy, TestSize.Level1)
{
    auto serializer = ArrayWifiIdSerializer::GetInstance();
    std::vector<std::vector<WifiId>> dataObj;
    std::vector<WifiId> data;
    WifiId id1;
    id1.SetSsid("wifi_name1");
    id1.SetBssid("68:77:24:77:A6:D7");
    data.push_back(id1);
    dataObj.push_back(data);
    std::vector<WifiId> result;
    serializer->MergePolicy(dataObj, result);
    ASSERT_TRUE(result.size() == 1);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS