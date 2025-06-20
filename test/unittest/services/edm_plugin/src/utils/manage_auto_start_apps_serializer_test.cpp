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
 
#include "manage_auto_start_apps_serializer_test.h"
#include "edm_constants.h"
#include "utils.h"
 
using namespace testing::ext;
 
namespace OHOS {
namespace EDM {
namespace TEST {
void ManageAutoStartAppsSerializerTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}
 
void ManageAutoStartAppsSerializerTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}
 
/**
 * @tc.name: TestSetDifferencePolicyDataEmpty
 * @tc.desc: Test ManageAutoStartAppsSerializerTest::SetDifferencePolicy when data is empty
 * @tc.type: FUNC
 */
    HWTEST_F(ManageAutoStartAppsSerializerTest, TestSetDifferencePolicyDataEmpty, TestSize.Level1)
{
    auto serializer = ManageAutoStartAppsSerializer::GetInstance();
    std::vector<ManageAutoStartAppInfo> data;
    std::vector<ManageAutoStartAppInfo> currentData;
    std::vector<ManageAutoStartAppInfo> res = serializer->SetDifferencePolicyData(data, currentData);
    ASSERT_TRUE(res.empty());
}
 
/**
 * @tc.name: TestSerializeEmpty
 * @tc.desc: Test ManageAutoStartAppsSerializerTest::Serialize when jsonString is empty
 * @tc.type: FUNC
 */
    HWTEST_F(ManageAutoStartAppsSerializerTest, TestSerializeEmpty, TestSize.Level1)
{
    auto serializer = ManageAutoStartAppsSerializer::GetInstance();
    std::string jsonString;
    std::vector<ManageAutoStartAppInfo> dataObj;
    bool ret = serializer->Serialize(dataObj, jsonString);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(jsonString.empty());
}
 
/**
 * @tc.name: TestSerializeSuc
 * @tc.desc: Test ManageAutoStartAppsSerializerTest::Serialize
 * @tc.type: FUNC
 */
    HWTEST_F(ManageAutoStartAppsSerializerTest, TestSerializeSuc, TestSize.Level1)
{
    auto serializer = ManageAutoStartAppsSerializer::GetInstance();
    std::string jsonString;
    std::vector<ManageAutoStartAppInfo> dataObj;
    ManageAutoStartAppInfo info1;
    info1.SetBundleName("test1");
    info1.SetAbilityName("testAB1");
    info1.SetDisallowModify(true);
    dataObj.push_back(info1);
    bool ret = serializer->Serialize(dataObj, jsonString);
    ASSERT_TRUE(ret);
    ASSERT_FALSE(jsonString.empty());
}
 
/**
 * @tc.name: TestDeserializeWithEmptyString
 * @tc.desc: Test ManageAutoStartAppsSerializerTest::Deserialize jsonString is empty
 * @tc.type: FUNC
 */
HWTEST_F(ManageAutoStartAppsSerializerTest, TestDeserializeWithEmptyString, TestSize.Level1)
{
    auto serializer = ManageAutoStartAppsSerializer::GetInstance();
    std::string jsonString = "";
    std::vector<ManageAutoStartAppInfo> dataObj;
    bool ret = serializer->Deserialize(jsonString, dataObj);
    ASSERT_TRUE(ret);
}
 
/**
 * @tc.name: TestDeserializeWithJustBundleNameAndAbilityName
 * @tc.desc: Test ManageAutoStartAppsSerializerTest::Deserialize WithJustBundleNameAndAbilityName
 * @tc.type: FUNC
 */
HWTEST_F(ManageAutoStartAppsSerializerTest, TestDeserializeWithJustBundleNameAndAbilityName, TestSize.Level1)
{
    auto serializer = ManageAutoStartAppsSerializer::GetInstance();
    std::string jsonString = R"(["test1/testAB1"])";
    std::vector<ManageAutoStartAppInfo> dataObj;
    bool ret = serializer->Deserialize(jsonString, dataObj);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(dataObj.size() == 1);
    ASSERT_TRUE(dataObj[0].GetBundleName() == "test1");
    ASSERT_TRUE(dataObj[0].GetAbilityName() == "testAB1");
    ASSERT_TRUE(dataObj[0].GetAbilityName() == "testAB1");
    ASSERT_TRUE(dataObj[0].GetUniqueKey() == "test1/testAB1");
    ASSERT_FALSE(dataObj[0].GetDisallowModify());
}
 
/**
 * @tc.name: TestDeserializeSuc
 * @tc.desc: Test ManageAutoStartAppsSerializerTest::Deserialize
 * @tc.type: FUNC
 */
HWTEST_F(ManageAutoStartAppsSerializerTest, TestDeserializeSuc, TestSize.Level1)
{
    auto serializer = ManageAutoStartAppsSerializer::GetInstance();
    std::string jsonString = R"([{"bundleName": "test", "abilityName": "testAB", "disallowModify": false}])";
    std::vector<ManageAutoStartAppInfo> dataObj;
    bool ret = serializer->Deserialize(jsonString, dataObj);
    ASSERT_TRUE(ret);
    ASSERT_EQ(dataObj.size(), 1);
    ASSERT_EQ(dataObj[0].GetBundleName(), "test");
    ASSERT_EQ(dataObj[0].GetAbilityName(), "testAB");
    ASSERT_EQ(dataObj[0].GetDisallowModify(), false);
}
 
/**
 * @tc.name: TestDeserializeMalformedJson
 * @tc.desc: Test ManageAutoStartAppsSerializerTest::Deserialize MalformedJson
 * @tc.type: FUNC
 */
HWTEST_F(ManageAutoStartAppsSerializerTest, TestDeserializeMalformedJson, TestSize.Level1)
{
    auto serializer = ManageAutoStartAppsSerializer::GetInstance();
    std::string jsonString = R"([
            {"bundleName": "test1", "abilityName": "testAB1", "disallowModify": false,
            {"bundleName": "test2", "abilityName": "testAB2", "disallowModify": true}
        ])";
    std::vector<ManageAutoStartAppInfo> dataObj;
    serializer->Deserialize(jsonString, dataObj);
    ASSERT_TRUE(dataObj.empty());
}
 
/**
 * @tc.name: TestGetPolicyOutOfRange
 * @tc.desc: Test ManageAutoStartAppsSerializerTest::GetPolicy out of range
 * @tc.type: FUNC
 */
HWTEST_F(ManageAutoStartAppsSerializerTest, TestGetPolicyOutOfRange, TestSize.Level1)
{
    auto serializer = ManageAutoStartAppsSerializer::GetInstance();
    MessageParcel data;
    data.WriteInt32(EdmConstants::AUTO_START_APPS_MAX_SIZE + 1);
    std::vector<ManageAutoStartAppInfo> dataObj;
    bool ret = serializer->GetPolicy(data, dataObj);
    ASSERT_FALSE(ret);
}
 
/**
 * @tc.name: TestGetPolicy
 * @tc.desc: Test ManageAutoStartAppsSerializerTest::GetPolicy
 * @tc.type: FUNC
 */
HWTEST_F(ManageAutoStartAppsSerializerTest, TestGetPolicy, TestSize.Level1)
{
    auto serializer = ManageAutoStartAppsSerializer::GetInstance();
    MessageParcel data;
    std::vector<ManageAutoStartAppInfo> dataObj;
    data.WriteInt32(1);
    data.WriteString("test1");
    data.WriteString("testAB1");
    data.WriteBool(true);
    bool ret = serializer->GetPolicy(data, dataObj);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(dataObj[0].GetBundleName() == "test1");
    ASSERT_TRUE(dataObj[0].GetAbilityName() == "testAB1");
    ASSERT_TRUE(dataObj[0].GetDisallowModify());
}
 
/**
 * @tc.name: TestWritePolicy
 * @tc.desc: Test ManageAutoStartAppsSerializerTest::WritePolicy
 * @tc.type: FUNC
 */
HWTEST_F(ManageAutoStartAppsSerializerTest, TestWritePolicy, TestSize.Level1)
{
    auto serializer = ManageAutoStartAppsSerializer::GetInstance();
    MessageParcel reply;
    std::vector<ManageAutoStartAppInfo> dataObj;
    bool ret = serializer->WritePolicy(reply, dataObj);
    ASSERT_TRUE(ret);
}
 
/**
 * @tc.name: TestMergePolicy
 * @tc.desc: Test ManageAutoStartAppsSerializerTest::MergePolicy
 * @tc.type: FUNC
 */
HWTEST_F(ManageAutoStartAppsSerializerTest, TestMergePolicy, TestSize.Level1)
{
    auto serializer = ManageAutoStartAppsSerializer::GetInstance();
    std::vector<std::vector<ManageAutoStartAppInfo>> dataObj;
    std::vector<ManageAutoStartAppInfo> data;
    ManageAutoStartAppInfo id1;
    id1.SetBundleName("test1");
    id1.SetAbilityName("testAB1");
    id1.SetDisallowModify(true);
    data.push_back(id1);
    dataObj.push_back(data);
 
    std::vector<ManageAutoStartAppInfo> data2;
    ManageAutoStartAppInfo id2;
    id2.SetUniqueKey("test1/testAB1");
    id2.SetDisallowModify(false);
    data2.push_back(id2);
    dataObj.push_back(data2);
    std::vector<ManageAutoStartAppInfo> result;
    serializer->MergePolicy(dataObj, result);
    ASSERT_TRUE(result.size() == 1);
    ASSERT_TRUE(result[0].GetDisallowModify());
}
 
/**
 * @tc.name: TestUpdateByMergePolicy
 * @tc.desc: Test ManageAutoStartAppsSerializerTest::UpdateByMergePolicy
 * @tc.type: FUNC
 */
HWTEST_F(ManageAutoStartAppsSerializerTest, TestUpdateByMergePolicy, TestSize.Level1)
{
    auto serializer = ManageAutoStartAppsSerializer::GetInstance();
    std::vector<ManageAutoStartAppInfo> data;
    ManageAutoStartAppInfo id1;
    id1.SetBundleName("test1");
    id1.SetAbilityName("testAB1");
    id1.SetDisallowModify(true);
    data.push_back(id1);
 
    ManageAutoStartAppInfo id2;
    id2.SetBundleName("test2");
    id2.SetAbilityName("testAB2");
    id2.SetDisallowModify(true);
    data.push_back(id2);
 
    std::vector<ManageAutoStartAppInfo> data2;
    ManageAutoStartAppInfo id3;
    id3.SetBundleName("test2");
    id3.SetAbilityName("testAB2");
    id3.SetDisallowModify(false);
    data2.push_back(id3);
 
    ManageAutoStartAppInfo id4;
    id4.SetBundleName("test3");
    id4.SetAbilityName("testAB4");
    id4.SetDisallowModify(false);
    data2.push_back(id3);
 
    ManageAutoStartAppInfo id5;
    id5.SetBundleName("test4");
    id5.SetAbilityName("testAB4");
    id5.SetDisallowModify(false);
    data2.push_back(id5);
 
    serializer->UpdateByMergePolicy(data, data2);
    ASSERT_TRUE(data.size() == 2);
    ASSERT_FALSE(data[1].GetDisallowModify());
}
 
/**
 * @tc.name: TestSetIntersectionPolicyData
 * @tc.desc: Test ManageAutoStartAppsSerializerTest::SetIntersectionPolicyData
 * @tc.type: FUNC
 */
HWTEST_F(ManageAutoStartAppsSerializerTest, TestSetIntersectionPolicyData, TestSize.Level1)
{
    auto serializer = ManageAutoStartAppsSerializer::GetInstance();
    std::vector<std::string> uniqueKey;
    uniqueKey.push_back("test1/testAB1");
    uniqueKey.push_back("test2/testAB2");
    
    std::vector<ManageAutoStartAppInfo> data;
    ManageAutoStartAppInfo id1;
    id1.SetUniqueKey("test1/testAB1");
    id1.SetDisallowModify(true);
    data.push_back(id1);
 
    ManageAutoStartAppInfo id2;
    id2.SetUniqueKey("test3/testAB3");
    id2.SetDisallowModify(true);
    data.push_back(id2);
 
    std::vector<ManageAutoStartAppInfo>result = serializer->SetIntersectionPolicyData(uniqueKey, data);
    ASSERT_TRUE(result.size() == 1);
    ASSERT_TRUE(result[0].GetBundleName() == "test1");
}
 
/**
 * @tc.name: TestSetNeedRemoveMergePolicyData
 * @tc.desc: Test ManageAutoStartAppsSerializerTest::SetNeedRemoveMergePolicyData
 * @tc.type: FUNC
 */
HWTEST_F(ManageAutoStartAppsSerializerTest, TestSetNeedRemoveMergePolicyData, TestSize.Level1)
{
    auto serializer = ManageAutoStartAppsSerializer::GetInstance();
    std::vector<ManageAutoStartAppInfo> data;
    ManageAutoStartAppInfo id1;
    id1.SetUniqueKey("test1/testAB1");
    id1.SetDisallowModify(true);
    data.push_back(id1);
 
    ManageAutoStartAppInfo id2;
    id2.SetUniqueKey("test2/testAB2");
    id2.SetDisallowModify(true);
    data.push_back(id2);
    
    std::vector<ManageAutoStartAppInfo> mergeData;
    ManageAutoStartAppInfo id3;
    id3.SetUniqueKey("test1/testAB1");
    id3.SetDisallowModify(true);
    mergeData.push_back(id3);
 
    ManageAutoStartAppInfo id4;
    id4.SetUniqueKey("test3/testAB3");
    id4.SetDisallowModify(true);
    mergeData.push_back(id4);
 
    ManageAutoStartAppInfo id5;
    id5.SetUniqueKey("test4/testAB4");
    id5.SetDisallowModify(true);
    mergeData.push_back(id5);
 
    std::vector<ManageAutoStartAppInfo>result = serializer->SetNeedRemoveMergePolicyData(mergeData, data);
    ASSERT_TRUE(result.size() == 1);
    ASSERT_TRUE(result[0].GetBundleName() == "test2");
}
 
/**
 * @tc.name: TestSetUnionPolicyData
 * @tc.desc: Test ManageAutoStartAppsSerializerTest::SetUnionPolicyData
 * @tc.type: FUNC
 */
HWTEST_F(ManageAutoStartAppsSerializerTest, TestSetUnionPolicyData, TestSize.Level1)
{
    auto serializer = ManageAutoStartAppsSerializer::GetInstance();
    std::vector<ManageAutoStartAppInfo> data;
    ManageAutoStartAppInfo id1;
    id1.SetUniqueKey("test1/testAB1");
    id1.SetDisallowModify(true);
    data.push_back(id1);
 
    ManageAutoStartAppInfo id2;
    id2.SetUniqueKey("test2/testAB2");
    id2.SetDisallowModify(true);
    data.push_back(id2);
    
    std::vector<ManageAutoStartAppInfo> mergeData;
    ManageAutoStartAppInfo id3;
    id3.SetUniqueKey("test1/testAB1");
    id3.SetDisallowModify(false);
    mergeData.push_back(id3);
 
    ManageAutoStartAppInfo id4;
    id4.SetUniqueKey("test3/testAB3");
    id4.SetDisallowModify(true);
    mergeData.push_back(id4);
 
    ManageAutoStartAppInfo id5;
    id5.SetUniqueKey("test4/testAB4");
    id5.SetDisallowModify(true);
    mergeData.push_back(id5);
 
    std::vector<ManageAutoStartAppInfo>result = serializer->SetUnionPolicyData(data, mergeData);
    ASSERT_TRUE(result.size() == 4);
    ASSERT_TRUE(result[0].GetBundleName() == "test1");
    ASSERT_FALSE(result[0].GetDisallowModify());
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS