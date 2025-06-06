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

#include "manage_keep_alive_apps_serializer_test.h"
#include "edm_constants.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
void ManageKeepAliveAppsSerializerTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void ManageKeepAliveAppsSerializerTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestSetDifferencePolicyDataEmpty
 * @tc.desc: Test ManageKeepAliveAppsSerializerTest::SetDifferencePolicy when data is empty
 * @tc.type: FUNC
 */
    HWTEST_F(ManageKeepAliveAppsSerializerTest, TestSetDifferencePolicyDataEmpty, TestSize.Level1)
{
    auto serializer = ManageKeepAliveAppsSerializer::GetInstance();
    std::vector<ManageKeepAliveAppInfo> data;
    std::vector<ManageKeepAliveAppInfo> currentData;
    std::vector<ManageKeepAliveAppInfo> res = serializer->SetDifferencePolicyData(data, currentData);
    ASSERT_TRUE(res.empty());
}

/**
 * @tc.name: TestSerializeEmpty
 * @tc.desc: Test ManageKeepAliveAppsSerializerTest::Serialize when jsonString is empty
 * @tc.type: FUNC
 */
    HWTEST_F(ManageKeepAliveAppsSerializerTest, TestSerializeEmpty, TestSize.Level1)
{
    auto serializer = ManageKeepAliveAppsSerializer::GetInstance();
    std::string jsonString;
    std::vector<ManageKeepAliveAppInfo> dataObj;
    bool ret = serializer->Serialize(dataObj, jsonString);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(jsonString.empty());
}

/**
 * @tc.name: TestSerializeSuc
 * @tc.desc: Test ManageKeepAliveAppsSerializerTest::Serialize
 * @tc.type: FUNC
 */
    HWTEST_F(ManageKeepAliveAppsSerializerTest, TestSerializeSuc, TestSize.Level1)
{
    auto serializer = ManageKeepAliveAppsSerializer::GetInstance();
    std::string jsonString;
    std::vector<ManageKeepAliveAppInfo> dataObj;
    ManageKeepAliveAppInfo info1;
    info1.SetBundleName("test1");
    info1.SetDisallowModify(true);
    dataObj.push_back(info1);
    bool ret = serializer->Serialize(dataObj, jsonString);
    ASSERT_TRUE(ret);
    ASSERT_FALSE(jsonString.empty());
}

/**
 * @tc.name: TestDeserializeWithEmptyString
 * @tc.desc: Test ManageKeepAliveAppsSerializerTest::Deserialize jsonString is empty
 * @tc.type: FUNC
 */
HWTEST_F(ManageKeepAliveAppsSerializerTest, TestDeserializeWithEmptyString, TestSize.Level1)
{
    auto serializer = ManageKeepAliveAppsSerializer::GetInstance();
    std::string jsonString = "";
    std::vector<ManageKeepAliveAppInfo> dataObj;
    bool ret = serializer->Deserialize(jsonString, dataObj);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: TestDeserializeWithJustBundleName
 * @tc.desc: Test ManageKeepAliveAppsSerializerTest::Deserialize WithJustBundleName
 * @tc.type: FUNC
 */
HWTEST_F(ManageKeepAliveAppsSerializerTest, TestDeserializeWithJustBundleName, TestSize.Level1)
{
    auto serializer = ManageKeepAliveAppsSerializer::GetInstance();
    std::string jsonString = R"(["test1"])";
    std::vector<ManageKeepAliveAppInfo> dataObj;
    bool ret = serializer->Deserialize(jsonString, dataObj);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(dataObj.size() == 1);
    ASSERT_TRUE(dataObj[0].GetBundleName() == "test1");
    ASSERT_FALSE(dataObj[0].GetDisallowModify());
}

/**
 * @tc.name: TestDeserializeSuc
 * @tc.desc: Test ManageKeepAliveAppsSerializerTest::Deserialize
 * @tc.type: FUNC
 */
HWTEST_F(ManageKeepAliveAppsSerializerTest, TestDeserializeSuc, TestSize.Level1)
{
    auto serializer = ManageKeepAliveAppsSerializer::GetInstance();
    std::string jsonString = R"([{"bundleName": "test", "disallowModify": false}])";
    std::vector<ManageKeepAliveAppInfo> dataObj;
    bool ret = serializer->Deserialize(jsonString, dataObj);
    ASSERT_TRUE(ret);
    ASSERT_EQ(dataObj.size(), 1);
    ASSERT_EQ(dataObj[0].GetBundleName(), "test");
    ASSERT_EQ(dataObj[0].GetDisallowModify(), false);
}

/**
 * @tc.name: TestDeserializeMalformedJson
 * @tc.desc: Test ManageKeepAliveAppsSerializerTest::Deserialize MalformedJson
 * @tc.type: FUNC
 */
HWTEST_F(ManageKeepAliveAppsSerializerTest, TestDeserializeMalformedJson, TestSize.Level1)
{
    auto serializer = ManageKeepAliveAppsSerializer::GetInstance();
    std::string jsonString = R"([
            {"bundleName": "test1", "disallowModify": false,
            {"bundleName": "test2", "disallowModify": true}
        ])";
    std::vector<ManageKeepAliveAppInfo> dataObj;
    serializer->Deserialize(jsonString, dataObj);
    ASSERT_TRUE(dataObj.empty());
}

/**
 * @tc.name: TestGetPolicyOutOfRange
 * @tc.desc: Test ManageKeepAliveAppsSerializerTest::GetPolicy out of range
 * @tc.type: FUNC
 */
HWTEST_F(ManageKeepAliveAppsSerializerTest, TestGetPolicyOutOfRange, TestSize.Level1)
{
    auto serializer = ManageKeepAliveAppsSerializer::GetInstance();
    MessageParcel data;
    data.WriteInt32(EdmConstants::KEEP_ALIVE_APPS_MAX_SIZE + 1);
    std::vector<ManageKeepAliveAppInfo> dataObj;
    bool ret = serializer->GetPolicy(data, dataObj);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TestGetPolicy
 * @tc.desc: Test ManageKeepAliveAppsSerializerTest::GetPolicy
 * @tc.type: FUNC
 */
HWTEST_F(ManageKeepAliveAppsSerializerTest, TestGetPolicy, TestSize.Level1)
{
    auto serializer = ManageKeepAliveAppsSerializer::GetInstance();
    MessageParcel data;
    std::vector<ManageKeepAliveAppInfo> dataObj;
    data.WriteInt32(1);
    data.WriteString("test1");
    data.WriteBool(true);
    bool ret = serializer->GetPolicy(data, dataObj);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(dataObj[0].GetBundleName() == "test1");
    ASSERT_TRUE(dataObj[0].GetDisallowModify());
}

/**
 * @tc.name: TestWritePolicy
 * @tc.desc: Test ManageKeepAliveAppsSerializerTest::WritePolicy
 * @tc.type: FUNC
 */
HWTEST_F(ManageKeepAliveAppsSerializerTest, TestWritePolicy, TestSize.Level1)
{
    auto serializer = ManageKeepAliveAppsSerializer::GetInstance();
    MessageParcel reply;
    std::vector<ManageKeepAliveAppInfo> dataObj;
    bool ret = serializer->WritePolicy(reply, dataObj);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: TestMergePolicy
 * @tc.desc: Test ManageKeepAliveAppsSerializerTest::MergePolicy
 * @tc.type: FUNC
 */
HWTEST_F(ManageKeepAliveAppsSerializerTest, TestMergePolicy, TestSize.Level1)
{
    auto serializer = ManageKeepAliveAppsSerializer::GetInstance();
    std::vector<std::vector<ManageKeepAliveAppInfo>> dataObj;
    std::vector<ManageKeepAliveAppInfo> data;
    ManageKeepAliveAppInfo id1;
    id1.SetBundleName("test1");
    id1.SetDisallowModify(true);
    data.push_back(id1);
    dataObj.push_back(data);

    std::vector<ManageKeepAliveAppInfo> data2;
    ManageKeepAliveAppInfo id2;
    id2.SetBundleName("test1");
    id2.SetDisallowModify(false);
    data2.push_back(id2);
    dataObj.push_back(data2);
    std::vector<ManageKeepAliveAppInfo> result;
    serializer->MergePolicy(dataObj, result);
    ASSERT_TRUE(result.size() == 1);
    ASSERT_TRUE(result[0].GetDisallowModify());
}

/**
 * @tc.name: TestUpdateByMergePolicy
 * @tc.desc: Test ManageKeepAliveAppsSerializerTest::UpdateByMergePolicy
 * @tc.type: FUNC
 */
HWTEST_F(ManageKeepAliveAppsSerializerTest, TestUpdateByMergePolicy, TestSize.Level1)
{
    auto serializer = ManageKeepAliveAppsSerializer::GetInstance();
    std::vector<ManageKeepAliveAppInfo> data;
    ManageKeepAliveAppInfo id1;
    id1.SetBundleName("test1");
    id1.SetDisallowModify(true);
    data.push_back(id1);

    ManageKeepAliveAppInfo id2;
    id2.SetBundleName("test2");
    id2.SetDisallowModify(true);
    data.push_back(id2);

    std::vector<ManageKeepAliveAppInfo> data2;
    ManageKeepAliveAppInfo id3;
    id3.SetBundleName("test2");
    id3.SetDisallowModify(false);
    data2.push_back(id3);

    ManageKeepAliveAppInfo id4;
    id4.SetBundleName("test3");
    id4.SetDisallowModify(false);
    data2.push_back(id3);

    ManageKeepAliveAppInfo id5;
    id5.SetBundleName("test4");
    id5.SetDisallowModify(false);
    data2.push_back(id5);

    serializer->UpdateByMergePolicy(data, data2);
    ASSERT_TRUE(data.size() == 2);
    ASSERT_FALSE(data[1].GetDisallowModify());
}

/**
 * @tc.name: TestSetIntersectionPolicyData
 * @tc.desc: Test ManageKeepAliveAppsSerializerTest::SetIntersectionPolicyData
 * @tc.type: FUNC
 */
HWTEST_F(ManageKeepAliveAppsSerializerTest, TestSetIntersectionPolicyData, TestSize.Level1)
{
    auto serializer = ManageKeepAliveAppsSerializer::GetInstance();
    std::vector<std::string> bundleNames;
    bundleNames.push_back("test1");
    bundleNames.push_back("test2");
    
    std::vector<ManageKeepAliveAppInfo> data;
    ManageKeepAliveAppInfo id1;
    id1.SetBundleName("test1");
    id1.SetDisallowModify(true);
    data.push_back(id1);

    ManageKeepAliveAppInfo id2;
    id2.SetBundleName("test3");
    id2.SetDisallowModify(true);
    data.push_back(id2);

    std::vector<ManageKeepAliveAppInfo>result = serializer->SetIntersectionPolicyData(bundleNames, data);
    ASSERT_TRUE(result.size() == 1);
    ASSERT_TRUE(result[0].GetBundleName() == "test1");
}

/**
 * @tc.name: TestSetNeedRemoveMergePolicyData
 * @tc.desc: Test ManageKeepAliveAppsSerializerTest::SetNeedRemoveMergePolicyData
 * @tc.type: FUNC
 */
HWTEST_F(ManageKeepAliveAppsSerializerTest, TestSetNeedRemoveMergePolicyData, TestSize.Level1)
{
    auto serializer = ManageKeepAliveAppsSerializer::GetInstance();
    std::vector<ManageKeepAliveAppInfo> data;
    ManageKeepAliveAppInfo id1;
    id1.SetBundleName("test1");
    id1.SetDisallowModify(true);
    data.push_back(id1);

    ManageKeepAliveAppInfo id2;
    id2.SetBundleName("test2");
    id2.SetDisallowModify(true);
    data.push_back(id2);
    
    std::vector<ManageKeepAliveAppInfo> mergeData;
    ManageKeepAliveAppInfo id3;
    id3.SetBundleName("test1");
    id3.SetDisallowModify(true);
    mergeData.push_back(id3);

    ManageKeepAliveAppInfo id4;
    id4.SetBundleName("test3");
    id4.SetDisallowModify(true);
    mergeData.push_back(id4);

    ManageKeepAliveAppInfo id5;
    id5.SetBundleName("test4");
    id5.SetDisallowModify(true);
    mergeData.push_back(id5);

    std::vector<ManageKeepAliveAppInfo>result = serializer->SetNeedRemoveMergePolicyData(mergeData, data);
    ASSERT_TRUE(result.size() == 1);
    ASSERT_TRUE(result[0].GetBundleName() == "test2");
}

/**
 * @tc.name: TestSetUnionPolicyData
 * @tc.desc: Test ManageKeepAliveAppsSerializerTest::SetUnionPolicyData
 * @tc.type: FUNC
 */
HWTEST_F(ManageKeepAliveAppsSerializerTest, TestSetUnionPolicyData, TestSize.Level1)
{
    auto serializer = ManageKeepAliveAppsSerializer::GetInstance();
    std::vector<ManageKeepAliveAppInfo> data;
    ManageKeepAliveAppInfo id1;
    id1.SetBundleName("test1");
    id1.SetDisallowModify(true);
    data.push_back(id1);

    ManageKeepAliveAppInfo id2;
    id2.SetBundleName("test2");
    id2.SetDisallowModify(true);
    data.push_back(id2);
    
    std::vector<ManageKeepAliveAppInfo> mergeData;
    ManageKeepAliveAppInfo id3;
    id3.SetBundleName("test1");
    id3.SetDisallowModify(false);
    mergeData.push_back(id3);

    ManageKeepAliveAppInfo id4;
    id4.SetBundleName("test3");
    id4.SetDisallowModify(true);
    mergeData.push_back(id4);

    ManageKeepAliveAppInfo id5;
    id5.SetBundleName("test4");
    id5.SetDisallowModify(true);
    mergeData.push_back(id5);

    std::vector<ManageKeepAliveAppInfo>result = serializer->SetUnionPolicyData(data, mergeData);
    ASSERT_TRUE(result.size() == 4);
    ASSERT_TRUE(result[0].GetBundleName() == "test1");
    ASSERT_FALSE(result[0].GetDisallowModify());
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS