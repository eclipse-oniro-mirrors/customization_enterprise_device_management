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
#include <gmock/gmock.h>

#define private public
#define protected public
#include "allowed_permission_bundle_serializer.h"
#undef private
#undef protected

#include "application_instance.h"
#include "cJSON.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {

class AllowedPermissionBundleSerializerTest : public testing::Test {
protected:
    void SetUp() override
    {
        serializer_ = AllowedPermissionBundleSerializer::GetInstance();
    }

    void TearDown() override
    {
        serializer_ = nullptr;
    }

    std::shared_ptr<AllowedPermissionBundleSerializer> serializer_;
    ApplicationInstance CreateAppInstance(const std::string& appIdentifier, int32_t accountId,
        int32_t appIndex, const std::string& bundleName = "")
    {
        ApplicationInstance app;
        app.appIdentifier = appIdentifier;
        app.accountId = accountId;
        app.appIndex = appIndex;
        app.bundleName = bundleName;
        return app;
    }
};

/**
 * @tc.name: TestDeserialize_SUC
 * @tc.desc: Test Deserialize function with valid JSON string.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleSerializerTest, TestDeserialize_SUC, TestSize.Level1)
{
    std::string policy = R"({"ohos.permission.CAMERA":[
        {"appIdentifier":"com.test.app1","accountId":100,"appIndex":0,"bundleName":"com.test.app1"}]})";
    std::map<std::string, std::vector<ApplicationInstance>> dataObj;
    bool ret = serializer_->Deserialize(policy, dataObj);
    ASSERT_TRUE(ret);
    EXPECT_EQ(dataObj.size(), 1u);
    EXPECT_TRUE(dataObj.find("ohos.permission.CAMERA") != dataObj.end());
    EXPECT_EQ(dataObj["ohos.permission.CAMERA"].size(), 1u);
    EXPECT_EQ(dataObj["ohos.permission.CAMERA"][0].appIdentifier, "com.test.app1");
    EXPECT_EQ(dataObj["ohos.permission.CAMERA"][0].accountId, 100);
    EXPECT_EQ(dataObj["ohos.permission.CAMERA"][0].appIndex, 0);
}

/**
 * @tc.name: TestDeserializeEmpty_SUC
 * @tc.desc: Test Deserialize function with empty string.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleSerializerTest, TestDeserializeEmpty_SUC, TestSize.Level1)
{
    std::string policy = "";
    std::map<std::string, std::vector<ApplicationInstance>> dataObj;
    bool ret = serializer_->Deserialize(policy, dataObj);
    ASSERT_TRUE(ret);
    EXPECT_TRUE(dataObj.empty());
}

/**
 * @tc.name: TestDeserializeInvalidJson_FAIL
 * @tc.desc: Test Deserialize function with invalid JSON string.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleSerializerTest, TestDeserializeInvalidJson_FAIL, TestSize.Level1)
{
    std::string policy = "invalid_json";
    std::map<std::string, std::vector<ApplicationInstance>> dataObj;
    bool ret = serializer_->Deserialize(policy, dataObj);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TestDeserializeNotObject_FAIL
 * @tc.desc: Test Deserialize function when JSON root is not object.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleSerializerTest, TestDeserializeNotObject_FAIL, TestSize.Level1)
{
    std::string policy = R"([{"appIdentifier":"com.test.app1"}])";
    std::map<std::string, std::vector<ApplicationInstance>> dataObj;
    bool ret = serializer_->Deserialize(policy, dataObj);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TestDeserializePermissionNotArray_FAIL
 * @tc.desc: Test Deserialize function when permission value is not array.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleSerializerTest, TestDeserializePermissionNotArray_FAIL, TestSize.Level1)
{
    std::string policy = R"({"ohos.permission.CAMERA":"not_array"})";
    std::map<std::string, std::vector<ApplicationInstance>> dataObj;
    bool ret = serializer_->Deserialize(policy, dataObj);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TestDeserializeAppItemNotObject_FAIL
 * @tc.desc: Test Deserialize function when app item is not object.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleSerializerTest, TestDeserializeAppItemNotObject_FAIL, TestSize.Level1)
{
    std::string policy = R"({"ohos.permission.CAMERA":["not_object"]})";
    std::map<std::string, std::vector<ApplicationInstance>> dataObj;
    bool ret = serializer_->Deserialize(policy, dataObj);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TestDeserializeMissingRequiredField_FAIL
 * @tc.desc: Test Deserialize function when required field is missing.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleSerializerTest, TestDeserializeMissingRequiredField_FAIL, TestSize.Level1)
{
    std::string policy = R"({"ohos.permission.CAMERA":[{"accountId":100}]})";
    std::map<std::string, std::vector<ApplicationInstance>> dataObj;
    bool ret = serializer_->Deserialize(policy, dataObj);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TestDeserializeMultiplePermissions_SUC
 * @tc.desc: Test Deserialize function with multiple permissions.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleSerializerTest, TestDeserializeMultiplePermissions_SUC, TestSize.Level1)
{
    std::string policy = R"({
        "ohos.permission.CAMERA":[{"appIdentifier":"com.test.app1","accountId":100,"appIndex":0}],
        "ohos.permission.LOCATION":[{"appIdentifier":"com.test.app2","accountId":100,"appIndex":0}]
    })";
    std::map<std::string, std::vector<ApplicationInstance>> dataObj;
    bool ret = serializer_->Deserialize(policy, dataObj);
    ASSERT_TRUE(ret);
    EXPECT_EQ(dataObj.size(), 2u);
}

/**
 * @tc.name: TestSerialize_SUC
 * @tc.desc: Test Serialize function with valid data.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleSerializerTest, TestSerialize_SUC, TestSize.Level1)
{
    std::map<std::string, std::vector<ApplicationInstance>> dataObj;
    ApplicationInstance app1 = CreateAppInstance("com.test.app1", 100, 0, "com.test.app1");
    ApplicationInstance app2 = CreateAppInstance("com.test.app2", 100, 0, "com.test.app2");
    dataObj["ohos.permission.CAMERA"] = {app1, app2};

    std::string policy;
    bool ret = serializer_->Serialize(dataObj, policy);
    ASSERT_TRUE(ret);
    EXPECT_FALSE(policy.empty());

    // Verify by deserializing
    std::map<std::string, std::vector<ApplicationInstance>> result;
    ret = serializer_->Deserialize(policy, result);
    ASSERT_TRUE(ret);
    EXPECT_EQ(result.size(), 1u);
    EXPECT_EQ(result["ohos.permission.CAMERA"].size(), 2u);
}

/**
 * @tc.name: TestSerializeEmpty_SUC
 * @tc.desc: Test Serialize function with empty data.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleSerializerTest, TestSerializeEmpty_SUC, TestSize.Level1)
{
    std::map<std::string, std::vector<ApplicationInstance>> dataObj;
    std::string policy;
    bool ret = serializer_->Serialize(dataObj, policy);
    ASSERT_TRUE(ret);
    EXPECT_TRUE(policy.empty());
}

/**
 * @tc.name: TestSerializeEmptyAppList_SUC
 * @tc.desc: Test Serialize function with empty app list.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleSerializerTest, TestSerializeEmptyAppList_SUC, TestSize.Level1)
{
    std::map<std::string, std::vector<ApplicationInstance>> dataObj;
    dataObj["ohos.permission.CAMERA"] = {};
    std::string policy;
    bool ret = serializer_->Serialize(dataObj, policy);
    ASSERT_TRUE(ret);
    EXPECT_FALSE(policy.empty());
}

/**
 * @tc.name: TestGetPolicy_SUC
 * @tc.desc: Test GetPolicy function with valid MessageParcel.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleSerializerTest, TestGetPolicy_SUC, TestSize.Level1)
{
    MessageParcel data;
    uint32_t permissionCount = 1;
    data.WriteUint32(permissionCount);
    data.WriteString("ohos.permission.CAMERA");
    uint32_t appCount = 1;
    data.WriteUint32(appCount);
    ApplicationInstance app = CreateAppInstance("com.test.app1", 100, 0, "com.test.app1");
    ApplicationInstanceHandle::WriteApplicationInstance(data, app);

    std::map<std::string, std::vector<ApplicationInstance>> result;
    bool ret = serializer_->GetPolicy(data, result);
    ASSERT_TRUE(ret);
    EXPECT_EQ(result.size(), 1u);
    EXPECT_EQ(result["ohos.permission.CAMERA"].size(), 1u);
}

/**
 * @tc.name: TestGetPolicyReadPermissionCountFail_FAIL
 * @tc.desc: Test GetPolicy function when read permission count fails.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleSerializerTest, TestGetPolicyReadPermissionCountFail_FAIL, TestSize.Level1)
{
    MessageParcel data;
    // Not writing permission count
    std::map<std::string, std::vector<ApplicationInstance>> result;
    bool ret = serializer_->GetPolicy(data, result);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TestGetPolicyReadPermissionNameFail_FAIL
 * @tc.desc: Test GetPolicy function when read permission name fails.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleSerializerTest, TestGetPolicyReadPermissionNameFail_FAIL, TestSize.Level1)
{
    MessageParcel data;
    data.WriteUint32(1);
    // Not writing permission name
    std::map<std::string, std::vector<ApplicationInstance>> result;
    bool ret = serializer_->GetPolicy(data, result);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TestGetPolicyReadAppCountFail_FAIL
 * @tc.desc: Test GetPolicy function when read app count fails.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleSerializerTest, TestGetPolicyReadAppCountFail_FAIL, TestSize.Level1)
{
    MessageParcel data;
    data.WriteUint32(1);
    data.WriteString("ohos.permission.CAMERA");
    // Not writing app count
    std::map<std::string, std::vector<ApplicationInstance>> result;
    bool ret = serializer_->GetPolicy(data, result);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TestWritePolicy_SUC
 * @tc.desc: Test WritePolicy function with valid data.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleSerializerTest, TestWritePolicy_SUC, TestSize.Level1)
{
    std::map<std::string, std::vector<ApplicationInstance>> result;
    ApplicationInstance app = CreateAppInstance("com.test.app1", 100, 0, "com.test.app1");
    result["ohos.permission.CAMERA"] = {app};

    MessageParcel reply;
    bool ret = serializer_->WritePolicy(reply, result);
    ASSERT_TRUE(ret);

    // Verify by reading
    uint32_t permissionCount = reply.ReadUint32();
    EXPECT_EQ(permissionCount, 1u);
    std::string permissionName = reply.ReadString();
    EXPECT_EQ(permissionName, "ohos.permission.CAMERA");
    uint32_t appCount = reply.ReadUint32();
    EXPECT_EQ(appCount, 1u);
}

/**
 * @tc.name: TestWritePolicyEmpty_SUC
 * @tc.desc: Test WritePolicy function with empty data.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleSerializerTest, TestWritePolicyEmpty_SUC, TestSize.Level1)
{
    std::map<std::string, std::vector<ApplicationInstance>> result;
    MessageParcel reply;
    bool ret = serializer_->WritePolicy(reply, result);
    ASSERT_TRUE(ret);
    uint32_t permissionCount = reply.ReadUint32();
    EXPECT_EQ(permissionCount, 0u);
}

/**
 * @tc.name: TestMergePolicy_SUC
 * @tc.desc: Test MergePolicy function with multiple admin policies.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleSerializerTest, TestMergePolicy_SUC, TestSize.Level1)
{
    std::vector<std::map<std::string, std::vector<ApplicationInstance>>> data;
    
    std::map<std::string, std::vector<ApplicationInstance>> policy1;
    ApplicationInstance app1 = CreateAppInstance("com.test.app1", 100, 0);
    policy1["ohos.permission.CAMERA"] = {app1};
    data.push_back(policy1);

    std::map<std::string, std::vector<ApplicationInstance>> policy2;
    ApplicationInstance app2 = CreateAppInstance("com.test.app2", 100, 0);
    policy2["ohos.permission.CAMERA"] = {app2};
    data.push_back(policy2);

    std::map<std::string, std::vector<ApplicationInstance>> result;
    bool ret = serializer_->MergePolicy(data, result);
    ASSERT_TRUE(ret);
    EXPECT_EQ(result.size(), 1u);
    EXPECT_EQ(result["ohos.permission.CAMERA"].size(), 2u);
}

/**
 * @tc.name: TestMergePolicyDuplicate_SUC
 * @tc.desc: Test MergePolicy function with duplicate apps.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleSerializerTest, TestMergePolicyDuplicate_SUC, TestSize.Level1)
{
    std::vector<std::map<std::string, std::vector<ApplicationInstance>>> data;
    
    std::map<std::string, std::vector<ApplicationInstance>> policy1;
    ApplicationInstance app1 = CreateAppInstance("com.test.app1", 100, 0);
    policy1["ohos.permission.CAMERA"] = {app1};
    data.push_back(policy1);

    std::map<std::string, std::vector<ApplicationInstance>> policy2;
    ApplicationInstance app2 = CreateAppInstance("com.test.app1", 100, 0); // Same app
    policy2["ohos.permission.CAMERA"] = {app2};
    data.push_back(policy2);

    std::map<std::string, std::vector<ApplicationInstance>> result;
    bool ret = serializer_->MergePolicy(data, result);
    ASSERT_TRUE(ret);
    EXPECT_EQ(result.size(), 1u);
    EXPECT_EQ(result["ohos.permission.CAMERA"].size(), 1u); // Should deduplicate
}

/**
 * @tc.name: TestSetUnionPolicyData_SUC
 * @tc.desc: Test SetUnionPolicyData function.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleSerializerTest, TestSetUnionPolicyData_SUC, TestSize.Level1)
{
    std::map<std::string, std::vector<ApplicationInstance>> data;
    ApplicationInstance app1 = CreateAppInstance("com.test.app1", 100, 0);
    data["ohos.permission.CAMERA"] = {app1};

    std::map<std::string, std::vector<ApplicationInstance>> currentData;
    ApplicationInstance app2 = CreateAppInstance("com.test.app2", 100, 0);
    currentData["ohos.permission.CAMERA"] = {app2};

    auto result = serializer_->SetUnionPolicyData(data, currentData);
    EXPECT_EQ(result.size(), 1u);
    EXPECT_EQ(result["ohos.permission.CAMERA"].size(), 2u);
}

/**
 * @tc.name: TestSetUnionPolicyDataDifferentPermissions_SUC
 * @tc.desc: Test SetUnionPolicyData with different permissions.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleSerializerTest, TestSetUnionPolicyDataDifferentPermissions_SUC, TestSize.Level1)
{
    std::map<std::string, std::vector<ApplicationInstance>> data;
    ApplicationInstance app1 = CreateAppInstance("com.test.app1", 100, 0);
    data["ohos.permission.CAMERA"] = {app1};

    std::map<std::string, std::vector<ApplicationInstance>> currentData;
    ApplicationInstance app2 = CreateAppInstance("com.test.app2", 100, 0);
    currentData["ohos.permission.LOCATION"] = {app2};

    auto result = serializer_->SetUnionPolicyData(data, currentData);
    EXPECT_EQ(result.size(), 2u);
}

/**
 * @tc.name: TestSetDifferencePolicyData_SUC
 * @tc.desc: Test SetDifferencePolicyData function.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleSerializerTest, TestSetDifferencePolicyData_SUC, TestSize.Level1)
{
    std::map<std::string, std::vector<ApplicationInstance>> data;
    ApplicationInstance app1 = CreateAppInstance("com.test.app1", 100, 0);
    data["ohos.permission.CAMERA"] = {app1};

    std::map<std::string, std::vector<ApplicationInstance>> currentData;
    ApplicationInstance app2 = CreateAppInstance("com.test.app2", 100, 0);
    currentData["ohos.permission.CAMERA"] = {app1, app2};

    auto result = serializer_->SetDifferencePolicyData(data, currentData);
    EXPECT_EQ(result.size(), 1u);
    EXPECT_EQ(result["ohos.permission.CAMERA"].size(), 1u);
    EXPECT_EQ(result["ohos.permission.CAMERA"][0].appIdentifier, "com.test.app2");
}

/**
 * @tc.name: TestSetDifferencePolicyDataPermissionNotExist_SUC
 * @tc.desc: Test SetDifferencePolicyData when permission not in data.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleSerializerTest, TestSetDifferencePolicyDataPermissionNotExist_SUC, TestSize.Level1)
{
    std::map<std::string, std::vector<ApplicationInstance>> data;
    ApplicationInstance app1 = CreateAppInstance("com.test.app1", 100, 0);
    data["ohos.permission.CAMERA"] = {app1};

    std::map<std::string, std::vector<ApplicationInstance>> currentData;
    ApplicationInstance app2 = CreateAppInstance("com.test.app2", 100, 0);
    currentData["ohos.permission.LOCATION"] = {app2};

    auto result = serializer_->SetDifferencePolicyData(data, currentData);
    EXPECT_EQ(result.size(), 1u);
    EXPECT_TRUE(result.find("ohos.permission.LOCATION") != result.end());
}

/**
 * @tc.name: TestSetIntersectionPolicyData_SUC
 * @tc.desc: Test SetIntersectionPolicyData function.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleSerializerTest, TestSetIntersectionPolicyData_SUC, TestSize.Level1)
{
    std::map<std::string, std::vector<ApplicationInstance>> data;
    ApplicationInstance app1 = CreateAppInstance("com.test.app1", 100, 0);
    ApplicationInstance app3 = CreateAppInstance("com.test.app3", 100, 0);
    data["ohos.permission.CAMERA"] = {app1, app3};

    std::map<std::string, std::vector<ApplicationInstance>> currentData;
    ApplicationInstance app2 = CreateAppInstance("com.test.app2", 100, 0);
    currentData["ohos.permission.CAMERA"] = {app1, app2};

    auto result = serializer_->SetIntersectionPolicyData(data, currentData);
    EXPECT_EQ(result.size(), 1u);
    EXPECT_EQ(result["ohos.permission.CAMERA"].size(), 1u);
    EXPECT_EQ(result["ohos.permission.CAMERA"][0].appIdentifier, "com.test.app1");
}

/**
 * @tc.name: TestSetIntersectionPolicyDataPermissionNotExist_SUC
 * @tc.desc: Test SetIntersectionPolicyData when permission not in currentData.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleSerializerTest, TestSetIntersectionPolicyDataPermissionNotExist_SUC, TestSize.Level1)
{
    std::map<std::string, std::vector<ApplicationInstance>> data;
    ApplicationInstance app1 = CreateAppInstance("com.test.app1", 100, 0);
    data["ohos.permission.CAMERA"] = {app1};

    std::map<std::string, std::vector<ApplicationInstance>> currentData;
    ApplicationInstance app2 = CreateAppInstance("com.test.app2", 100, 0);
    currentData["ohos.permission.LOCATION"] = {app2};

    auto result = serializer_->SetIntersectionPolicyData(data, currentData);
    EXPECT_TRUE(result.empty());
}

/**
 * @tc.name: TestSetNeedRemoveMergePolicyData_SUC
 * @tc.desc: Test SetNeedRemoveMergePolicyData function.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleSerializerTest, TestSetNeedRemoveMergePolicyData_SUC, TestSize.Level1)
{
    std::map<std::string, std::vector<ApplicationInstance>> mergeData;
    ApplicationInstance app1 = CreateAppInstance("com.test.app1", 100, 0);
    mergeData["ohos.permission.CAMERA"] = {app1};

    std::map<std::string, std::vector<ApplicationInstance>> data;
    ApplicationInstance app2 = CreateAppInstance("com.test.app2", 100, 0);
    data["ohos.permission.CAMERA"] = {app1, app2};

    auto result = serializer_->SetNeedRemoveMergePolicyData(mergeData, data);
    EXPECT_EQ(result.size(), 1u);
    EXPECT_EQ(result["ohos.permission.CAMERA"].size(), 1u);
    EXPECT_EQ(result["ohos.permission.CAMERA"][0].appIdentifier, "com.test.app2");
}

/**
 * @tc.name: TestSetNeedRemoveMergePolicyDataPermissionNotExist_SUC
 * @tc.desc: Test SetNeedRemoveMergePolicyData when permission not in mergeData.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleSerializerTest, TestSetNeedRemoveMergePolicyDataPermissionNotExist_SUC, TestSize.Level1)
{
    std::map<std::string, std::vector<ApplicationInstance>> mergeData;
    ApplicationInstance app1 = CreateAppInstance("com.test.app1", 100, 0);
    mergeData["ohos.permission.LOCATION"] = {app1};

    std::map<std::string, std::vector<ApplicationInstance>> data;
    ApplicationInstance app2 = CreateAppInstance("com.test.app2", 100, 0);
    data["ohos.permission.CAMERA"] = {app2};

    auto result = serializer_->SetNeedRemoveMergePolicyData(mergeData, data);
    EXPECT_EQ(result.size(), 1u);
    EXPECT_TRUE(result.find("ohos.permission.CAMERA") != result.end());
}

/**
 * @tc.name: TestMakeKey_SUC
 * @tc.desc: Test MakeKey function.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleSerializerTest, TestMakeKey_SUC, TestSize.Level1)
{
    ApplicationInstance app;
    app.appIdentifier = "com.test.app1";
    app.accountId = 100;
    app.appIndex = 0;

    std::string key = serializer_->MakeKey(app);
    EXPECT_EQ(key, "com.test.app1_100_0");
}

/**
 * @tc.name: TestMakeKeyDifferentValues_SUC
 * @tc.desc: Test MakeKey with different values.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleSerializerTest, TestMakeKeyDifferentValues_SUC, TestSize.Level1)
{
    ApplicationInstance app1;
    app1.appIdentifier = "com.test.app1";
    app1.accountId = 100;
    app1.appIndex = 0;

    ApplicationInstance app2;
    app2.appIdentifier = "com.test.app1";
    app2.accountId = 100;
    app2.appIndex = 1;

    std::string key1 = serializer_->MakeKey(app1);
    std::string key2 = serializer_->MakeKey(app2);
    EXPECT_NE(key1, key2);
}

/**
 * @tc.name: TestIsAppInList_SUC
 * @tc.desc: Test IsAppInList function when app is in list.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleSerializerTest, TestIsAppInList_SUC, TestSize.Level1)
{
    ApplicationInstance app1 = CreateAppInstance("com.test.app1", 100, 0);
    ApplicationInstance app2 = CreateAppInstance("com.test.app1", 100, 0);
    ApplicationInstance app3 = CreateAppInstance("com.test.app2", 100, 0);
    std::vector<ApplicationInstance> appList = {app1, app3};

    bool ret = serializer_->IsAppInList(app2, appList);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: TestIsAppInListNotIn_FAIL
 * @tc.desc: Test IsAppInList function when app is not in list.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleSerializerTest, TestIsAppInListNotIn_FAIL, TestSize.Level1)
{
    ApplicationInstance app1 = CreateAppInstance("com.test.app1", 100, 0);
    ApplicationInstance app2 = CreateAppInstance("com.test.app2", 100, 0);
    ApplicationInstance app3 = CreateAppInstance("com.test.app3", 100, 0);
    std::vector<ApplicationInstance> appList = {app1, app2};

    bool ret = serializer_->IsAppInList(app3, appList);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: TestIsAppInListDifferentAppIndex_FAIL
 * @tc.desc: Test IsAppInList with different appIndex.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleSerializerTest, TestIsAppInListDifferentAppIndex_FAIL, TestSize.Level1)
{
    ApplicationInstance app1 = CreateAppInstance("com.test.app1", 100, 0);
    ApplicationInstance app2 = CreateAppInstance("com.test.app1", 100, 1);
    std::vector<ApplicationInstance> appList = {app1};

    bool ret = serializer_->IsAppInList(app2, appList);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: TestIsAppInListEmptyList_FAIL
 * @tc.desc: Test IsAppInList with empty list.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleSerializerTest, TestIsAppInListEmptyList_FAIL, TestSize.Level1)
{
    ApplicationInstance app = CreateAppInstance("com.test.app1", 100, 0);
    std::vector<ApplicationInstance> appList;

    bool ret = serializer_->IsAppInList(app, appList);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: TestGetAppsNotInList_SUC
 * @tc.desc: Test GetAppsNotInList function.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleSerializerTest, TestGetAppsNotInList_SUC, TestSize.Level1)
{
    ApplicationInstance app1 = CreateAppInstance("com.test.app1", 100, 0);
    ApplicationInstance app2 = CreateAppInstance("com.test.app2", 100, 0);
    ApplicationInstance app3 = CreateAppInstance("com.test.app3", 100, 0);
    std::vector<ApplicationInstance> sourceList = {app1, app2, app3};
    std::vector<ApplicationInstance> targetList = {app1};

    auto result = serializer_->GetAppsNotInList(sourceList, targetList);
    EXPECT_EQ(result.size(), 2u);
    EXPECT_EQ(result[0].appIdentifier, "com.test.app2");
    EXPECT_EQ(result[1].appIdentifier, "com.test.app3");
}

/**
 * @tc.name: TestGetAppsNotInListAllIn_SUC
 * @tc.desc: Test GetAppsNotInList when all apps are in target list.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleSerializerTest, TestGetAppsNotInListAllIn_SUC, TestSize.Level1)
{
    ApplicationInstance app1 = CreateAppInstance("com.test.app1", 100, 0);
    ApplicationInstance app2 = CreateAppInstance("com.test.app2", 100, 0);
    std::vector<ApplicationInstance> sourceList = {app1, app2};
    std::vector<ApplicationInstance> targetList = {app1, app2};

    auto result = serializer_->GetAppsNotInList(sourceList, targetList);
    EXPECT_TRUE(result.empty());
}

/**
 * @tc.name: TestGetAppsNotInListNoneIn_SUC
 * @tc.desc: Test GetAppsNotInList when none apps are in target list.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleSerializerTest, TestGetAppsNotInListNoneIn_SUC, TestSize.Level1)
{
    ApplicationInstance app1 = CreateAppInstance("com.test.app1", 100, 0);
    ApplicationInstance app2 = CreateAppInstance("com.test.app2", 100, 0);
    ApplicationInstance app3 = CreateAppInstance("com.test.app3", 100, 0);
    std::vector<ApplicationInstance> sourceList = {app1, app2};
    std::vector<ApplicationInstance> targetList = {app3};

    auto result = serializer_->GetAppsNotInList(sourceList, targetList);
    EXPECT_EQ(result.size(), 2u);
}

/**
 * @tc.name: TestGetAppsNotInListEmptySource_SUC
 * @tc.desc: Test GetAppsNotInList with empty source list.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleSerializerTest, TestGetAppsNotInListEmptySource_SUC, TestSize.Level1)
{
    std::vector<ApplicationInstance> sourceList;
    ApplicationInstance app1 = CreateAppInstance("com.test.app1", 100, 0);
    std::vector<ApplicationInstance> targetList = {app1};

    auto result = serializer_->GetAppsNotInList(sourceList, targetList);
    EXPECT_TRUE(result.empty());
}

/**
 * @tc.name: TestGetAppsInList_SUC
 * @tc.desc: Test GetAppsInList function.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleSerializerTest, TestGetAppsInList_SUC, TestSize.Level1)
{
    ApplicationInstance app1 = CreateAppInstance("com.test.app1", 100, 0);
    ApplicationInstance app2 = CreateAppInstance("com.test.app2", 100, 0);
    ApplicationInstance app3 = CreateAppInstance("com.test.app3", 100, 0);
    std::vector<ApplicationInstance> sourceList = {app1, app2, app3};
    std::vector<ApplicationInstance> targetList = {app1, app3};

    auto result = serializer_->GetAppsInList(sourceList, targetList);
    EXPECT_EQ(result.size(), 2u);
    EXPECT_EQ(result[0].appIdentifier, "com.test.app1");
    EXPECT_EQ(result[1].appIdentifier, "com.test.app3");
}

/**
 * @tc.name: TestGetAppsInListNoneIn_SUC
 * @tc.desc: Test GetAppsInList when none apps are in target list.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleSerializerTest, TestGetAppsInListNoneIn_SUC, TestSize.Level1)
{
    ApplicationInstance app1 = CreateAppInstance("com.test.app1", 100, 0);
    ApplicationInstance app2 = CreateAppInstance("com.test.app2", 100, 0);
    ApplicationInstance app3 = CreateAppInstance("com.test.app3", 100, 0);
    std::vector<ApplicationInstance> sourceList = {app1, app2};
    std::vector<ApplicationInstance> targetList = {app3};

    auto result = serializer_->GetAppsInList(sourceList, targetList);
    EXPECT_TRUE(result.empty());
}

/**
 * @tc.name: TestGetAppsInListEmptySource_SUC
 * @tc.desc: Test GetAppsInList with empty source list.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleSerializerTest, TestGetAppsInListEmptySource_SUC, TestSize.Level1)
{
    std::vector<ApplicationInstance> sourceList;
    ApplicationInstance app1 = CreateAppInstance("com.test.app1", 100, 0);
    std::vector<ApplicationInstance> targetList = {app1};

    auto result = serializer_->GetAppsInList(sourceList, targetList);
    EXPECT_TRUE(result.empty());
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS