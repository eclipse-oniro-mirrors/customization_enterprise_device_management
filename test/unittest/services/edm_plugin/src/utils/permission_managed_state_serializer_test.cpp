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

#include "permission_managed_state_info.h"
#include "permission_managed_state_serializer_test.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string POLICY_DATA_ILLEGAL =
    "[{\"permissionName\":\"name0\",\"tokenId\":0,\"appIndex\":0,\"managedState\":0,"
    "\"permissionNames\":[\"name0\"]},{\"managedState\":0,\"permissionNames\":[\"name0\"]}]";

const std::string POLICY_DATA_ILLEGAL2 =
    "[{\"permissionName\":\"name0\",\"accountId\":0,\"managedState\":0,"
    "\"permissionNames\":[\"name0\"]}]";
const std::string POLICY_DATA1 =
    "[{\"appIdentifier\":\"0\",\"permissionName\":\"name0\",\"accountId\":0,\"tokenId\":0,\"appIndex\":0,"
    "\"managedState\":0,\"permissionNames\":[\"name0\"]},{\"appIdentifier\":\"1\",\"permissionName\":\"name1\","
    "\"accountId\":0,\"tokenId\":0,\"appIndex\":0,\"managedState\":0,\"permissionNames\":[\"name1\"]}]";

void PermissionManagedStateSerializerTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void PermissionManagedStateSerializerTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestDeserializeEmpty
 * @tc.desc: Test PermissionManagedStateSerializer::Deserialize when jsonString is empty
 * @tc.type: FUNC
 */
HWTEST_F(PermissionManagedStateSerializerTest, TestDeserializeEmpty, TestSize.Level1)
{
    auto serializer = PermissionManagedStateSerializer::GetInstance();
    std::string jsonString;
    std::map<std::string, PermissionManagedStateInfo> result;
    bool ret = serializer->Deserialize(jsonString, result);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(result.empty());
}

/**
 * @tc.name: TestDeserializeIllegal
 * @tc.desc: Test PermissionManagedStateSerializer::Deserialize when jsonString is illegal
 * @tc.type: FUNC
 */
HWTEST_F(PermissionManagedStateSerializerTest, TestDeserializeIllegal, TestSize.Level1)
{
    auto serializer = PermissionManagedStateSerializer::GetInstance();
    std::string jsonString = POLICY_DATA_ILLEGAL;
    std::map<std::string, PermissionManagedStateInfo> result;
    bool ret = serializer->Deserialize(jsonString, result);
    ASSERT_FALSE(ret);
    ASSERT_TRUE(result.empty());
}

/**
 * @tc.name: TestDeserializeIllegal2
 * @tc.desc: Test PermissionManagedStateSerializer::Deserialize when jsonString is illegal
 * @tc.type: FUNC
 */
HWTEST_F(PermissionManagedStateSerializerTest, TestDeserializeIllegal2, TestSize.Level1)
{
    auto serializer = PermissionManagedStateSerializer::GetInstance();
    std::string jsonString = POLICY_DATA_ILLEGAL2;
    std::map<std::string, PermissionManagedStateInfo> result;
    bool ret = serializer->Deserialize(jsonString, result);
    ASSERT_FALSE(ret);
    ASSERT_TRUE(result.empty());
}

/**
 * @tc.name: TestDeserializeSuc
 * @tc.desc: Test PermissionManagedStateSerializer::Deserialize
 * @tc.type: FUNC
 */
HWTEST_F(PermissionManagedStateSerializerTest, TestDeserializeSuc, TestSize.Level1)
{
    auto serializer = PermissionManagedStateSerializer::GetInstance();
    std::string jsonString = POLICY_DATA1;
    std::map<std::string, PermissionManagedStateInfo> result;
    bool ret = serializer->Deserialize(jsonString, result);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(result.size() == 2);
}

/**
 * @tc.name: TestSerializeEmpty
 * @tc.desc: Test PermissionManagedStateSerializer::Serialize
 * @tc.type: FUNC
 */
HWTEST_F(PermissionManagedStateSerializerTest, TestSerializeEmpty, TestSize.Level1)
{
    auto serializer = PermissionManagedStateSerializer::GetInstance();
    std::string jsonString;
    std::map<std::string, PermissionManagedStateInfo> result;
    bool ret = serializer->Serialize(result, jsonString);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(jsonString.empty());
}

/**
 * @tc.name: TestSerializeSuc
 * @tc.desc: Test PermissionManagedStateSerializer::Serialize
 * @tc.type: FUNC
 */
HWTEST_F(PermissionManagedStateSerializerTest, TestSerializeSuc, TestSize.Level1)
{
    auto serializer = PermissionManagedStateSerializer::GetInstance();
    std::string jsonString;
    std::map<std::string, PermissionManagedStateInfo> result;
    PermissionManagedStateInfo info;
    info.appIdentifier = "0";
    info.permissionName = "ohos.permission.CAMERA";
    info.accountId = 0;
    info.tokenId = 0;
    info.appIndex = 0;
    info.managedState = static_cast<int32_t>(ManagedState::GRANTED);
    info.permissionNames = {"ohos.permission.CAMERA"};
    result.insert(std::make_pair("1", info));
    bool ret = serializer->Serialize(result, jsonString);
    ASSERT_TRUE(ret);
    ASSERT_FALSE(jsonString.empty());
}

/**
 * @tc.name: TestGetPolicySuc
 * @tc.desc: Test PermissionManagedStateSerializer::GetPolicy without permissions
 * @tc.type: FUNC
 */
HWTEST_F(PermissionManagedStateSerializerTest, TestGetPolicyWithoutPermission, TestSize.Level1)
{
    auto serializer = PermissionManagedStateSerializer::GetInstance();
    MessageParcel data;
    data.WriteString("1");
    data.WriteInt32(100);
    data.WriteInt32(0);
    data.WriteInt32(0);
    std::map<std::string, PermissionManagedStateInfo> result;
    bool ret = serializer->GetPolicy(data, result);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TestGetPolicySuc
 * @tc.desc: Test PermissionManagedStateSerializer::GetPolicy with invalid appIdentifier
 * @tc.type: FUNC
 */
HWTEST_F(PermissionManagedStateSerializerTest, TestGetPolicyWithInvalidAppIdentifier, TestSize.Level1)
{
    auto serializer = PermissionManagedStateSerializer::GetInstance();
    MessageParcel data;
    data.WriteString("1");
    data.WriteInt32(100);
    data.WriteInt32(0);
    data.WriteStringVector({"permission"});
    data.WriteInt32(0);
    std::map<std::string, PermissionManagedStateInfo> result;
    bool ret = serializer->GetPolicy(data, result);
    ASSERT_FALSE(ret);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS