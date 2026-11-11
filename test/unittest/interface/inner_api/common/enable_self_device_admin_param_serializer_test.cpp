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

#include "enable_self_device_admin_param_serializer.h"

#include <gtest/gtest.h>

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class EnableSelfDeviceAdminParamSerializerTest : public testing::Test {};

/**
 * @tc.name: TestGetPolicyThreeStrings
 * @tc.desc: Test EnableSelfDeviceAdminParamSerializer::GetPolicy reads the three strings.
 * @tc.type: FUNC
 */
HWTEST_F(EnableSelfDeviceAdminParamSerializerTest, TestGetPolicyThreeStrings, TestSize.Level1)
{
    auto serializer = EnableSelfDeviceAdminParamSerializer::GetInstance();
    MessageParcel data;
    data.WriteString("com.test.admin");
    data.WriteString("TestAbility");
    data.WriteString("credential-value");

    EnableSelfDeviceAdminParam result;
    EXPECT_TRUE(serializer->GetPolicy(data, result));
    EXPECT_EQ(result.bundleName, "com.test.admin");
    EXPECT_EQ(result.abilityName, "TestAbility");
    EXPECT_EQ(result.credential, "credential-value");
}

/**
 * @tc.name: TestGetPolicyEmptyParcel
 * @tc.desc: Test EnableSelfDeviceAdminParamSerializer::GetPolicy keeps fields empty when absent.
 * @tc.type: FUNC
 */
HWTEST_F(EnableSelfDeviceAdminParamSerializerTest, TestGetPolicyEmptyParcel, TestSize.Level1)
{
    auto serializer = EnableSelfDeviceAdminParamSerializer::GetInstance();
    MessageParcel data;
    EnableSelfDeviceAdminParam result;
    EXPECT_TRUE(serializer->GetPolicy(data, result));
    EXPECT_TRUE(result.bundleName.empty());
    EXPECT_TRUE(result.abilityName.empty());
    EXPECT_TRUE(result.credential.empty());
}

/**
 * @tc.name: TestSerializeAndDeserialize
 * @tc.desc: Test EnableSelfDeviceAdminParamSerializer Serialize/Deserialize always succeed.
 * @tc.type: FUNC
 */
HWTEST_F(EnableSelfDeviceAdminParamSerializerTest, TestSerializeAndDeserialize, TestSize.Level1)
{
    auto serializer = EnableSelfDeviceAdminParamSerializer::GetInstance();
    EnableSelfDeviceAdminParam config;
    config.bundleName = "com.test.admin";
    std::string jsonString;
    EXPECT_TRUE(serializer->Serialize(config, jsonString));

    EnableSelfDeviceAdminParam output;
    EXPECT_TRUE(serializer->Deserialize(jsonString, output));
}

/**
 * @tc.name: TestMergePolicy
 * @tc.desc: Test EnableSelfDeviceAdminParamSerializer::MergePolicy returns success.
 * @tc.type: FUNC
 */
HWTEST_F(EnableSelfDeviceAdminParamSerializerTest, TestMergePolicy, TestSize.Level1)
{
    auto serializer = EnableSelfDeviceAdminParamSerializer::GetInstance();
    std::vector<EnableSelfDeviceAdminParam> data;
    EnableSelfDeviceAdminParam item;
    item.bundleName = "com.test.admin";
    data.push_back(item);
    EnableSelfDeviceAdminParam result;
    EXPECT_TRUE(serializer->MergePolicy(data, result));
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
