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

#include "install_market_apps_serializer.h"

#include <gtest/gtest.h>

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class InstallMarketAppsSerializerTest : public testing::Test {};

/**
 * @tc.name: TestGetPolicy
 * @tc.desc: Test InstallMarketAppsSerializer::GetPolicy reads bundle list and the status fields.
 * @tc.type: FUNC
 */
HWTEST_F(InstallMarketAppsSerializerTest, TestGetPolicy, TestSize.Level1)
{
    auto serializer = InstallMarketAppsSerializer::GetInstance();
    MessageParcel data;
    std::vector<std::string> bundleNames = { "com.test.a", "com.test.b" };
    data.WriteStringVector(bundleNames);
    data.WriteInt32(1);
    data.WriteInt32(200);
    data.WriteString("com.test.a");
    data.WriteInt32(0);

    InstallMarketAppsInfo result;
    EXPECT_TRUE(serializer->GetPolicy(data, result));
    EXPECT_EQ(result.bundleNames.size(), 2u);
    EXPECT_EQ(result.bundleNames[0], "com.test.a");
    EXPECT_EQ(result.installFlag, 1);
    EXPECT_EQ(result.eventCode, 200);
    EXPECT_EQ(result.singleBundleName, "com.test.a");
    EXPECT_EQ(result.reason, 0);
}

/**
 * @tc.name: TestGetPolicyEmptyParcel
 * @tc.desc: Test InstallMarketAppsSerializer::GetPolicy keeps defaults when nothing was written.
 * @tc.type: FUNC
 */
HWTEST_F(InstallMarketAppsSerializerTest, TestGetPolicyEmptyParcel, TestSize.Level1)
{
    auto serializer = InstallMarketAppsSerializer::GetInstance();
    MessageParcel data;
    InstallMarketAppsInfo result;
    result.installFlag = 9;
    EXPECT_TRUE(serializer->GetPolicy(data, result));
    EXPECT_TRUE(result.bundleNames.empty());
}

/**
 * @tc.name: TestSerializeAndDeserialize
 * @tc.desc: Test InstallMarketAppsSerializer Serialize/Deserialize return success.
 * @tc.type: FUNC
 */
HWTEST_F(InstallMarketAppsSerializerTest, TestSerializeAndDeserialize, TestSize.Level1)
{
    auto serializer = InstallMarketAppsSerializer::GetInstance();
    InstallMarketAppsInfo config;
    config.bundleNames.push_back("com.test.a");
    std::string jsonString;
    EXPECT_TRUE(serializer->Serialize(config, jsonString));

    InstallMarketAppsInfo output;
    EXPECT_TRUE(serializer->Deserialize(jsonString, output));
}

/**
 * @tc.name: TestWritePolicyAndMergePolicy
 * @tc.desc: Test InstallMarketAppsSerializer WritePolicy/MergePolicy return success.
 * @tc.type: FUNC
 */
HWTEST_F(InstallMarketAppsSerializerTest, TestWritePolicyAndMergePolicy, TestSize.Level1)
{
    auto serializer = InstallMarketAppsSerializer::GetInstance();
    MessageParcel reply;
    InstallMarketAppsInfo result;
    EXPECT_TRUE(serializer->WritePolicy(reply, result));

    std::vector<InstallMarketAppsInfo> data = { result };
    InstallMarketAppsInfo merged;
    EXPECT_TRUE(serializer->MergePolicy(data, merged));
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
