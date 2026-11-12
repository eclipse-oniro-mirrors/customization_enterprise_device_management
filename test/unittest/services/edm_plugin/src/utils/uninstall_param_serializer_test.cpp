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

#include "uninstall_param_serializer.h"

#include <gtest/gtest.h>
#include "utils.h"
#include <message_parcel.h>

#include "edm_constants.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class UninstallParamSerializerTest : public testing::Test {};

/**
 * @tc.name: TestGetPolicy
 * @tc.desc: Test UninstallParamSerializer::GetPolicy reads bundle, userId and keepData flag.
 * @tc.type: FUNC
 */
HWTEST_F(UninstallParamSerializerTest, TestGetPolicy, TestSize.Level1)
{
    auto serializer = UninstallParamSerializer::GetInstance();
    MessageParcel data;
    data.WriteString("com.test.uninstall");
    data.WriteInt32(DEFAULT_USER_ID);
    data.WriteBool(true);

    UninstallParam result;
    EXPECT_TRUE(serializer->GetPolicy(data, result));
    EXPECT_EQ(result.bundleName, "com.test.uninstall");
    EXPECT_EQ(result.userId, DEFAULT_USER_ID);
    EXPECT_TRUE(result.isKeepData);
}

/**
 * @tc.name: TestGetPolicyKeepDataFalse
 * @tc.desc: Test UninstallParamSerializer::GetPolicy keeps the flag when it is not set.
 * @tc.type: FUNC
 */
HWTEST_F(UninstallParamSerializerTest, TestGetPolicyKeepDataFalse, TestSize.Level1)
{
    auto serializer = UninstallParamSerializer::GetInstance();
    MessageParcel data;
    data.WriteString("com.test.uninstall");
    data.WriteInt32(DEFAULT_USER_ID);
    data.WriteBool(false);

    UninstallParam result;
    EXPECT_TRUE(serializer->GetPolicy(data, result));
    EXPECT_EQ(result.bundleName, "com.test.uninstall");
    EXPECT_FALSE(result.isKeepData);
}

/**
 * @tc.name: TestSerializeAndDeserialize
 * @tc.desc: Test UninstallParamSerializer Serialize/Deserialize always succeed.
 * @tc.type: FUNC
 */
HWTEST_F(UninstallParamSerializerTest, TestSerializeAndDeserialize, TestSize.Level1)
{
    auto serializer = UninstallParamSerializer::GetInstance();
    UninstallParam config;
    config.bundleName = "com.test.uninstall";
    config.userId = DEFAULT_USER_ID;
    config.isKeepData = true;

    std::string jsonString;
    EXPECT_TRUE(serializer->Serialize(config, jsonString));

    UninstallParam output;
    EXPECT_TRUE(serializer->Deserialize("{}", output));
    EXPECT_TRUE(serializer->Deserialize("", output));
    EXPECT_TRUE(serializer->Deserialize("broken", output));
}

/**
 * @tc.name: TestWritePolicyAndMergePolicy
 * @tc.desc: Test UninstallParamSerializer WritePolicy/MergePolicy return success.
 * @tc.type: FUNC
 */
HWTEST_F(UninstallParamSerializerTest, TestWritePolicyAndMergePolicy, TestSize.Level1)
{
    auto serializer = UninstallParamSerializer::GetInstance();
    MessageParcel reply;
    UninstallParam result;
    EXPECT_TRUE(serializer->WritePolicy(reply, result));

    std::vector<UninstallParam> data = { result };
    UninstallParam merged;
    EXPECT_TRUE(serializer->MergePolicy(data, merged));
    std::vector<UninstallParam> emptyData;
    EXPECT_TRUE(serializer->MergePolicy(emptyData, merged));
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
