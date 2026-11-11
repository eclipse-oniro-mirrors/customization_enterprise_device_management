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

#include "operate_device_param_serializer.h"

#include <gtest/gtest.h>
#include "utils.h"
#include <message_parcel.h>

#include "edm_constants.h"
#include "message_parcel_utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
namespace {
const std::string TEST_OPERATE = "shutdown";
const std::string TEST_ADDITION = "30";
}

class OperateDeviceParamSerializerTest : public testing::Test {};

/**
 * @tc.name: TestGetPolicyAfterUtilsWrite
 * @tc.desc: Test OperateDeviceParamSerializer::GetPolicy reads what MessageParcelUtils wrote.
 * @tc.type: FUNC
 */
HWTEST_F(OperateDeviceParamSerializerTest, TestGetPolicyAfterUtilsWrite, TestSize.Level1)
{
    auto serializer = OperateDeviceParamSerializer::GetInstance();
    OperateDeviceParam input;
    input.operate = TEST_OPERATE;
    input.addition = TEST_ADDITION;
    input.userId = DEFAULT_USER_ID;
    input.size = 0;

    MessageParcel data;
    MessageParcelUtils::WriteOperateDeviceParam(input, data);
    data.RewindRead(0);

    OperateDeviceParam result;
    EXPECT_TRUE(serializer->GetPolicy(data, result));
    EXPECT_EQ(result.operate, TEST_OPERATE);
    EXPECT_EQ(result.addition, TEST_ADDITION);
    EXPECT_EQ(result.userId, DEFAULT_USER_ID);
    EXPECT_EQ(result.size, 0);
}

/**
 * @tc.name: TestGetPolicyWithFileContent
 * @tc.desc: Test OperateDeviceParamSerializer::GetPolicy reads the payload when size is set.
 * @tc.type: FUNC
 */
HWTEST_F(OperateDeviceParamSerializerTest, TestGetPolicyWithFileContent, TestSize.Level1)
{
    auto serializer = OperateDeviceParamSerializer::GetInstance();
    OperateDeviceParam input;
    input.operate = TEST_OPERATE;
    input.addition = TEST_ADDITION;
    input.userId = DEFAULT_USER_ID;
    input.file = { 1, 2, 3 };
    input.size = static_cast<int32_t>(input.file.size());

    MessageParcel data;
    MessageParcelUtils::WriteOperateDeviceParam(input, data);
    data.RewindRead(0);

    OperateDeviceParam result;
    EXPECT_TRUE(serializer->GetPolicy(data, result));
    EXPECT_EQ(result.size, 3);
    EXPECT_EQ(result.file.size(), 3u);
}

/**
 * @tc.name: TestWritePolicy
 * @tc.desc: Test OperateDeviceParamSerializer::WritePolicy delegates to MessageParcelUtils.
 * @tc.type: FUNC
 */
HWTEST_F(OperateDeviceParamSerializerTest, TestWritePolicy, TestSize.Level1)
{
    auto serializer = OperateDeviceParamSerializer::GetInstance();
    OperateDeviceParam result;
    result.operate = TEST_OPERATE;
    MessageParcel reply;
    EXPECT_TRUE(serializer->WritePolicy(reply, result));
    reply.RewindRead(0);
    EXPECT_EQ(reply.ReadString(), TEST_OPERATE);
}

/**
 * @tc.name: TestSerializeDeserializeAndMerge
 * @tc.desc: Test OperateDeviceParamSerializer Serialize/Deserialize/MergePolicy return success.
 * @tc.type: FUNC
 */
HWTEST_F(OperateDeviceParamSerializerTest, TestSerializeDeserializeAndMerge, TestSize.Level1)
{
    auto serializer = OperateDeviceParamSerializer::GetInstance();
    OperateDeviceParam config;
    config.operate = TEST_OPERATE;
    std::string jsonString;
    EXPECT_TRUE(serializer->Serialize(config, jsonString));
    EXPECT_TRUE(serializer->Deserialize("{}", config));
    EXPECT_TRUE(serializer->Deserialize("broken", config));

    std::vector<OperateDeviceParam> data = { config };
    OperateDeviceParam merged;
    EXPECT_TRUE(serializer->MergePolicy(data, merged));
    std::vector<OperateDeviceParam> emptyData;
    EXPECT_TRUE(serializer->MergePolicy(emptyData, merged));
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
