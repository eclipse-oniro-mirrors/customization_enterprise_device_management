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

#include "clear_up_application_data_param_serializer.h"

#include <gtest/gtest.h>
#include "utils.h"
#include <message_parcel.h>

#include "edm_constants.h"
#include "message_parcel_utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class ClearUpApplicationDataParamSerializerTest : public testing::Test {};

/**
 * @tc.name: TestGetPolicyAfterUtilsWrite
 * @tc.desc: Test ClearUpApplicationDataParamSerializer::GetPolicy reads the utils output.
 * @tc.type: FUNC
 */
HWTEST_F(ClearUpApplicationDataParamSerializerTest, TestGetPolicyAfterUtilsWrite, TestSize.Level1)
{
    auto serializer = ClearUpApplicationDataParamSerializer::GetInstance();
    ClearUpApplicationDataParam input;
    input.bundleName = "com.test.clear";
    input.appIndex = 3;
    input.userId = DEFAULT_USER_ID;

    MessageParcel data;
    MessageParcelUtils::WriteClearUpApplicationDataParam(input, data);
    data.RewindRead(0);

    ClearUpApplicationDataParam result;
    EXPECT_TRUE(serializer->GetPolicy(data, result));
    EXPECT_EQ(result.bundleName, "com.test.clear");
    EXPECT_EQ(result.appIndex, 3);
    EXPECT_EQ(result.userId, DEFAULT_USER_ID);
}

/**
 * @tc.name: TestWritePolicy
 * @tc.desc: Test ClearUpApplicationDataParamSerializer::WritePolicy delegates to utils.
 * @tc.type: FUNC
 */
HWTEST_F(ClearUpApplicationDataParamSerializerTest, TestWritePolicy, TestSize.Level1)
{
    auto serializer = ClearUpApplicationDataParamSerializer::GetInstance();
    ClearUpApplicationDataParam result;
    result.bundleName = "com.test.clear";
    MessageParcel reply;
    EXPECT_TRUE(serializer->WritePolicy(reply, result));
    reply.RewindRead(0);
    EXPECT_EQ(reply.ReadString(), "com.test.clear");
}

/**
 * @tc.name: TestSerializeAndDeserialize
 * @tc.desc: Test ClearUpApplicationDataParamSerializer Serialize/Deserialize always succeed.
 * @tc.type: FUNC
 */
HWTEST_F(ClearUpApplicationDataParamSerializerTest, TestSerializeAndDeserialize, TestSize.Level1)
{
    auto serializer = ClearUpApplicationDataParamSerializer::GetInstance();
    ClearUpApplicationDataParam config;
    std::string jsonString;
    EXPECT_TRUE(serializer->Serialize(config, jsonString));
    EXPECT_TRUE(serializer->Deserialize("{}", config));
    EXPECT_TRUE(serializer->Deserialize("broken", config));
}

/**
 * @tc.name: TestMergePolicy
 * @tc.desc: Test ClearUpApplicationDataParamSerializer::MergePolicy returns success.
 * @tc.type: FUNC
 */
HWTEST_F(ClearUpApplicationDataParamSerializerTest, TestMergePolicy, TestSize.Level1)
{
    auto serializer = ClearUpApplicationDataParamSerializer::GetInstance();
    std::vector<ClearUpApplicationDataParam> data;
    ClearUpApplicationDataParam item;
    item.bundleName = "com.test.clear";
    data.push_back(item);
    ClearUpApplicationDataParam result;
    EXPECT_TRUE(serializer->MergePolicy(data, result));
    std::vector<ClearUpApplicationDataParam> emptyData;
    EXPECT_TRUE(serializer->MergePolicy(emptyData, result));
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
