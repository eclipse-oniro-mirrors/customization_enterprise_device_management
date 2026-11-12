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

#include "wall_paper_param_serializer.h"

#include <fcntl.h>
#include <gtest/gtest.h>
#include <unistd.h>

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class WallPaperParamSerializerTest : public testing::Test {};

/**
 * @tc.name: TestGetPolicyFdAndFlag
 * @tc.desc: Test WallPaperParamSerializer::GetPolicy reads the fd and the home-screen flag.
 * @tc.type: FUNC
 */
HWTEST_F(WallPaperParamSerializerTest, TestGetPolicyFdAndFlag, TestSize.Level1)
{
    auto serializer = WallPaperParamSerializer::GetInstance();
    int32_t fd = ::open("/dev/null", O_RDONLY);
    ASSERT_GE(fd, 0);
    MessageParcel data;
    data.WriteFileDescriptor(fd);
    data.WriteBool(true);
    ::close(fd);

    WallPaperParam result;
    EXPECT_TRUE(serializer->GetPolicy(data, result));
    EXPECT_GE(result.fd, 0);
    EXPECT_TRUE(result.isHomeWallPaper);
    if (result.fd >= 0) {
        ::close(result.fd);
    }
}

/**
 * @tc.name: TestGetPolicyWithoutFd
 * @tc.desc: Test WallPaperParamSerializer::GetPolicy reports an invalid fd when none was written.
 * @tc.type: FUNC
 */
HWTEST_F(WallPaperParamSerializerTest, TestGetPolicyWithoutFd, TestSize.Level1)
{
    auto serializer = WallPaperParamSerializer::GetInstance();
    MessageParcel data;
    data.WriteBool(false);

    WallPaperParam result;
    result.fd = 123;
    EXPECT_TRUE(serializer->GetPolicy(data, result));
    EXPECT_EQ(result.isHomeWallPaper, false);
}

/**
 * @tc.name: TestSerializeAndMergePolicy
 * @tc.desc: Test WallPaperParamSerializer Serialize/Deserialize/MergePolicy return success.
 * @tc.type: FUNC
 */
HWTEST_F(WallPaperParamSerializerTest, TestSerializeAndMergePolicy, TestSize.Level1)
{
    auto serializer = WallPaperParamSerializer::GetInstance();
    WallPaperParam config;
    config.isHomeWallPaper = true;
    config.fd = -1;
    std::string jsonString;
    EXPECT_TRUE(serializer->Serialize(config, jsonString));

    WallPaperParam output;
    EXPECT_TRUE(serializer->Deserialize(jsonString, output));

    std::vector<WallPaperParam> data = { config };
    WallPaperParam result;
    EXPECT_TRUE(serializer->MergePolicy(data, result));
}

/**
 * @tc.name: TestWritePolicy
 * @tc.desc: Test WallPaperParamSerializer::WritePolicy returns success.
 * @tc.type: FUNC
 */
HWTEST_F(WallPaperParamSerializerTest, TestWritePolicy, TestSize.Level1)
{
    auto serializer = WallPaperParamSerializer::GetInstance();
    MessageParcel reply;
    WallPaperParam result;
    result.isHomeWallPaper = false;
    result.fd = -1;
    EXPECT_TRUE(serializer->WritePolicy(reply, result));
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
