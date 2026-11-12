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

#include "http_proxy_serializer.h"

#include <gtest/gtest.h>
#include "utils.h"
#include <message_parcel.h>

#include "edm_constants.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class HttpProxySerializerTest : public testing::Test {};

/**
 * @tc.name: TestGetPolicyEmptyParcel
 * @tc.desc: Test HttpProxySerializer::GetPolicy fails when the parcel holds no proxy.
 * @tc.type: FUNC
 */
HWTEST_F(HttpProxySerializerTest, TestGetPolicyEmptyParcel, TestSize.Level1)
{
    auto serializer = HttpProxySerializer::GetInstance();
    MessageParcel data;
    NetManagerStandard::HttpProxy httpProxy;
    EXPECT_FALSE(serializer->GetPolicy(data, httpProxy));
}

/**
 * @tc.name: TestSerializeAndDeserialize
 * @tc.desc: Test HttpProxySerializer Serialize/Deserialize always succeed.
 * @tc.type: FUNC
 */
HWTEST_F(HttpProxySerializerTest, TestSerializeAndDeserialize, TestSize.Level1)
{
    auto serializer = HttpProxySerializer::GetInstance();
    NetManagerStandard::HttpProxy config;
    std::string jsonString = "unset";
    EXPECT_TRUE(serializer->Serialize(config, jsonString));
    EXPECT_EQ(jsonString, "unset");
    EXPECT_TRUE(serializer->Deserialize("{}", config));
    EXPECT_TRUE(serializer->Deserialize("broken", config));
}

/**
 * @tc.name: TestWritePolicyAndMergePolicy
 * @tc.desc: Test HttpProxySerializer WritePolicy/MergePolicy return success.
 * @tc.type: FUNC
 */
HWTEST_F(HttpProxySerializerTest, TestWritePolicyAndMergePolicy, TestSize.Level1)
{
    auto serializer = HttpProxySerializer::GetInstance();
    MessageParcel reply;
    NetManagerStandard::HttpProxy result;
    EXPECT_TRUE(serializer->WritePolicy(reply, result));

    std::vector<NetManagerStandard::HttpProxy> data = { result };
    EXPECT_TRUE(serializer->MergePolicy(data, result));
    std::vector<NetManagerStandard::HttpProxy> emptyData;
    EXPECT_TRUE(serializer->MergePolicy(emptyData, result));
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
