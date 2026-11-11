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

#include "wifi_device_config_serializer.h"

#include <gtest/gtest.h>
#include "utils.h"
#include <message_parcel.h>

#include "edm_constants.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class WifiDeviceConfigSerializerTest : public testing::Test {};

/**
 * @tc.name: TestGetPolicyEmptyParcel
 * @tc.desc: Test WifiDeviceConfigSerializer::GetPolicy succeeds on an empty parcel.
 * @tc.type: FUNC
 */
HWTEST_F(WifiDeviceConfigSerializerTest, TestGetPolicyEmptyParcel, TestSize.Level1)
{
    auto serializer = WifiDeviceConfigSerializer::GetInstance();
    MessageParcel data;
    Wifi::WifiDeviceConfig result;
    EXPECT_TRUE(serializer->GetPolicy(data, result));
}

/**
 * @tc.name: TestSerializeKeepsPolicyString
 * @tc.desc: Test WifiDeviceConfigSerializer::Serialize does not touch the output string.
 * @tc.type: FUNC
 */
HWTEST_F(WifiDeviceConfigSerializerTest, TestSerializeKeepsPolicyString, TestSize.Level1)
{
    auto serializer = WifiDeviceConfigSerializer::GetInstance();
    Wifi::WifiDeviceConfig config;
    std::string jsonString = "unset";
    EXPECT_TRUE(serializer->Serialize(config, jsonString));
    EXPECT_EQ(jsonString, "unset");
}

/**
 * @tc.name: TestDeserializeAlwaysSucceeds
 * @tc.desc: Test WifiDeviceConfigSerializer::Deserialize accepts any input.
 * @tc.type: FUNC
 */
HWTEST_F(WifiDeviceConfigSerializerTest, TestDeserializeAlwaysSucceeds, TestSize.Level1)
{
    auto serializer = WifiDeviceConfigSerializer::GetInstance();
    Wifi::WifiDeviceConfig config;
    EXPECT_TRUE(serializer->Deserialize("{}", config));
    EXPECT_TRUE(serializer->Deserialize("", config));
    EXPECT_TRUE(serializer->Deserialize("broken", config));
}

/**
 * @tc.name: TestWritePolicyAndMergePolicy
 * @tc.desc: Test WifiDeviceConfigSerializer WritePolicy/MergePolicy return success.
 * @tc.type: FUNC
 */
HWTEST_F(WifiDeviceConfigSerializerTest, TestWritePolicyAndMergePolicy, TestSize.Level1)
{
    auto serializer = WifiDeviceConfigSerializer::GetInstance();
    MessageParcel reply;
    Wifi::WifiDeviceConfig result;
    EXPECT_TRUE(serializer->WritePolicy(reply, result));
    std::vector<Wifi::WifiDeviceConfig> data = { result };
    EXPECT_TRUE(serializer->MergePolicy(data, result));
    std::vector<Wifi::WifiDeviceConfig> emptyData;
    EXPECT_TRUE(serializer->MergePolicy(emptyData, result));
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
