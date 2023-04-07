/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "wifi_device_config_serializer.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class WifiDeviceConfigSerializerTest : public testing::Test {
protected:
    void SetUp() override {}

    void TearDown() override {}
};

/**
 * @tc.name: TestWifiDeviceConfigSerializer
 * @tc.desc: Test Serialize and Deserialize function.
 * @tc.type: FUNC
 */
HWTEST_F(WifiDeviceConfigSerializerTest, TestSerializeAndDeserialize, TestSize.Level1)
{
    auto serializer = WifiDeviceConfigSerializer::GetInstance();
    Wifi::WifiDeviceConfig config;
    config.wifiEapConfig.certEntry = { 0x01 };
    config.wifiIpConfig.staticIpAddress.ipAddress.address.addressIpv6 = { 0x02 };
    std::string jsonStr;
    serializer->Serialize(config, jsonStr);
    Wifi::WifiDeviceConfig deConfig;
    serializer->Deserialize(jsonStr, deConfig);
    ASSERT_TRUE(config.wifiEapConfig.certEntry == deConfig.wifiEapConfig.certEntry);
    ASSERT_TRUE(deConfig.wifiIpConfig.staticIpAddress.ipAddress.address.addressIpv6[0] == 0x02);
}

/**
 * @tc.name: TestWifiDeviceConfigSerializer
 * @tc.desc: Test WritePolicy and GetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(WifiDeviceConfigSerializerTest, TestWritePolicyAndGetPolicy, TestSize.Level1)
{
    auto serializer = WifiDeviceConfigSerializer::GetInstance();
    Wifi::WifiDeviceConfig config;
    config.wifiEapConfig.certEntry = { 0x01 };
    config.wifiIpConfig.staticIpAddress.ipAddress.address.addressIpv6 = { 0x02 };
    MessageParcel data;
    serializer->WritePolicy(data, config);
    Wifi::WifiDeviceConfig deConfig;
    serializer->GetPolicy(data, deConfig);
    ASSERT_TRUE(config.wifiEapConfig.certEntry == deConfig.wifiEapConfig.certEntry);
    ASSERT_TRUE(deConfig.wifiIpConfig.staticIpAddress.ipAddress.address.addressIpv6[0] == 0x02);
}

/**
 * @tc.name: TestWifiDeviceConfigSerializer
 * @tc.desc: Test MergePolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(WifiDeviceConfigSerializerTest, TestMergePolicy, TestSize.Level1)
{
    auto serializer = WifiDeviceConfigSerializer::GetInstance();
    std::vector<Wifi::WifiDeviceConfig> data;
    Wifi::WifiDeviceConfig result;
    serializer->MergePolicy(data, result);
    ASSERT_FALSE(result.hiddenSSID);
    Wifi::WifiDeviceConfig config;
    config.hiddenSSID = true;
    data.push_back(config);
    serializer->MergePolicy(data, result);
    ASSERT_TRUE(result.hiddenSSID);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS