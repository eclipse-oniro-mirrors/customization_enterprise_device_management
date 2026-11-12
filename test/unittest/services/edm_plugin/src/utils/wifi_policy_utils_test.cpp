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

#include "wifi_policy_utils.h"

#include <gtest/gtest.h>

#include "edm_constants.h"
#include "wifi_id.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
namespace {
std::string MakeLongSsid(size_t length)
{
    std::string ssid;
    for (size_t i = 0; i < length; i++) {
        ssid += static_cast<char>('a' + (i % 26));
    }
    return ssid;
}

WifiId BuildWifiId(const std::string &ssid, const std::string &bssid)
{
    WifiId wifiId;
    wifiId.SetSsid(ssid);
    if (!bssid.empty()) {
        wifiId.SetBssid(bssid);
    }
    return wifiId;
}
}

class WifiPolicyUtilsTest : public testing::Test {};

/**
 * @tc.name: TestCheckWifiIdEmptyList
 * @tc.desc: Test WifiPolicyUtils::CheckWifiId accepts an empty list.
 * @tc.type: FUNC
 */
HWTEST_F(WifiPolicyUtilsTest, TestCheckWifiIdEmptyList, TestSize.Level1)
{
    std::vector<WifiId> data;
    EXPECT_TRUE(WifiPolicyUtils::CheckWifiId(data, true));
    EXPECT_TRUE(WifiPolicyUtils::CheckWifiId(data, false));
}

/**
 * @tc.name: TestCheckWifiIdValid
 * @tc.desc: Test WifiPolicyUtils::CheckWifiId accepts a valid ssid with a full-length bssid.
 * @tc.type: FUNC
 */
HWTEST_F(WifiPolicyUtilsTest, TestCheckWifiIdValid, TestSize.Level1)
{
    std::vector<WifiId> data = { BuildWifiId("testSsid", "11:22:33:44:55:66") };
    EXPECT_TRUE(WifiPolicyUtils::CheckWifiId(data, true));
}

/**
 * @tc.name: TestCheckWifiIdEmptySsid
 * @tc.desc: Test WifiPolicyUtils::CheckWifiId rejects an empty ssid.
 * @tc.type: FUNC
 */
HWTEST_F(WifiPolicyUtilsTest, TestCheckWifiIdEmptySsid, TestSize.Level1)
{
    std::vector<WifiId> data = { BuildWifiId("", "") };
    EXPECT_FALSE(WifiPolicyUtils::CheckWifiId(data, true));
}

/**
 * @tc.name: TestCheckWifiIdOversizeSsid
 * @tc.desc: Test WifiPolicyUtils::CheckWifiId rejects a ssid longer than the limit.
 * @tc.type: FUNC
 */
HWTEST_F(WifiPolicyUtilsTest, TestCheckWifiIdOversizeSsid, TestSize.Level1)
{
    std::string longSsid = MakeLongSsid(EdmConstants::WIFI_SSID_MAX_LENGTH + 1);
    std::vector<WifiId> data = { BuildWifiId(longSsid, "") };
    EXPECT_FALSE(WifiPolicyUtils::CheckWifiId(data, true));
}

/**
 * @tc.name: TestCheckWifiIdInvalidBssid
 * @tc.desc: Test WifiPolicyUtils::CheckWifiId rejects a bssid with a wrong length.
 * @tc.type: FUNC
 */
HWTEST_F(WifiPolicyUtilsTest, TestCheckWifiIdInvalidBssid, TestSize.Level1)
{
    std::vector<WifiId> data = { BuildWifiId("testSsid", "11:22:33") };
    EXPECT_FALSE(WifiPolicyUtils::CheckWifiId(data, false));
}

/**
 * @tc.name: TestHasConflictPolicyStable
 * @tc.desc: Test WifiPolicyUtils::HasConflictPolicy is stable for the same stored policies.
 * @tc.type: FUNC
 */
HWTEST_F(WifiPolicyUtilsTest, TestHasConflictPolicyStable, TestSize.Level1)
{
    EXPECT_EQ(WifiPolicyUtils::HasConflictPolicy(true), WifiPolicyUtils::HasConflictPolicy(true));
    EXPECT_EQ(WifiPolicyUtils::HasConflictPolicy(false), WifiPolicyUtils::HasConflictPolicy(false));
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
