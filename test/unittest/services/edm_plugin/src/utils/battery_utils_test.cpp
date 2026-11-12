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

#include <gtest/gtest.h>

#include "edm_constants.h"

#define private public
#include "battery_utils.h"
#undef private
#include "utils.h"


using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class BatteryUtilsTest : public testing::Test {};

/**
 * @tc.name: TestGetBatteryPluggedType
 * @tc.desc: Test BatteryUtils::GetBatteryPluggedType returns the fixed plugged type.
 * @tc.type: FUNC
 */
HWTEST_F(BatteryUtilsTest, TestGetBatteryPluggedType, TestSize.Level1)
{
    std::string type = BatteryUtils::GetBatteryPluggedType();
    EXPECT_EQ(type, BatteryUtils::PLUGGED_TYPE_DC);
    EXPECT_NE(type, BatteryUtils::PLUGGED_TYPE_AC);
}

/**
 * @tc.name: TestGetSubUserTableUri
 * @tc.desc: Test BatteryUtils::GetSubUserTableUri builds the settingsdata uri of the user.
 * @tc.type: FUNC
 */
HWTEST_F(BatteryUtilsTest, TestGetSubUserTableUri, TestSize.Level1)
{
    std::string uri = BatteryUtils::GetSubUserTableUri();
    const std::string prefix = "datashare:///com.ohos.settingsdata/entry/settingsdata/";
    EXPECT_NE(uri.find(prefix + "USER_SETTINGSDATA_SECURE_"), std::string::npos);
    EXPECT_NE(uri.find("?Proxy=true"), std::string::npos);
    EXPECT_GT(uri.size(), std::string("datashare:///").size());
}

/**
 * @tc.name: TestGetCurrentUserId
 * @tc.desc: Test BatteryUtils::GetCurrentUserId returns -1 or an existing account id.
 * @tc.type: FUNC
 */
HWTEST_F(BatteryUtilsTest, TestGetCurrentUserId, TestSize.Level1)
{
    int32_t userId = BatteryUtils::GetCurrentUserId();
    EXPECT_TRUE(userId == -1 || userId >= DEFAULT_USER_ID);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
