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

#define private public
#include "settings_data_share_utils.h"
#undef private

#include <gtest/gtest.h>

#include "edm_ipc_interface_code.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class SettingsDataShareUtilsTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void SettingsDataShareUtilsTest::SetUpTestSuite(void)
{
    Utils::SetEdmServiceEnable();
    Utils::SetEdmInitialEnv();
}

void SettingsDataShareUtilsTest::TearDownTestSuite(void)
{
    Utils::SetEdmServiceDisable();
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: GetScreenOffTimeTest
 * @tc.desc: Test SettingsDataShareUtils::GetScreenOffTime function.
 * @tc.type: FUNC
 */
HWTEST_F(SettingsDataShareUtilsTest, GetScreenOffTimeTest, TestSize.Level1)
{
    int32_t time = 0;
    ErrCode code = SettingsDataShareUtils::GetScreenOffTime(time);
    ASSERT_TRUE(code == ERR_OK);
    ASSERT_TRUE(time != 0);
}

/**
 * @tc.name: SetScreenOffTimeTest
 * @tc.desc: Test SettingsDataShareUtils::SetScreenOffTime function.
 * @tc.type: FUNC
 */
HWTEST_F(SettingsDataShareUtilsTest, SetScreenOffTimeTest, TestSize.Level1)
{
    std::string time("30000");
    ErrCode code = SettingsDataShareUtils::SetScreenOffTime(time);
    ASSERT_TRUE(code == ERR_OK);
}

/**
 * @tc.name: GetDeviceNameTest
 * @tc.desc: Test SettingsDataShareUtils::GetDeviceName function.
 * @tc.type: FUNC
 */
HWTEST_F(SettingsDataShareUtilsTest, GetDeviceNameTest, TestSize.Level1)
{
    std::string deviceName;
    ErrCode code = SettingsDataShareUtils::GetDeviceName(deviceName);
    ASSERT_TRUE(code == ERR_OK);
}

/**
 * @tc.name: GetStringFromSettingsDataShareTest
 * @tc.desc: Test SettingsDataShareUtils::GetStringFromSettingsDataShare function.
 * @tc.type: FUNC
 */
HWTEST_F(SettingsDataShareUtilsTest, GetStringFromSettingsDataShareTest, TestSize.Level1)
{
    std::string key("settings.general.device_name");
    std::string deviceName;
    ErrCode code = SettingsDataShareUtils::GetStringFromSettingsDataShare(key, deviceName);
    ASSERT_TRUE(code == ERR_OK);

    key = "settings.general.invalid_test_key";
    code = SettingsDataShareUtils::GetStringFromSettingsDataShare(key, deviceName);
    ASSERT_TRUE(code == ERR_OK);
}

/**
 * @tc.name: GetIntFromSettingsDataShareTest
 * @tc.desc: Test SettingsDataShareUtils::GetIntFromSettingsDataShare function.
 * @tc.type: FUNC
 */
HWTEST_F(SettingsDataShareUtilsTest, GetIntFromSettingsDataShareTest, TestSize.Level1)
{
    std::string key("settings.display.screen_off_timeout");
    int32_t time = 0;
    ErrCode code = SettingsDataShareUtils::GetIntFromSettingsDataShare(key, time);
    ASSERT_TRUE(code == ERR_OK);

    key = "settings.general.invalid_test_key";
    code = SettingsDataShareUtils::GetIntFromSettingsDataShare(key, time);
    ASSERT_TRUE(code == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: UpdateSettingsDataTest
 * @tc.desc: Test SettingsDataShareUtils::UpdateSettingsData function.
 * @tc.type: FUNC
 */
HWTEST_F(SettingsDataShareUtilsTest, UpdateSettingsDataTest, TestSize.Level1)
{
    std::string key("settings.display.screen_off_timeout");
    std::string time("30000");
    ErrCode code = SettingsDataShareUtils::UpdateSettingsData(key, time);
    ASSERT_TRUE(code == ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS