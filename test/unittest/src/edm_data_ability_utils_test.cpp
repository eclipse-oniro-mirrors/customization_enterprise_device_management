/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "edm_data_ability_utils.h"

#include <gtest/gtest.h>

#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string KEY_DEVICE_NAME = "settings.general.device_name";
const std::string KEY_SCREEN_OFF_TIME = "settings.display.screen_off_timeout";
const std::string INVAILD_STRING = "settings.general.invalid_string";

class EdmDataAbilityUtilsTest : public testing::Test {
protected:
    void SetUp() override;

    void TearDown() override;

    static void TearDownTestSuite(void);
};

void EdmDataAbilityUtilsTest::SetUp()
{
    Utils::SetEdmInitialEnv();
    Utils::SetEdmServiceEnable();
}

void EdmDataAbilityUtilsTest::TearDown()
{
    Utils::ResetTokenTypeAndUid();
    Utils::SetEdmServiceDisable();
}

void EdmDataAbilityUtilsTest::TearDownTestSuite()
{
    ASSERT_FALSE(Utils::GetEdmServiceState());
    std::cout << "EdmServiceState : " << Utils::GetEdmServiceState() << std::endl;
}

/**
 * @tc.name: TestGetStringFromSettingsDataShare
 * @tc.desc: Test GetStringFromSettingsDataShare function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmDataAbilityUtilsTest, TestGetStringFromSettingsDataShare, TestSize.Level1)
{
    std::string result;
    ErrCode code = EdmDataAbilityUtils::GetStringFromSettingsDataShare(INVAILD_STRING, result);
    ASSERT_TRUE(code == ERR_OK);
    ASSERT_TRUE(result.empty());

    code = EdmDataAbilityUtils::GetStringFromSettingsDataShare(KEY_DEVICE_NAME, result);
    ASSERT_TRUE(code == ERR_OK);
    ASSERT_FALSE(result.empty());
}

/**
 * @tc.name: TestGetIntFromSettingsDataShare
 * @tc.desc: Test GetIntFromSettingsDataShare function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmDataAbilityUtilsTest, TestGetIntFromSettingsDataShare, TestSize.Level1)
{
    int32_t result = 0;
    ErrCode code = EdmDataAbilityUtils::GetIntFromSettingsDataShare(INVAILD_STRING, result);
    ASSERT_TRUE(code == EdmReturnErrCode::SYSTEM_ABNORMALLY);

    code = EdmDataAbilityUtils::GetIntFromSettingsDataShare(KEY_SCREEN_OFF_TIME, result);
    ASSERT_TRUE(code == ERR_OK);
    ASSERT_FALSE(result == 0);
}

/**
 * @tc.name: TestUpdateSettingsData
 * @tc.desc: Test UpdateSettingsData function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmDataAbilityUtilsTest, TestUpdateSettingsData, TestSize.Level1)
{
    std::string value = "30000";
    ErrCode code = EdmDataAbilityUtils::UpdateSettingsData(KEY_SCREEN_OFF_TIME, value);
    ASSERT_TRUE(code == ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS