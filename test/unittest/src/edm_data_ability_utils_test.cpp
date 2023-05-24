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

#include <gtest/gtest.h>
#include "edm_data_ability_utils.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string INVALID_BASE_URI =
    "datashare:///com.ohos.invalid/entry/settingsdata/SETTINGSDATA?Proxy=true";
const std::string ERROR_URI = "datashare:///com.ohos.settingsdata";
const std::string PREDICATES_STRING = "settings.general.device_name";
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
 * @tc.name: TestGetStringFromDataShare
 * @tc.desc: Test GetStringFromDataShare function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmDataAbilityUtilsTest, TestGetStringFromDataShare, TestSize.Level1)
{
    std::string result;
    ErrCode code = EdmDataAbilityUtils::GetStringFromDataShare(ERROR_URI, PREDICATES_STRING, result);
    ASSERT_TRUE(code == EdmReturnErrCode::SYSTEM_ABNORMALLY);

    code = EdmDataAbilityUtils::GetStringFromDataShare(INVALID_BASE_URI, PREDICATES_STRING, result);
    ASSERT_TRUE(code == EdmReturnErrCode::SYSTEM_ABNORMALLY);

    EdmDataAbilityUtils::GetStringFromDataShare(EdmDataAbilityUtils::SETTINGS_DATA_BASE_URI, INVAILD_STRING, result);
    ASSERT_TRUE(result.empty());

    EdmDataAbilityUtils::GetStringFromDataShare(EdmDataAbilityUtils::SETTINGS_DATA_BASE_URI, PREDICATES_STRING, result);
    ASSERT_FALSE(result.empty());
}

/**
 * @tc.name: TestGetIntFromDataShare
 * @tc.desc: Test GetIntFromDataShare function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmDataAbilityUtilsTest, TestGetIntFromDataShare, TestSize.Level1)
{
    int32_t result = 0;
    ErrCode code = EdmDataAbilityUtils::GetIntFromDataShare(ERROR_URI, KEY_SCREEN_OFF_TIME, result);
    ASSERT_TRUE(code == EdmReturnErrCode::SYSTEM_ABNORMALLY);

    code = EdmDataAbilityUtils::GetIntFromDataShare(INVALID_BASE_URI, KEY_SCREEN_OFF_TIME, result);
    ASSERT_TRUE(code == EdmReturnErrCode::SYSTEM_ABNORMALLY);

    EdmDataAbilityUtils::GetIntFromDataShare(EdmDataAbilityUtils::SETTINGS_DATA_BASE_URI, INVAILD_STRING, result);
    ASSERT_TRUE(result == 0);

    EdmDataAbilityUtils::GetIntFromDataShare(EdmDataAbilityUtils::SETTINGS_DATA_BASE_URI, KEY_SCREEN_OFF_TIME, result);
    ASSERT_FALSE(result == 0);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS