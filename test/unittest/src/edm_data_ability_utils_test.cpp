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
const std::string SETTINGS_DATA_BASE_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true";
const std::string INVALID_BASE_URI =
    "datashare:///com.ohos.invalid/entry/settingsdata/SETTINGSDATA?Proxy=true";
const std::string ERROR_URI = "datashare:///com.ohos.settingsdata";
const std::string PREDICATES_STRING = "settings.general.device_name";
const std::string INVAILD_STRING = "settings.general.invalid_string";

class EdmDataAbilityUtilsTest : public testing::Test {
protected:
    void SetUp() override;

    void TearDown() override;
};

void EdmDataAbilityUtilsTest::SetUp()
{
    Utils::SetEdmInitialEnv();
}

void EdmDataAbilityUtilsTest::TearDown()
{
    Utils::ResetTokenTypeAndUid();
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

    EdmDataAbilityUtils::GetStringFromDataShare(SETTINGS_DATA_BASE_URI, INVAILD_STRING, result);
    ASSERT_TRUE(result.empty());

    EdmDataAbilityUtils::GetStringFromDataShare(SETTINGS_DATA_BASE_URI, PREDICATES_STRING, result);
    ASSERT_FALSE(result.empty());
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS