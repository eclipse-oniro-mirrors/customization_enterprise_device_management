/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include <string>
#include <vector>

#define private public
#include "language_manager.h"
#undef private
#include "admin_manager.h"
#include "cJSON.h"
#include "edm_constants.h"
#include "edm_data_ability_utils.h"
#include "locale_config.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
constexpr int32_t DEFAULT_USERID = 100;

class LanguageManagerTest : public testing::TestWithParam<std::pair<std::pair<std::string, std::string>, std::string>> {
public:
    void SetUp() override { Utils::SetEdmInitialEnv(); }

    void TearDown() override
    {
        Utils::ResetTokenTypeAndUid();
        ASSERT_TRUE(Utils::IsOriginalUTEnv());
        std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
    }
};

/**
 * @tc.name: TestGetEnterpriseName_ReturnEmptyString
 * @tc.desc: Test PolicyManager GetEnterpriseName func.
 * @tc.type: FUNC
 */
HWTEST_F(LanguageManagerTest, TestGetEnterpriseName_ReturnEmptyString, TestSize.Level1)
{
    AdminManager::GetInstance()->ClearAdmins();
    std::string result = LanguageManager::GetEnterpriseName();
    EXPECT_EQ(result, "");
}

/**
 * @tc.name: TestGetEnterpriseName_ReturnEmptyString
 * @tc.desc: Test LanguageManager GetEnterpriseName func.
 * @tc.type: FUNC
 */
HWTEST_F(LanguageManagerTest, TestGetEnterpriseName_ReturnEnterpriseName, TestSize.Level1)
{
    AdminManager::GetInstance()->ClearAdmins();
    EntInfo entInfo("exampleName", "desc");
    AdminInfo adminInfo = {.packageName_ = "aaa",
        .className_ = "bbb",
        .entInfo_ = entInfo,
        .adminType_ = AdminType::ENT};
    AdminManager::GetInstance()->SetAdminValue(DEFAULT_USERID, adminInfo);
    std::string result = LanguageManager::GetEnterpriseName();
    AdminManager::GetInstance()->ClearAdmins();
    EXPECT_EQ(result, "exampleName");
}

INSTANTIATE_TEST_CASE_P(TestGetTargetLanguageValue, LanguageManagerTest,
    testing::ValuesIn(std::vector<std::pair<std::pair<std::string, std::string>, std::string>>({
        {{"", ""}, ""},
        {{"", "aaa"}, ""},
        {{"aaa", ""}, ""},
        {{"aaa", "bbb"}, ""},
        {{R"({"default":"aaa","zh":"bb"})", "unknown"}, ""},
        {{R"({"default":"aaa","zh":1})", "zh"}, ""},
        {{R"({"default":"aaa","zh":""})", "zh"}, ""},
        {{R"({"default":"aaa","zh":"lockInfo"})", "zh"}, "lockInfo"},
        {{R"({"unknown":"aaa","en":"lockInfo"})", "zh"}, ""},
        {{R"({"default":1,"en":"lockInfo"})", "zh"}, ""},
        {{R"({"default":"en","en":"lockInfo"})", "zh"}, "lockInfo"},
    })));

/**
 * @tc.name: TestGetTargetLanguageValue
 * @tc.desc: Test LanguageManager GetTargetLanguageValue func.
 * @tc.type: FUNC
 */
HWTEST_P(LanguageManagerTest, TestGetTargetLanguageValue, TestSize.Level1)
{
    std::pair<std::pair<std::string, std::string>, std::string> inputParam = GetParam();
    std::string result = LanguageManager::GetTargetLanguageValue(inputParam.first.first, inputParam.first.second);
    EXPECT_EQ(result, inputParam.second);
}

/**
 * @tc.name: TestGetValueFromLocal_ReturnDefault
 * @tc.desc: Test LanguageManager GetValueFromLocal func.
 * @tc.type: FUNC
 */
HWTEST_F(LanguageManagerTest, TestGetValueFromLocal_ReturnDefault, TestSize.Level1)
{
    std::string result;
    bool ret = LanguageManager::GetValueFromLocal(result);
    if (ret) {
        ASSERT_TRUE(!result.empty());
    } else {
        EXPECT_EQ(result, "");
    }
}

/**
 * @tc.name: TestGetValueFromLocal
 * @tc.desc: Test LanguageManager GetValueFromLocal func.
 * @tc.type: FUNC
 */
HWTEST_F(LanguageManagerTest, TestGetValueFromLocal_ReturnEnterpriseName, TestSize.Level1)
{
    AdminManager::GetInstance()->ClearAdmins();
    EntInfo entInfo("exampleName", "desc");
    AdminInfo adminInfo = {.packageName_ = "aaa",
        .className_ = "bbb",
        .entInfo_ = entInfo,
        .adminType_ = AdminType::ENT};
    AdminManager::GetInstance()->SetAdminValue(DEFAULT_USERID, adminInfo);
    std::string result;
    bool ret = LanguageManager::GetValueFromLocal(result);
    AdminManager::GetInstance()->ClearAdmins();
    if (ret) {
        ASSERT_TRUE(!result.empty());
        EXPECT_NE(result.find("exampleName"), string::npos);
    } else {
        EXPECT_EQ(result, "");
    }
}

/**
 * @tc.name: TestGetValueFromCloudSettings
 * @tc.desc: Test LanguageManager GetValueFromCloudSettings func.
 * @tc.type: FUNC
 */
HWTEST_F(LanguageManagerTest, TestGetValueFromCloudSettings_ReturnsValue, TestSize.Level1)
{
    std::string language = Global::I18n::LocaleConfig::GetSystemLanguage();
    cJSON* root = cJSON_CreateObject();
    ASSERT_TRUE(root != nullptr);
    cJSON_AddStringToObject(root, language.c_str(), "lockInfo");
    char* enterpriseInfo = cJSON_Print(root);
    EdmDataAbilityUtils::UpdateSettingsData(EdmConstants::ENTERPRISE_MANAGED_TIPS, enterpriseInfo);
    std::string result;
    bool ret = LanguageManager::GetValueFromCloudSettings(result);
    EdmDataAbilityUtils::UpdateSettingsData(EdmConstants::ENTERPRISE_MANAGED_TIPS, "");
    free(enterpriseInfo);
    cJSON_Delete(root);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(result, "lockInfo");
}

/**
 * @tc.name: TestGetValueFromCloudSettings
 * @tc.desc: Test LanguageManager GetValueFromCloudSettings func.
 * @tc.type: FUNC
 */
HWTEST_F(LanguageManagerTest, TestGetValueFromCloudSettings_ReturnsParseEmpty, TestSize.Level1)
{
    std::string language = Global::I18n::LocaleConfig::GetSystemLanguage();
    cJSON* root = cJSON_CreateObject();
    ASSERT_TRUE(root != nullptr);
    cJSON_AddStringToObject(root, language.c_str(), "");
    char* enterpriseInfo = cJSON_Print(root);
    EdmDataAbilityUtils::UpdateSettingsData(EdmConstants::ENTERPRISE_MANAGED_TIPS, enterpriseInfo);
    std::string result;
    bool ret = LanguageManager::GetValueFromCloudSettings(result);
    EdmDataAbilityUtils::UpdateSettingsData(EdmConstants::ENTERPRISE_MANAGED_TIPS, "");
    free(enterpriseInfo);
    cJSON_Delete(root);
    EXPECT_EQ(ret, false);
    EXPECT_EQ(result, "");
}

/**
 * @tc.name: TestGetValueFromCloudSettings
 * @tc.desc: Test LanguageManager GetValueFromCloudSettings func.
 * @tc.type: FUNC
 */
HWTEST_F(LanguageManagerTest, TestGetValueFromCloudSettings_ReturnsJsonEmpty, TestSize.Level1)
{
    EdmDataAbilityUtils::UpdateSettingsData(EdmConstants::ENTERPRISE_MANAGED_TIPS, "");
    std::string result;
    bool ret = LanguageManager::GetValueFromCloudSettings(result);
    EdmDataAbilityUtils::UpdateSettingsData(EdmConstants::ENTERPRISE_MANAGED_TIPS, "");
    EXPECT_EQ(ret, false);
    EXPECT_EQ(result, "");
}

/**
 * @tc.name: TestGetValueFromCloudSettings
 * @tc.desc: Test LanguageManager GetValueFromCloudSettings func.
 * @tc.type: FUNC
 */
HWTEST_F(LanguageManagerTest, TestGetEnterpriseManagedTips, TestSize.Level1)
{
    LanguageManager::GetEnterpriseManagedTips();
    std::string language = Global::I18n::LocaleConfig::GetSystemLanguage();
    cJSON* root = cJSON_CreateObject();
    ASSERT_TRUE(root != nullptr);
    cJSON_AddStringToObject(root, language.c_str(), "lockInfo");
    char* enterpriseInfo = cJSON_Print(root);
    EdmDataAbilityUtils::UpdateSettingsData(EdmConstants::ENTERPRISE_MANAGED_TIPS, enterpriseInfo);
    std::string result = LanguageManager::GetEnterpriseManagedTips();
    EdmDataAbilityUtils::UpdateSettingsData(EdmConstants::ENTERPRISE_MANAGED_TIPS, "");
    free(enterpriseInfo);
    cJSON_Delete(root);
#ifdef FEATURE_PC_ONLY
    EXPECT_EQ(result, "lockInfo");
#else
    EXPECT_TRUE(result.empty());
#endif
}

/**
 * @tc.name: TestIsNeedToShowEnterpriseManagedTips_ReturnsFalse
 * @tc.desc: Test LanguageManager IsNeedToShowEnterpriseManagedTips func.
 * @tc.type: FUNC
 */
HWTEST_F(LanguageManagerTest, TestIsNeedToShowEnterpriseManagedTips_ReturnsFalse, TestSize.Level1)
{
    std::string bundleName = "test";
    AdminInfo adminInfo = {.packageName_ = bundleName, .adminType_ = AdminType::NORMAL, .isDebug_ = false};
    AdminManager::GetInstance()->SetAdminValue(EdmConstants::DEFAULT_USER_ID, adminInfo);
    bool ret = LanguageManager::IsNeedToShowEnterpriseManagedTips();
#ifdef FEATURE_PC_ONLY
    EXPECT_EQ(ret, true);
#else
    EXPECT_EQ(ret, false);
#endif
    auto res = AdminManager::GetInstance()->DeleteAdmin(bundleName, EdmConstants::DEFAULT_USER_ID, AdminType::NORMAL);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.name: TestIsNeedToShowEnterpriseManagedTips_ReturnsTrue
 * @tc.desc: Test LanguageManager IsNeedToShowEnterpriseManagedTips func.
 * @tc.type: FUNC
 */
HWTEST_F(LanguageManagerTest, TestIsNeedToShowEnterpriseManagedTips_ReturnsTrue, TestSize.Level1)
{
    std::string bundleName = "test";
    AdminInfo adminInfo = {.packageName_ = bundleName, .adminType_ = AdminType::ENT, .isDebug_ = true};
    AdminManager::GetInstance()->SetAdminValue(EdmConstants::DEFAULT_USER_ID, adminInfo);
    bool ret = LanguageManager::IsNeedToShowEnterpriseManagedTips();
    EXPECT_EQ(ret, true);
    auto res = AdminManager::GetInstance()->DeleteAdmin(bundleName, EdmConstants::DEFAULT_USER_ID, AdminType::ENT);
    EXPECT_EQ(res, ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
