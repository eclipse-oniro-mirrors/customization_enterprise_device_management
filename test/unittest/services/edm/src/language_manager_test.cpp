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

#include <map>
#include <string>
#include <vector>

#include "parameters.h"

#define private public
#include "language_manager.h"
#include "permission_checker.h"
#undef private
#include "admin_manager.h"
#include "cJSON.h"
#include "edm_bundle_manager_impl_mock.h"
#include "edm_constants.h"
#include "edm_data_ability_utils.h"
#include "external_manager_factory_mock.h"
#include "ext_info_manager.h"
#include "locale_config.h"
#include "permission_checker_mock.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
constexpr int32_t DEFAULT_USERID = 100;

class LanguageManagerTest : public testing::TestWithParam<std::pair<std::pair<std::string, std::string>, std::string>> {
public:
    void SetUp() override
    {
        Utils::SetEdmInitialEnv();
        bundleMgrMock_ = std::make_shared<EdmBundleManagerImplMock>();
        factoryMock_ = std::make_shared<ExternalManagerFactoryMock>();
        permissionCheckerMock_ = std::make_shared<PermissionCheckerMock>();
        PermissionChecker::instance_ = permissionCheckerMock_;
        EXPECT_CALL(*permissionCheckerMock_, GetExternalManagerFactory).WillRepeatedly(DoAll(Return(factoryMock_)));
        EXPECT_CALL(*factoryMock_, CreateBundleManager).WillRepeatedly(DoAll(Return(bundleMgrMock_)));
    }

    void TearDown() override
    {
        Utils::ResetTokenTypeAndUid();
        ASSERT_TRUE(Utils::IsOriginalUTEnv());
        PermissionChecker::instance_.reset();
        std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
    }

protected:
    std::shared_ptr<EdmBundleManagerImplMock> bundleMgrMock_ = nullptr;
    std::shared_ptr<ExternalManagerFactoryMock> factoryMock_ = nullptr;
    std::shared_ptr<PermissionCheckerMock> permissionCheckerMock_ = nullptr;
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
    EXPECT_EQ(result, "lockInfo");
}

/**
 * @tc.name: IsNeedToShowEnterpriseManagedTips_DisabledOnSettingsWithSettingsCall_False
 * @tc.desc: Test LanguageManager IsNeedToShowEnterpriseManagedTips func with managed tips disabled on settings.
 * @tc.type: FUNC
 */
HWTEST_F(LanguageManagerTest, IsNeedToShowEnterpriseManagedTips_DisabledOnSettingsWithSettingsCall_False,
    TestSize.Level1)
{
    system::SetParameter(EdmConstants::MANAGED_TIPS_DISABLED_ON_SETTINGS, "true");
    auto settingsInfo = ExtInfoManager::GetInstance()->GetWantAgentInfo();
    if (!settingsInfo.bundleName.empty()) {
        EXPECT_CALL(*bundleMgrMock_, GetNameForUid).WillOnce(DoAll(SetArgReferee<1>(settingsInfo.bundleName),
            Return(ERR_OK)));
    }

    bool ret = LanguageManager::IsNeedToShowEnterpriseManagedTips();

    if (settingsInfo.bundleName.empty()) {
        EXPECT_EQ(ret, true);
    } else {
        EXPECT_EQ(ret, false);
    }

    system::SetParameter(EdmConstants::MANAGED_TIPS_DISABLED_ON_SETTINGS, "false");
}

/**
 * @tc.name: IsNeedToShowEnterpriseManagedTips_DisabledOnSettingsWithNotSettingsCall_True
 * @tc.desc: Test LanguageManager IsNeedToShowEnterpriseManagedTips func with managed tips disabled on settings.
 * @tc.type: FUNC
 */
HWTEST_F(LanguageManagerTest, IsNeedToShowEnterpriseManagedTips_DisabledOnSettingsWithNotSettingsCall_True,
    TestSize.Level1)
{
    system::SetParameter(EdmConstants::MANAGED_TIPS_DISABLED_ON_SETTINGS, "true");

    bool ret = LanguageManager::IsNeedToShowEnterpriseManagedTips();
    EXPECT_EQ(ret, true);

    system::SetParameter(EdmConstants::MANAGED_TIPS_DISABLED_ON_SETTINGS, "false");
}

/**
 * @tc.name: IsNeedToShowEnterpriseManagedTips_DisabledWithSettingsCall_True
 * @tc.desc: Test LanguageManager IsNeedToShowEnterpriseManagedTips func.
 * @tc.type: FUNC
 */
HWTEST_F(LanguageManagerTest, IsNeedToShowEnterpriseManagedTips_DisabledWithSettingsCall_True, TestSize.Level1)
{
    system::SetParameter(EdmConstants::MANAGED_TIPS_DISABLED, "true");
    auto settingsInfo = ExtInfoManager::GetInstance()->GetWantAgentInfo();

    if (!settingsInfo.bundleName.empty()) {
        EXPECT_CALL(*bundleMgrMock_, GetNameForUid).WillOnce(DoAll(SetArgReferee<1>(settingsInfo.bundleName),
            Return(ERR_OK)));
    }

    bool ret = LanguageManager::IsNeedToShowEnterpriseManagedTips();
    if (settingsInfo.bundleName.empty()) {
        EXPECT_EQ(ret, false);
    } else {
        EXPECT_EQ(ret, true);
    }

    system::SetParameter(EdmConstants::MANAGED_TIPS_DISABLED, "false");
}

/**
 * @tc.name: IsNeedToShowEnterpriseManagedTips_DisabledWithNotSettingsCall_False
 * @tc.desc: Test LanguageManager IsNeedToShowEnterpriseManagedTips func.
 * @tc.type: FUNC
 */
HWTEST_F(LanguageManagerTest, IsNeedToShowEnterpriseManagedTips_DisabledWithNotSettingsCall_False, TestSize.Level1)
{
    system::SetParameter(EdmConstants::MANAGED_TIPS_DISABLED, "true");

    bool ret = LanguageManager::IsNeedToShowEnterpriseManagedTips();
    EXPECT_EQ(ret, false);

    system::SetParameter(EdmConstants::MANAGED_TIPS_DISABLED, "false");
}

/**
 * @tc.name: TestIsNeedToShowEnterpriseManagedTips_HasDebugAdmin_True
 * @tc.desc: Test LanguageManager IsNeedToShowEnterpriseManagedTips func.
 * @tc.type: FUNC
 */
HWTEST_F(LanguageManagerTest, TestIsNeedToShowEnterpriseManagedTips_HasDebugAdmin_True, TestSize.Level1)
{
    std::string bundleName = "test";
    AdminInfo adminInfo = {.packageName_ = bundleName, .adminType_ = AdminType::BYOD, .isDebug_ = true};
    AdminManager::GetInstance()->SetAdminValue(EdmConstants::DEFAULT_USER_ID, adminInfo);
    bool ret = LanguageManager::IsNeedToShowEnterpriseManagedTips();
    EXPECT_EQ(ret, true);
    auto res = AdminManager::GetInstance()->DeleteAdmin(bundleName, EdmConstants::DEFAULT_USER_ID, AdminType::BYOD);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.name: TestIsNeedToShowEnterpriseManagedTips_HasByodAdmin_False
 * @tc.desc: Test LanguageManager IsNeedToShowEnterpriseManagedTips func.
 * @tc.type: FUNC
 */
HWTEST_F(LanguageManagerTest, TestIsNeedToShowEnterpriseManagedTips_HasByodAdmin_False, TestSize.Level1)
{
    std::string bundleName = "test";
    AdminInfo adminInfo = {.packageName_ = bundleName, .adminType_ = AdminType::BYOD, .isDebug_ = false};
    AdminManager::GetInstance()->SetAdminValue(EdmConstants::DEFAULT_USER_ID, adminInfo);
    bool ret = LanguageManager::IsNeedToShowEnterpriseManagedTips();
    EXPECT_EQ(ret, false);
    auto res = AdminManager::GetInstance()->DeleteAdmin(bundleName, EdmConstants::DEFAULT_USER_ID, AdminType::BYOD);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.name: IsSettingsCalling_NotSettingsCalling_False
 * @tc.desc: Test LanguageManager IsSettingsCalling when not settings calling.
 * @tc.type: FUNC
 */
HWTEST_F(LanguageManagerTest, IsSettingsCalling_NotSettingsCalling_False, TestSize.Level1)
{
    bool ret = LanguageManager::IsSettingsCalling();
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: IsSettingsCalling_SettingsCalling_True
 * @tc.desc: Test LanguageManager IsSettingsCalling when settings calling.
 * @tc.type: FUNC
 */
HWTEST_F(LanguageManagerTest, IsSettingsCalling_SettingsCalling_True, TestSize.Level1)
{
    auto settingsInfo = ExtInfoManager::GetInstance()->GetWantAgentInfo();

    if (!settingsInfo.bundleName.empty()) {
        EXPECT_CALL(*bundleMgrMock_, GetNameForUid).WillOnce(DoAll(SetArgReferee<1>(settingsInfo.bundleName),
            Return(ERR_OK)));
    }

    bool ret = LanguageManager::IsSettingsCalling();

    if (settingsInfo.bundleName.empty()) {
        EXPECT_EQ(ret, false);
    } else {
        EXPECT_EQ(ret, true);
    }
}

/**
 * @tc.name: GetValueFromCloudSettings_SettingsEnterpriseManagedTips_Success
 * @tc.desc: Test LanguageManager GetValueFromCloudSettings uses correct config key for Settings.
 * @tc.type: FUNC
 */
HWTEST_F(LanguageManagerTest, GetValueFromCloudSettings_SettingsEnterpriseManagedTips_Success, TestSize.Level1)
{
    auto settingsInfo = ExtInfoManager::GetInstance()->GetWantAgentInfo();

    if (!settingsInfo.bundleName.empty()) {
        EXPECT_CALL(*bundleMgrMock_, GetNameForUid).WillOnce(DoAll(SetArgReferee<1>(settingsInfo.bundleName),
            Return(ERR_OK)));
    }

    std::string language = Global::I18n::LocaleConfig::GetSystemLanguage();
    cJSON* root = cJSON_CreateObject();
    ASSERT_TRUE(root != nullptr);
    cJSON_AddStringToObject(root, language.c_str(), "settingsManagedTips");
    char* enterpriseInfo = cJSON_Print(root);
    EdmDataAbilityUtils::UpdateSettingsData(EdmConstants::ENTERPRISE_MANAGED_TIPS_ON_SETTINGS, enterpriseInfo);

    std::string result;
    bool ret = LanguageManager::GetValueFromCloudSettings(result);

    EdmDataAbilityUtils::UpdateSettingsData(EdmConstants::ENTERPRISE_MANAGED_TIPS_ON_SETTINGS, "");
    free(enterpriseInfo);
    cJSON_Delete(root);

    if (settingsInfo.bundleName.empty()) {
        EXPECT_EQ(ret, false);
    } else {
        EXPECT_EQ(ret, true);
        EXPECT_EQ(result, "settingsManagedTips");
    }
}

/**
 * @tc.name: TestFindEnterpriseName_SubtagStripping
 * @tc.desc: Test LanguageManager FindEnterpriseName matches language tags with subtags.
 * @tc.type: FUNC
 */
HWTEST_F(LanguageManagerTest, TestFindEnterpriseName_SubtagStripping, TestSize.Level1)
{
    std::map<std::string, std::string> enterpriseNames = {
        {"zh-Hans", "simpleChinese"},
        {"zh-Hant", "traditionalChinese"},
        {"en", "englishName"},
        {"bo", "tibetanName"},
        {"ug", "uyghurName"},
    };
    EXPECT_EQ(LanguageManager::FindEnterpriseName(enterpriseNames, "en-Latn-US"), "englishName");
    EXPECT_EQ(LanguageManager::FindEnterpriseName(enterpriseNames, "en"), "englishName");
    EXPECT_EQ(LanguageManager::FindEnterpriseName(enterpriseNames, "zh-Hans-CN"), "simpleChinese");
    EXPECT_EQ(LanguageManager::FindEnterpriseName(enterpriseNames, "zh-Hant-TW"), "traditionalChinese");
    EXPECT_EQ(LanguageManager::FindEnterpriseName(enterpriseNames, "bo"), "tibetanName");
    EXPECT_EQ(LanguageManager::FindEnterpriseName(enterpriseNames, "ug"), "uyghurName");
    EXPECT_EQ(LanguageManager::FindEnterpriseName(enterpriseNames, "ja"), "");
    EXPECT_EQ(LanguageManager::FindEnterpriseName(enterpriseNames, "zh"), "");
    EXPECT_EQ(LanguageManager::FindEnterpriseName(enterpriseNames, ""), "");
    std::map<std::string, std::string> emptyNames;
    EXPECT_EQ(LanguageManager::FindEnterpriseName(emptyNames, "en-Latn-US"), "");
}

/**
 * @tc.name: GetValueFromMdmSettings_NotSet_False
 * @tc.desc: Test LanguageManager GetValueFromMdmSettings when display info is not set.
 * @tc.type: FUNC
 */
HWTEST_F(LanguageManagerTest, GetValueFromMdmSettings_NotSet_False, TestSize.Level1)
{
    EdmDataAbilityUtils::UpdateSettingsData(EdmConstants::ENTERPRISE_DISPLAY_INFO, "");
    std::string result;
    bool ret = LanguageManager::GetValueFromMdmSettings(result);
    EXPECT_FALSE(ret);
    EXPECT_EQ(result, "");
}

/**
 * @tc.name: GetValueFromMdmSettings_InvalidJson_False
 * @tc.desc: Test LanguageManager GetValueFromMdmSettings when display info is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(LanguageManagerTest, GetValueFromMdmSettings_InvalidJson_False, TestSize.Level1)
{
    EdmDataAbilityUtils::UpdateSettingsData(EdmConstants::ENTERPRISE_DISPLAY_INFO, "invalid json");
    std::string result;
    bool ret = LanguageManager::GetValueFromMdmSettings(result);
    EdmDataAbilityUtils::UpdateSettingsData(EdmConstants::ENTERPRISE_DISPLAY_INFO, "");
    EXPECT_FALSE(ret);
    EXPECT_EQ(result, "");
}

/**
 * @tc.name: GetValueFromMdmSettings_ValidJson
 * @tc.desc: Test LanguageManager GetValueFromMdmSettings with valid display info.
 * @tc.type: FUNC
 */
HWTEST_F(LanguageManagerTest, GetValueFromMdmSettings_ValidJson, TestSize.Level1)
{
    std::string displayInfo = R"({"default":"zh-Hans","zh-Hans":"mdmEnterprise","en":"mdmEnterprise"})";
    EdmDataAbilityUtils::UpdateSettingsData(EdmConstants::ENTERPRISE_DISPLAY_INFO, displayInfo);
    std::string result;
    bool ret = LanguageManager::GetValueFromMdmSettings(result);
    EdmDataAbilityUtils::UpdateSettingsData(EdmConstants::ENTERPRISE_DISPLAY_INFO, "");
    if (ret) {
        EXPECT_FALSE(result.empty());
        EXPECT_NE(result.find("mdmEnterprise"), std::string::npos);
    } else {
        EXPECT_EQ(result, "");
    }
}

/**
 * @tc.name: IsNeedToShowEnterpriseManagedTips_MdmDisplayInfo_BypassDisabled
 * @tc.desc: Test LanguageManager IsNeedToShowEnterpriseManagedTips with mdm display info bypass the disabled param.
 * @tc.type: FUNC
 */
HWTEST_F(LanguageManagerTest, IsNeedToShowEnterpriseManagedTips_MdmDisplayInfo_BypassDisabled, TestSize.Level1)
{
    system::SetParameter(EdmConstants::MANAGED_TIPS_DISABLED, "true");
    bool ret = LanguageManager::IsNeedToShowEnterpriseManagedTips(true);
    system::SetParameter(EdmConstants::MANAGED_TIPS_DISABLED, "false");
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: GetEnterpriseManagedTips_MdmInvalid_FallbackCloud
 * @tc.desc: Test LanguageManager GetEnterpriseManagedTips falls back to cloud tips when mdm info invalid.
 * @tc.type: FUNC
 */
HWTEST_F(LanguageManagerTest, GetEnterpriseManagedTips_MdmInvalid_FallbackCloud, TestSize.Level1)
{
    EdmDataAbilityUtils::UpdateSettingsData(EdmConstants::ENTERPRISE_DISPLAY_INFO, "invalid json");
    std::string language = Global::I18n::LocaleConfig::GetSystemLanguage();
    cJSON* root = cJSON_CreateObject();
    ASSERT_TRUE(root != nullptr);
    ASSERT_TRUE(cJSON_AddStringToObject(root, language.c_str(), "cloudTips") != nullptr);
    char* enterpriseInfo = cJSON_Print(root);
    ASSERT_TRUE(enterpriseInfo != nullptr);
    EdmDataAbilityUtils::UpdateSettingsData(EdmConstants::ENTERPRISE_MANAGED_TIPS, enterpriseInfo);
    std::string result = LanguageManager::GetEnterpriseManagedTips();
    EdmDataAbilityUtils::UpdateSettingsData(EdmConstants::ENTERPRISE_MANAGED_TIPS, "");
    EdmDataAbilityUtils::UpdateSettingsData(EdmConstants::ENTERPRISE_DISPLAY_INFO, "");
    free(enterpriseInfo);
    cJSON_Delete(root);
    EXPECT_EQ(result, "cloudTips");
}

/**
 * @tc.name: TestValidateEnterpriseDisplayInfo_SUC
 * @tc.desc: Test LanguageManager ValidateEnterpriseDisplayInfo with valid display info.
 * @tc.type: FUNC
 */
HWTEST_F(LanguageManagerTest, TestValidateEnterpriseDisplayInfo_SUC, TestSize.Level1)
{
    std::string displayInfo = R"({"default":"zh-Hans","zh-Hans":"示例企业","zh-Hant":"範例企業",)"
        R"("en":"ExampleCorp","bo":"ExampleBo","ug":"ExampleUg"})";
    EXPECT_EQ(LanguageManager::ValidateEnterpriseDisplayInfo(displayInfo), ERR_OK);
    EXPECT_EQ(LanguageManager::ValidateEnterpriseDisplayInfo(R"({"default":"en","en":"ExampleCorp"})"), ERR_OK);
}

/**
 * @tc.name: TestValidateEnterpriseDisplayInfo_UnknownLanguage
 * @tc.desc: Test LanguageManager ValidateEnterpriseDisplayInfo with language tag out of the preset list.
 * @tc.type: FUNC
 */
HWTEST_F(LanguageManagerTest, TestValidateEnterpriseDisplayInfo_UnknownLanguage, TestSize.Level1)
{
    EXPECT_EQ(LanguageManager::ValidateEnterpriseDisplayInfo(R"({"default":"ja","ja":"ExampleCorp"})"), ERR_OK);
    EXPECT_EQ(LanguageManager::ValidateEnterpriseDisplayInfo(
        R"({"default":"en","en":"ExampleCorp","ja":"企業"})"), ERR_OK);
}

/**
 * @tc.name: TestValidateEnterpriseDisplayInfo_NameLength
 * @tc.desc: Test LanguageManager ValidateEnterpriseDisplayInfo checks the enterprise name length.
 * @tc.type: FUNC
 */
HWTEST_F(LanguageManagerTest, TestValidateEnterpriseDisplayInfo_NameLength, TestSize.Level1)
{
    std::string maxName(EdmConstants::MAX_ENTERPRISE_NAME_LENGTH, 'a');
    EXPECT_EQ(LanguageManager::ValidateEnterpriseDisplayInfo(R"({"default":"en","en":")" + maxName + R"("})"), ERR_OK);
    // 30 Chinese characters are 90 bytes but only 30 code points.
    std::string chineseName;
    for (uint32_t i = 0; i < EdmConstants::MAX_ENTERPRISE_NAME_LENGTH; ++i) {
        chineseName.append("企");
    }
    EXPECT_EQ(LanguageManager::ValidateEnterpriseDisplayInfo(R"({"default":"zh-Hans","zh-Hans":")" + chineseName +
        R"("})"), ERR_OK);
    std::string longName(EdmConstants::MAX_ENTERPRISE_NAME_LENGTH + 1, 'a');
    EXPECT_EQ(LanguageManager::ValidateEnterpriseDisplayInfo(R"({"default":"en","en":")" + longName + R"("})"),
        EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    EXPECT_EQ(LanguageManager::ValidateEnterpriseDisplayInfo(R"({"default":"en","en":""})"),
        EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    // The content of the name is not verified, only the length is checked.
    EXPECT_EQ(LanguageManager::ValidateEnterpriseDisplayInfo(R"({"default":"en","en":"   "})"), ERR_OK);
}

/**
 * @tc.name: TestValidateEnterpriseDisplayInfo_LanguageCount
 * @tc.desc: Test LanguageManager ValidateEnterpriseDisplayInfo checks the language count.
 * @tc.type: FUNC
 */
HWTEST_F(LanguageManagerTest, TestValidateEnterpriseDisplayInfo_LanguageCount, TestSize.Level1)
{
    // Only the default language is configured.
    EXPECT_EQ(LanguageManager::ValidateEnterpriseDisplayInfo(R"({"default":"en"})"),
        EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    EXPECT_EQ(LanguageManager::ValidateEnterpriseDisplayInfo(R"({"default":"en","en":"Corp"})"), ERR_OK);
    EXPECT_EQ(LanguageManager::ValidateEnterpriseDisplayInfo(
        R"({"default":"en","en":"Corp","ja":"Corp","ko":"Corp","fr":"Corp","de":"Corp"})"), ERR_OK);
    EXPECT_EQ(LanguageManager::ValidateEnterpriseDisplayInfo(
        R"({"default":"en","en":"Corp","ja":"Corp","ko":"Corp","fr":"Corp","de":"Corp","it":"Corp"})"),
        EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestValidateEnterpriseDisplayInfo_Empty
 * @tc.desc: Test LanguageManager ValidateEnterpriseDisplayInfo with empty input.
 * @tc.type: FUNC
 */
HWTEST_F(LanguageManagerTest, TestValidateEnterpriseDisplayInfo_Empty, TestSize.Level1)
{
    EXPECT_EQ(LanguageManager::ValidateEnterpriseDisplayInfo(""),
        EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestValidateEnterpriseDisplayInfo_DefaultMissing
 * @tc.desc: Test LanguageManager ValidateEnterpriseDisplayInfo without the mandatory default field.
 * @tc.type: FUNC
 */
HWTEST_F(LanguageManagerTest, TestValidateEnterpriseDisplayInfo_DefaultMissing, TestSize.Level1)
{
    EXPECT_EQ(LanguageManager::ValidateEnterpriseDisplayInfo(R"({"zh-Hans":"示例企业"})"),
        EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    EXPECT_EQ(LanguageManager::ValidateEnterpriseDisplayInfo("{}"),
        EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    EXPECT_EQ(LanguageManager::ValidateEnterpriseDisplayInfo(R"({"default":""})"),
        EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    EXPECT_EQ(LanguageManager::ValidateEnterpriseDisplayInfo(R"({"default":1,"en":"ExampleCorp"})"),
        EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    // The default language is not required to point to a configured language.
    EXPECT_EQ(LanguageManager::ValidateEnterpriseDisplayInfo(R"({"default":"en","zh-Hans":"示例企业"})"), ERR_OK);
}

/**
 * @tc.name: TestValidateEnterpriseDisplayInfo_FormatError
 * @tc.desc: Test LanguageManager ValidateEnterpriseDisplayInfo with invalid json format.
 * @tc.type: FUNC
 */
HWTEST_F(LanguageManagerTest, TestValidateEnterpriseDisplayInfo_FormatError, TestSize.Level1)
{
    EXPECT_EQ(LanguageManager::ValidateEnterpriseDisplayInfo("invalid json"),
        EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    EXPECT_EQ(LanguageManager::ValidateEnterpriseDisplayInfo(R"(["zh-Hans"])"),
        EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    EXPECT_EQ(LanguageManager::ValidateEnterpriseDisplayInfo(R"({"default":"en","en":{"name":"ExampleCorp"}})"),
        EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    std::string tooLongInfo(EdmConstants::MAX_ENTERPRISE_DISPLAY_INFO_LENGTH + 1, 'a');
    EXPECT_EQ(LanguageManager::ValidateEnterpriseDisplayInfo(tooLongInfo),
        EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestParseEnterpriseDisplayInfo_SUC
 * @tc.desc: Test LanguageManager ParseEnterpriseDisplayInfo with valid display info.
 * @tc.type: FUNC
 */
HWTEST_F(LanguageManagerTest, TestParseEnterpriseDisplayInfo_SUC, TestSize.Level1)
{
    std::map<std::string, std::string> enterpriseNames;
    std::string defaultLanguage;
    ErrCode ret = LanguageManager::ParseEnterpriseDisplayInfo(
        R"({"default":"zh-Hans","zh-Hans":"示例企业","en":"ExampleCorp"})", enterpriseNames, defaultLanguage);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(defaultLanguage, "zh-Hans");
    EXPECT_EQ(enterpriseNames.size(), 2);
    EXPECT_EQ(enterpriseNames["zh-Hans"], "示例企业");
}

/**
 * @tc.name: TestParseEnterpriseDisplayInfo_Fail
 * @tc.desc: Test LanguageManager ParseEnterpriseDisplayInfo with invalid input.
 * @tc.type: FUNC
 */
HWTEST_F(LanguageManagerTest, TestParseEnterpriseDisplayInfo_Fail, TestSize.Level1)
{
    std::map<std::string, std::string> enterpriseNames;
    std::string defaultLanguage;
    EXPECT_EQ(LanguageManager::ParseEnterpriseDisplayInfo("", enterpriseNames, defaultLanguage),
        EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    EXPECT_EQ(LanguageManager::ParseEnterpriseDisplayInfo("invalid", enterpriseNames, defaultLanguage),
        EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    EXPECT_EQ(LanguageManager::ParseEnterpriseDisplayInfo(R"(["zh-Hans"])", enterpriseNames, defaultLanguage),
        EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    // json length exceeds the upper limit.
    std::string tooLongInfo(EdmConstants::MAX_ENTERPRISE_DISPLAY_INFO_LENGTH + 1, 'a');
    EXPECT_EQ(LanguageManager::ParseEnterpriseDisplayInfo(tooLongInfo, enterpriseNames, defaultLanguage),
        EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestParseEnterpriseDisplayInfo_SkipNonStringField
 * @tc.desc: Test LanguageManager ParseEnterpriseDisplayInfo skips non-string fields and keeps string ones.
 * @tc.type: FUNC
 */
HWTEST_F(LanguageManagerTest, TestParseEnterpriseDisplayInfo_SkipNonStringField, TestSize.Level1)
{
    std::map<std::string, std::string> enterpriseNames;
    std::string defaultLanguage;
    ErrCode ret = LanguageManager::ParseEnterpriseDisplayInfo(
        R"({"default":"en","en":"ExampleCorp","num":1,"obj":{"a":"b"}})", enterpriseNames, defaultLanguage);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(defaultLanguage, "en");
    // Only the "en" string field is kept, "num" and "obj" are skipped.
    EXPECT_EQ(enterpriseNames.size(), 1);
    EXPECT_EQ(enterpriseNames["en"], "ExampleCorp");
}

/**
 * @tc.name: TestCountUtf8CodePoints
 * @tc.desc: Test LanguageManager CountUtf8CodePoints counts code points instead of bytes.
 * @tc.type: FUNC
 */
HWTEST_F(LanguageManagerTest, TestCountUtf8CodePoints, TestSize.Level1)
{
    EXPECT_EQ(LanguageManager::CountUtf8CodePoints(""), 0);
    EXPECT_EQ(LanguageManager::CountUtf8CodePoints("abc"), 3);
    // Three Chinese characters occupy 9 bytes but only 3 code points.
    EXPECT_EQ(LanguageManager::CountUtf8CodePoints("示例企"), 3);
    EXPECT_EQ(LanguageManager::CountUtf8CodePoints("a示b例"), 4);
}

/**
 * @tc.name: TestIsValidEnterpriseName_Boundary
 * @tc.desc: Test LanguageManager IsValidEnterpriseName boundary of the name length.
 * @tc.type: FUNC
 */
HWTEST_F(LanguageManagerTest, TestIsValidEnterpriseName_Boundary, TestSize.Level1)
{
    EXPECT_FALSE(LanguageManager::IsValidEnterpriseName(""));
    EXPECT_TRUE(LanguageManager::IsValidEnterpriseName("a"));
    std::string maxName(EdmConstants::MAX_ENTERPRISE_NAME_LENGTH, 'a');
    EXPECT_TRUE(LanguageManager::IsValidEnterpriseName(maxName));
    std::string longName(EdmConstants::MAX_ENTERPRISE_NAME_LENGTH + 1, 'a');
    EXPECT_FALSE(LanguageManager::IsValidEnterpriseName(longName));
}

/**
 * @tc.name: GetValueFromMdmSettings_NoMatchedName_False
 * @tc.desc: Test LanguageManager GetValueFromMdmSettings when neither system language nor default language matches.
 * @tc.type: FUNC
 */
HWTEST_F(LanguageManagerTest, GetValueFromMdmSettings_NoMatchedName_False, TestSize.Level1)
{
    // "xx" and "zz" never equal the real system language, and the default "zz" is not configured either.
    std::string displayInfo = R"({"default":"zz","xx":"unmatchedName"})";
    EdmDataAbilityUtils::UpdateSettingsData(EdmConstants::ENTERPRISE_DISPLAY_INFO, displayInfo);
    std::string result;
    bool ret = LanguageManager::GetValueFromMdmSettings(result);
    EdmDataAbilityUtils::UpdateSettingsData(EdmConstants::ENTERPRISE_DISPLAY_INFO, "");
    EXPECT_FALSE(ret);
    EXPECT_EQ(result, "");
}

/**
 * @tc.name: GetEnterpriseManagedTips_MdmValid_ReturnMdmTips
 * @tc.desc: Test LanguageManager GetEnterpriseManagedTips returns the mdm tips when mdm display info is valid.
 * @tc.type: FUNC
 */
HWTEST_F(LanguageManagerTest, GetEnterpriseManagedTips_MdmValid_ReturnMdmTips, TestSize.Level1)
{
    std::string language = Global::I18n::LocaleConfig::GetSystemLanguage();
    std::string displayInfo = R"({"default":")" + language + R"(",")" + language + R"(":"mdmTipsEnterprise"})";
    EdmDataAbilityUtils::UpdateSettingsData(EdmConstants::ENTERPRISE_DISPLAY_INFO, displayInfo);
    std::string mdmResult;
    bool hasMdmDisplayInfo = LanguageManager::GetValueFromMdmSettings(mdmResult);
    std::string result = LanguageManager::GetEnterpriseManagedTips();
    EdmDataAbilityUtils::UpdateSettingsData(EdmConstants::ENTERPRISE_DISPLAY_INFO, "");
    if (hasMdmDisplayInfo) {
        // The mdm display info takes precedence, so the returned tips must equal the mdm result.
        EXPECT_FALSE(mdmResult.empty());
        EXPECT_EQ(result, mdmResult);
    } else {
        // The system template is unavailable in this environment, so the mdm branch is skipped.
        EXPECT_TRUE(mdmResult.empty());
    }
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
