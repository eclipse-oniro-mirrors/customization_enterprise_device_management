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

#define private public
#define protected public
#include "policy_query_config.h"
#undef protected
#undef private

#include "edm_constants.h"
#include "iplugin.h"
#include "utils.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::EDM;

namespace OHOS {
namespace EDM {
namespace TEST {

class PolicyQueryConfigTest : public testing::Test {
protected:
    void SetUp() override {}

    void TearDown() override {}

    static void SetUpTestSuite(void)
    {
        Utils::SetEdmInitialEnv();
    }

    static void TearDownTestSuite(void)
    {
        Utils::ResetTokenTypeAndUid();
        ASSERT_TRUE(Utils::IsOriginalUTEnv());
        std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
    }
};

HWTEST_F(PolicyQueryConfigTest, TestRestrictionPermission_True_SuperAdmin, TestSize.Level1)
{
    PermissionConfig config = PermissionConfig::RestrictionPermission(true);
    std::string permission = config.GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "");
    ASSERT_EQ(permission, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
}

HWTEST_F(PolicyQueryConfigTest, TestRestrictionPermission_True_ByodAdmin, TestSize.Level1)
{
    PermissionConfig config = PermissionConfig::RestrictionPermission(true);
    std::string permission = config.GetPermission(IPlugin::PermissionType::BYOD_DEVICE_ADMIN, "");
    ASSERT_EQ(permission, EdmPermission::PERMISSION_PERSONAL_MANAGE_RESTRICTIONS);
}

HWTEST_F(PolicyQueryConfigTest, TestRestrictionPermission_True_NormalAdmin, TestSize.Level1)
{
    PermissionConfig config = PermissionConfig::RestrictionPermission(true);
    std::string permission = config.GetPermission(IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, "");
    ASSERT_EQ(permission, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
}

HWTEST_F(PolicyQueryConfigTest, TestRestrictionPermission_False_SuperAdmin, TestSize.Level1)
{
    PermissionConfig config = PermissionConfig::RestrictionPermission(false);
    std::string permission = config.GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "");
    ASSERT_EQ(permission, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
}

HWTEST_F(PolicyQueryConfigTest, TestRestrictionPermission_False_ByodAdmin, TestSize.Level1)
{
    PermissionConfig config = PermissionConfig::RestrictionPermission(false);
    std::string permission = config.GetPermission(IPlugin::PermissionType::BYOD_DEVICE_ADMIN, "");
    ASSERT_EQ(permission, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
}

HWTEST_F(PolicyQueryConfigTest, TestRestrictionPermission_False_ByodSameAsSuper, TestSize.Level1)
{
    PermissionConfig config = PermissionConfig::RestrictionPermission(false);
    std::string superPerm = config.GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "");
    std::string byodPerm = config.GetPermission(IPlugin::PermissionType::BYOD_DEVICE_ADMIN, "");
    ASSERT_EQ(superPerm, byodPerm);
}

HWTEST_F(PolicyQueryConfigTest, TestRestrictionPermission_True_ByodDifferentFromSuper, TestSize.Level1)
{
    PermissionConfig config = PermissionConfig::RestrictionPermission(true);
    std::string superPerm = config.GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "");
    std::string byodPerm = config.GetPermission(IPlugin::PermissionType::BYOD_DEVICE_ADMIN, "");
    ASSERT_NE(superPerm, byodPerm);
}

HWTEST_F(PolicyQueryConfigTest, TestRestrictionPermission_True_FieldValues, TestSize.Level1)
{
    PermissionConfig config = PermissionConfig::RestrictionPermission(true);
    ASSERT_EQ(config.pattern, PermissionPattern::RESTRICTION);
    ASSERT_EQ(config.hasByod, true);
    ASSERT_EQ(config.specificPermission, nullptr);
    ASSERT_EQ(config.tagPermission, nullptr);
    ASSERT_EQ(config.byodPermission, nullptr);
}

HWTEST_F(PolicyQueryConfigTest, TestRestrictionPermission_False_FieldValues, TestSize.Level1)
{
    PermissionConfig config = PermissionConfig::RestrictionPermission(false);
    ASSERT_EQ(config.pattern, PermissionPattern::RESTRICTION);
    ASSERT_EQ(config.hasByod, false);
}

HWTEST_F(PolicyQueryConfigTest, TestRestrictionPermissionDefault_SuperAdmin, TestSize.Level1)
{
    PermissionConfig config = PermissionConfig::RestrictionPermission();
    std::string permission = config.GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "");
    ASSERT_EQ(permission, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
}

HWTEST_F(PolicyQueryConfigTest, TestRestrictionPermissionDefault_ByodAdmin, TestSize.Level1)
{
    PermissionConfig config = PermissionConfig::RestrictionPermission();
    std::string permission = config.GetPermission(IPlugin::PermissionType::BYOD_DEVICE_ADMIN, "");
    ASSERT_EQ(permission, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
}

HWTEST_F(PolicyQueryConfigTest, TestRestrictionPermissionDefault_NormalAdmin, TestSize.Level1)
{
    PermissionConfig config = PermissionConfig::RestrictionPermission();
    std::string permission = config.GetPermission(IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, "");
    ASSERT_EQ(permission, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
}

HWTEST_F(PolicyQueryConfigTest, TestRestrictionPermissionDefault_AllTypesSame, TestSize.Level1)
{
    PermissionConfig config = PermissionConfig::RestrictionPermission();
    std::string superPerm = config.GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "");
    std::string byodPerm = config.GetPermission(IPlugin::PermissionType::BYOD_DEVICE_ADMIN, "");
    std::string normalPerm = config.GetPermission(IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, "");
    ASSERT_EQ(superPerm, byodPerm);
    ASSERT_EQ(superPerm, normalPerm);
}

HWTEST_F(PolicyQueryConfigTest, TestRestrictionPermissionDefault_FieldValues, TestSize.Level1)
{
    PermissionConfig config = PermissionConfig::RestrictionPermission();
    ASSERT_EQ(config.pattern, PermissionPattern::RESTRICTION);
    ASSERT_EQ(config.hasByod, false);
    ASSERT_EQ(config.specificPermission, nullptr);
}

HWTEST_F(PolicyQueryConfigTest, TestSpecificPermission_SuperAdmin, TestSize.Level1)
{
    PermissionConfig config = PermissionConfig::SpecificPermission("ohos.permission.TEST_PERMISSION");
    std::string permission = config.GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "");
    ASSERT_EQ(permission, "ohos.permission.TEST_PERMISSION");
}

HWTEST_F(PolicyQueryConfigTest, TestSpecificPermission_ByodAdmin, TestSize.Level1)
{
    PermissionConfig config = PermissionConfig::SpecificPermission("ohos.permission.TEST_PERMISSION");
    std::string permission = config.GetPermission(IPlugin::PermissionType::BYOD_DEVICE_ADMIN, "");
    ASSERT_EQ(permission, "ohos.permission.TEST_PERMISSION");
}

HWTEST_F(PolicyQueryConfigTest, TestSpecificPermission_NormalAdmin, TestSize.Level1)
{
    PermissionConfig config = PermissionConfig::SpecificPermission("ohos.permission.TEST_PERMISSION");
    std::string permission = config.GetPermission(IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, "");
    ASSERT_EQ(permission, "ohos.permission.TEST_PERMISSION");
}

HWTEST_F(PolicyQueryConfigTest, TestSpecificPermission_AllTypesSame, TestSize.Level1)
{
    PermissionConfig config = PermissionConfig::SpecificPermission("ohos.permission.TEST_PERMISSION");
    std::string superPerm = config.GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "");
    std::string byodPerm = config.GetPermission(IPlugin::PermissionType::BYOD_DEVICE_ADMIN, "");
    std::string normalPerm = config.GetPermission(IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, "");
    ASSERT_EQ(superPerm, "ohos.permission.TEST_PERMISSION");
    ASSERT_EQ(byodPerm, "ohos.permission.TEST_PERMISSION");
    ASSERT_EQ(normalPerm, "ohos.permission.TEST_PERMISSION");
}

HWTEST_F(PolicyQueryConfigTest, TestSpecificPermission_IgnoresTag, TestSize.Level1)
{
    PermissionConfig config = PermissionConfig::SpecificPermission("ohos.permission.TEST_PERMISSION");
    std::string permWithTag = config.GetPermission(
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "version_11");
    ASSERT_EQ(permWithTag, "ohos.permission.TEST_PERMISSION");
}

HWTEST_F(PolicyQueryConfigTest, TestSpecificPermission_EmptyPermission, TestSize.Level1)
{
    PermissionConfig config = PermissionConfig::SpecificPermission("");
    std::string permission = config.GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "");
    ASSERT_EQ(permission, "");
    permission = config.GetPermission(IPlugin::PermissionType::BYOD_DEVICE_ADMIN, "");
    ASSERT_EQ(permission, "");
}

HWTEST_F(PolicyQueryConfigTest, TestSpecificPermission_FieldValues, TestSize.Level1)
{
    PermissionConfig config = PermissionConfig::SpecificPermission("ohos.permission.TEST_PERMISSION");
    ASSERT_EQ(config.pattern, PermissionPattern::SPECIFIC);
    ASSERT_NE(config.specificPermission, nullptr);
    ASSERT_EQ(std::string(config.specificPermission), "ohos.permission.TEST_PERMISSION");
}

HWTEST_F(PolicyQueryConfigTest, TestSpecificPermission_RealConstants, TestSize.Level1)
{
    PermissionConfig config1 = PermissionConfig::SpecificPermission(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY);
    ASSERT_EQ(config1.GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, ""),
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY);

    PermissionConfig config2 = PermissionConfig::SpecificPermission(
        EdmPermission::PERMISSION_ENTERPRISE_SET_BUNDLE_INSTALL_POLICY);
    ASSERT_EQ(config2.GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, ""),
        EdmPermission::PERMISSION_ENTERPRISE_SET_BUNDLE_INSTALL_POLICY);

    PermissionConfig config3 = PermissionConfig::SpecificPermission(
        EdmPermission::PERMISSION_ENTERPRISE_GET_DEVICE_INFO);
    ASSERT_EQ(config3.GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, ""),
        EdmPermission::PERMISSION_ENTERPRISE_GET_DEVICE_INFO);
}

HWTEST_F(PolicyQueryConfigTest, TestTagPermission_SuperWithTag, TestSize.Level1)
{
    PermissionConfig config = PermissionConfig::TagPermission("ohos.permission.TAG_PERMISSION",
        "ohos.permission.DEFAULT_PERMISSION");
    std::string permission = config.GetPermission(
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "version_11");
    ASSERT_EQ(permission, "ohos.permission.TAG_PERMISSION");
}

HWTEST_F(PolicyQueryConfigTest, TestTagPermission_SuperWithoutTag, TestSize.Level1)
{
    PermissionConfig config = PermissionConfig::TagPermission("ohos.permission.TAG_PERMISSION",
        "ohos.permission.DEFAULT_PERMISSION");
    std::string permission = config.GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "");
    ASSERT_EQ(permission, "ohos.permission.DEFAULT_PERMISSION");
}

HWTEST_F(PolicyQueryConfigTest, TestTagPermission_ByodWithoutByodPerm, TestSize.Level1)
{
    PermissionConfig config = PermissionConfig::TagPermission("ohos.permission.TAG_PERMISSION",
        "ohos.permission.DEFAULT_PERMISSION");
    std::string permission = config.GetPermission(IPlugin::PermissionType::BYOD_DEVICE_ADMIN, "");
    ASSERT_EQ(permission, "ohos.permission.DEFAULT_PERMISSION");
}

HWTEST_F(PolicyQueryConfigTest, TestTagPermission_ByodWithByodPerm, TestSize.Level1)
{
    PermissionConfig config = PermissionConfig::TagPermission("ohos.permission.TAG_PERMISSION",
        "ohos.permission.DEFAULT_PERMISSION", "ohos.permission.BYOD_PERMISSION");
    std::string permission = config.GetPermission(IPlugin::PermissionType::BYOD_DEVICE_ADMIN, "");
    ASSERT_EQ(permission, "ohos.permission.BYOD_PERMISSION");
}

HWTEST_F(PolicyQueryConfigTest, TestTagPermission_ByodIgnoresTag, TestSize.Level1)
{
    PermissionConfig config = PermissionConfig::TagPermission("ohos.permission.TAG_PERMISSION",
        "ohos.permission.DEFAULT_PERMISSION", "ohos.permission.BYOD_PERMISSION");
    std::string permission = config.GetPermission(
        IPlugin::PermissionType::BYOD_DEVICE_ADMIN, "version_11");
    ASSERT_EQ(permission, "ohos.permission.BYOD_PERMISSION");
}

HWTEST_F(PolicyQueryConfigTest, TestTagPermission_ByodEmptyByodPermFallsToDefault, TestSize.Level1)
{
    PermissionConfig config = PermissionConfig::TagPermission("ohos.permission.TAG_PERMISSION",
        "ohos.permission.DEFAULT_PERMISSION");
    std::string permission = config.GetPermission(IPlugin::PermissionType::BYOD_DEVICE_ADMIN, "");
    ASSERT_EQ(permission, "ohos.permission.DEFAULT_PERMISSION");
}

HWTEST_F(PolicyQueryConfigTest, TestTagPermission_NormalAdminWithoutTag, TestSize.Level1)
{
    PermissionConfig config = PermissionConfig::TagPermission("ohos.permission.TAG_PERMISSION",
        "ohos.permission.DEFAULT_PERMISSION");
    std::string permission = config.GetPermission(IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, "");
    ASSERT_EQ(permission, "ohos.permission.DEFAULT_PERMISSION");
}

HWTEST_F(PolicyQueryConfigTest, TestTagPermission_NormalAdminWithTag, TestSize.Level1)
{
    PermissionConfig config = PermissionConfig::TagPermission("ohos.permission.TAG_PERMISSION",
        "ohos.permission.DEFAULT_PERMISSION");
    std::string permission = config.GetPermission(
        IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, "version_11");
    ASSERT_EQ(permission, "ohos.permission.DEFAULT_PERMISSION");
}

HWTEST_F(PolicyQueryConfigTest, TestTagPermission_EmptyTagPermWithTag, TestSize.Level1)
{
    PermissionConfig config = PermissionConfig::TagPermission("",
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY);
    std::string permission = config.GetPermission(
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "system");
    ASSERT_EQ(permission, "");
}

HWTEST_F(PolicyQueryConfigTest, TestTagPermission_EmptyTagPermWithoutTag, TestSize.Level1)
{
    PermissionConfig config = PermissionConfig::TagPermission("",
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY);
    std::string permission = config.GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "");
    ASSERT_EQ(permission, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY);
}

HWTEST_F(PolicyQueryConfigTest, TestTagPermission_EmptyTagPermByod, TestSize.Level1)
{
    PermissionConfig config = PermissionConfig::TagPermission("",
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY);
    std::string permission = config.GetPermission(IPlugin::PermissionType::BYOD_DEVICE_ADMIN, "");
    ASSERT_EQ(permission, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY);
}

HWTEST_F(PolicyQueryConfigTest, TestTagPermission_FieldValues, TestSize.Level1)
{
    PermissionConfig config = PermissionConfig::TagPermission("ohos.permission.TAG_PERMISSION",
        "ohos.permission.DEFAULT_PERMISSION", "ohos.permission.BYOD_PERMISSION");
    ASSERT_EQ(config.pattern, PermissionPattern::TAG);
    ASSERT_NE(config.specificPermission, nullptr);
    ASSERT_EQ(std::string(config.specificPermission), "ohos.permission.DEFAULT_PERMISSION");
    ASSERT_NE(config.tagPermission, nullptr);
    ASSERT_EQ(std::string(config.tagPermission), "ohos.permission.TAG_PERMISSION");
    ASSERT_NE(config.byodPermission, nullptr);
    ASSERT_EQ(std::string(config.byodPermission), "ohos.permission.BYOD_PERMISSION");
}

HWTEST_F(PolicyQueryConfigTest, TestTagPermission_FieldValuesNoByod, TestSize.Level1)
{
    PermissionConfig config = PermissionConfig::TagPermission("ohos.permission.TAG_PERMISSION",
        "ohos.permission.DEFAULT_PERMISSION");
    ASSERT_EQ(config.pattern, PermissionPattern::TAG);
    ASSERT_EQ(config.byodPermission, nullptr);
}

HWTEST_F(PolicyQueryConfigTest, TestTagPermission_RealConstants_Bluetooth, TestSize.Level1)
{
    PermissionConfig config = PermissionConfig::TagPermission(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_BLUETOOTH,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS,
        EdmPermission::PERMISSION_PERSONAL_MANAGE_RESTRICTIONS);
    ASSERT_EQ(config.GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "version_11"),
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_BLUETOOTH);
    ASSERT_EQ(config.GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, ""),
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    ASSERT_EQ(config.GetPermission(IPlugin::PermissionType::BYOD_DEVICE_ADMIN, ""),
        EdmPermission::PERMISSION_PERSONAL_MANAGE_RESTRICTIONS);
}

HWTEST_F(PolicyQueryConfigTest, TestTagPermission_RealConstants_Datetime, TestSize.Level1)
{
    PermissionConfig config = PermissionConfig::TagPermission(
        EdmPermission::PERMISSION_ENTERPRISE_SET_DATETIME,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    ASSERT_EQ(config.GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "version_11"),
        EdmPermission::PERMISSION_ENTERPRISE_SET_DATETIME);
    ASSERT_EQ(config.GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, ""),
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    ASSERT_EQ(config.GetPermission(IPlugin::PermissionType::BYOD_DEVICE_ADMIN, ""),
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
}

HWTEST_F(PolicyQueryConfigTest, TestTagPermission_RealConstants_PasswordPolicy, TestSize.Level1)
{
    PermissionConfig config = PermissionConfig::TagPermission(
        "", EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY);
    ASSERT_EQ(config.GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "system"),
        "");
    ASSERT_EQ(config.GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, ""),
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY);
    ASSERT_EQ(config.GetPermission(IPlugin::PermissionType::BYOD_DEVICE_ADMIN, ""),
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY);
}

HWTEST_F(PolicyQueryConfigTest, TestTagPermission_RealConstants_Hdc, TestSize.Level1)
{
    PermissionConfig config = PermissionConfig::TagPermission(
        EdmPermission::PERMISSION_ENTERPRISE_RESTRICT_POLICY,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS,
        EdmPermission::PERMISSION_PERSONAL_MANAGE_RESTRICTIONS);
    ASSERT_EQ(config.GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "version_11"),
        EdmPermission::PERMISSION_ENTERPRISE_RESTRICT_POLICY);
    ASSERT_EQ(config.GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, ""),
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    ASSERT_EQ(config.GetPermission(IPlugin::PermissionType::BYOD_DEVICE_ADMIN, ""),
        EdmPermission::PERMISSION_PERSONAL_MANAGE_RESTRICTIONS);
}

HWTEST_F(PolicyQueryConfigTest, TestTagPermission_RealConstants_DisallowedRunningBundles, TestSize.Level1)
{
    PermissionConfig config = PermissionConfig::TagPermission(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SET_APP_RUNNING_POLICY,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION);
    ASSERT_EQ(config.GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "version_11"),
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SET_APP_RUNNING_POLICY);
    ASSERT_EQ(config.GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, ""),
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION);
    ASSERT_EQ(config.GetPermission(IPlugin::PermissionType::BYOD_DEVICE_ADMIN, ""),
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION);
}

HWTEST_F(PolicyQueryConfigTest, TestPermissionPattern_EnumValues, TestSize.Level1)
{
    ASSERT_EQ(static_cast<int>(PermissionPattern::RESTRICTION), 0);
    ASSERT_EQ(static_cast<int>(PermissionPattern::SPECIFIC), 1);
    ASSERT_EQ(static_cast<int>(PermissionPattern::TAG), 2);
}

HWTEST_F(PolicyQueryConfigTest, TestPolicyQueryConfig_DefaultValues, TestSize.Level1)
{
    PolicyQueryConfig config;
    ASSERT_EQ(config.policyName, nullptr);
    ASSERT_EQ(config.isPolicySaved, false);
}

HWTEST_F(PolicyQueryConfigTest, TestPolicyDataType_EnumValues, TestSize.Level1)
{
    ASSERT_EQ(static_cast<int>(PolicyDataType::BOOL), 0);
    ASSERT_EQ(static_cast<int>(PolicyDataType::ARRAY_STRING), 1);
    ASSERT_EQ(static_cast<int>(PolicyDataType::INT), 2);
    ASSERT_EQ(static_cast<int>(PolicyDataType::STRING), 3);
    ASSERT_EQ(static_cast<int>(PolicyDataType::CUSTOM), 4);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
