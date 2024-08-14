/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "admin.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string TEST_PERMISSION = "ohos.permission.EDM_TEST_PERMISSION";
const std::string TEST_PERMISSION_FAIL = "ohos.permission.EDM_TEST_PERMISSION_FAIL";
const std::string TEST_BUNDLE_NAME = "com.edm.test.demo";
const std::string TEST_ABILITY_NAME = "com.edm.test.demo.Ability";
class AdminTest : public testing::Test {};
/**
 * @tc.name: TestCheckPermissionWithPermissionEmpty
 * @tc.desc: Test AdminManager::CheckPermission.
 * @tc.type: FUNC
 */
HWTEST_F(AdminTest, TestCheckPermissionWithPermissionEmpty, TestSize.Level1)
{
    AppExecFwk::ExtensionAbilityInfo abilityInfo;
    EntInfo entInfo;
    std::vector<std::string> permissions;
    std::shared_ptr<Admin> admin = std::make_shared<Admin>(abilityInfo, AdminType::ENT, entInfo, permissions, true);
    bool ret = admin->CheckPermission(TEST_PERMISSION);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TestCheckPermissionWithInvalidPermission
 * @tc.desc: Test AdminManager::CheckPermission.
 * @tc.type: FUNC
 */
HWTEST_F(AdminTest, TestCheckPermissionWithInvalidPermission, TestSize.Level1)
{
    AppExecFwk::ExtensionAbilityInfo abilityInfo;
    EntInfo entInfo;
    std::vector<std::string> permissions;
    permissions.push_back(TEST_PERMISSION_FAIL);
    std::shared_ptr<Admin> admin = std::make_shared<Admin>(abilityInfo, AdminType::ENT, entInfo, permissions, true);
    bool ret = admin->CheckPermission(TEST_PERMISSION);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TestCheckPermission
 * @tc.desc: Test AdminManager::CheckPermission.
 * @tc.type: FUNC
 */
HWTEST_F(AdminTest, TestCheckPermission, TestSize.Level1)
{
    AppExecFwk::ExtensionAbilityInfo abilityInfo;
    EntInfo entInfo;
    std::vector<std::string> permissions;
    permissions.push_back(TEST_PERMISSION);
    std::shared_ptr<Admin> admin = std::make_shared<Admin>(abilityInfo, AdminType::ENT, entInfo, permissions, true);
    bool ret = admin->CheckPermission(TEST_PERMISSION);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: TestGetAdminTypeWithSuperAdmin
 * @tc.desc: Test AdminManager::GetAdminType.
 * @tc.type: FUNC
 */
HWTEST_F(AdminTest, TestGetAdminTypeWithSuperAdmin, TestSize.Level1)
{
    AppExecFwk::ExtensionAbilityInfo abilityInfo;
    EntInfo entInfo;
    std::vector<std::string> permissions;
    std::shared_ptr<Admin> admin = std::make_shared<Admin>(abilityInfo, AdminType::ENT, entInfo, permissions, true);
    AdminType adminType = admin->GetAdminType();
    ASSERT_TRUE(adminType == AdminType::ENT);
}

/**
 * @tc.name: TestGetAdminTypeWithNormalAdmin
 * @tc.desc: Test AdminManager::GetAdminType.
 * @tc.type: FUNC
 */
HWTEST_F(AdminTest, TestGetAdminTypeWithNormalAdmin, TestSize.Level1)
{
    AppExecFwk::ExtensionAbilityInfo abilityInfo;
    EntInfo entInfo;
    std::vector<std::string> permissions;
    std::shared_ptr<Admin> admin = std::make_shared<Admin>(abilityInfo, AdminType::NORMAL, entInfo, permissions, true);
    AdminType adminType = admin->GetAdminType();
    ASSERT_TRUE(adminType == AdminType::NORMAL);
}

/**
 * @tc.name: TestGetAdminTypeWithUnknownAdmin
 * @tc.desc: Test AdminManager::GetAdminType.
 * @tc.type: FUNC
 */
HWTEST_F(AdminTest, TestGetAdminTypeWithUnknownAdmin, TestSize.Level1)
{
    AppExecFwk::ExtensionAbilityInfo abilityInfo;
    EntInfo entInfo;
    std::vector<std::string> permissions;
    std::shared_ptr<Admin> admin = std::make_shared<Admin>(abilityInfo, AdminType::UNKNOWN, entInfo, permissions, true);
    AdminType adminType = admin->GetAdminType();
    ASSERT_TRUE(adminType == AdminType::UNKNOWN);
}

/**
 * @tc.name: TestGetParentAdminNameWithSuperAdmin
 * @tc.desc: Test AdminManager::GetParentAdminName.
 * @tc.type: FUNC
 */
HWTEST_F(AdminTest, TestGetParentAdminNameWithSuperAdmin, TestSize.Level1)
{
    AppExecFwk::ExtensionAbilityInfo abilityInfo;
    EntInfo entInfo;
    std::vector<std::string> permissions;
    std::shared_ptr<Admin> admin = std::make_shared<Admin>(abilityInfo, AdminType::ENT, entInfo, permissions, true);
    std::string parentAdminName = admin->GetParentAdminName();
    ASSERT_TRUE(parentAdminName.empty());
}

/**
 * @tc.name: TestGetParentAdminNameWithNormalAdmin
 * @tc.desc: Test AdminManager::GetParentAdminName.
 * @tc.type: FUNC
 */
HWTEST_F(AdminTest, TestGetParentAdminNameWithNormalAdmin, TestSize.Level1)
{
    AppExecFwk::ExtensionAbilityInfo abilityInfo;
    EntInfo entInfo;
    std::vector<std::string> permissions;
    std::shared_ptr<Admin> admin = std::make_shared<Admin>(abilityInfo, AdminType::NORMAL, entInfo, permissions, true);
    std::string parentAdminName = admin->GetParentAdminName();
    ASSERT_TRUE(parentAdminName.empty());
}

/**
 * @tc.name: TestGetParentAdminNameWithUnknownAdmin
 * @tc.desc: Test AdminManager::GetParentAdminName.
 * @tc.type: FUNC
 */
HWTEST_F(AdminTest, TestGetParentAdminNameWithUnknownAdmin, TestSize.Level1)
{
    AppExecFwk::ExtensionAbilityInfo abilityInfo;
    EntInfo entInfo;
    std::vector<std::string> permissions;
    std::shared_ptr<Admin> admin = std::make_shared<Admin>(abilityInfo, AdminType::UNKNOWN, entInfo, permissions, true);
    std::string parentAdminName = admin->GetParentAdminName();
    ASSERT_TRUE(parentAdminName.empty());
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS