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

#define private public
#include "admin_manager_test.h"
#undef private
#include <vector>

#include "admin_manager.h"
#include "iplugin.h"
#include "permission_manager.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
constexpr int32_t TEST_USER_ID = 101;
constexpr int HUGE_ADMIN_SIZE = 100;

void AdminManagerTest::SetUp()
{
    PermissionManager::GetInstance()->AddPermission("ohos.permission.EDM_TEST_PERMISSION",
        IPlugin::PermissionType::NORMAL_DEVICE_ADMIN);
    PermissionManager::GetInstance()->AddPermission("ohos.permission.EDM_TEST_ENT_PERMISSION",
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN);
    adminMgr_ = AdminManager::GetInstance();
    adminMgr_->Init();
}

void AdminManagerTest::TearDown()
{
    std::vector<std::shared_ptr<Admin>> userAdmin;
    adminMgr_->GetAdminByUserId(DEFAULT_USER_ID, userAdmin);
    for (const auto &admin : userAdmin) {
        adminMgr_->DeleteAdmin(admin->adminInfo_.packageName_, DEFAULT_USER_ID);
    }
    adminMgr_->GetAdminByUserId(TEST_USER_ID, userAdmin);
    for (const auto &admin : userAdmin) {
        adminMgr_->DeleteAdmin(admin->adminInfo_.packageName_, TEST_USER_ID);
    }
    adminMgr_->instance_.reset();
    adminMgr_.reset();
    PermissionManager::DestroyInstance();
}

/**
 * @tc.name: TestGetReqPermission
 * @tc.desc: Test AdminManager::GetGrantedPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(AdminManagerTest, TestGetReqPermission, TestSize.Level1)
{
    std::vector<std::string> permissions;
    std::vector<EdmPermission> reqPermission;
    permissions = {"ohos.permission.EDM_TEST_PERMISSION_FAIL", "ohos.permission.EDM_TEST_PERMISSION"};
    adminMgr_->GetReqPermission(permissions, reqPermission);
    ASSERT_TRUE(reqPermission.size() == 1);

    permissions = {"ohos.permission.EDM_TEST_PERMISSION_FAIL", "ohos.permission.EDM_TEST_PERMISSION",
        "ohos.permission.EDM_TEST_ENT_PERMISSION"};
    adminMgr_->GetReqPermission(permissions, reqPermission);
    ASSERT_TRUE(reqPermission.size() == 2);
}

/**
 * @tc.name: TestGetGrantedPermission
 * @tc.desc: Test AdminManager::GetGrantedPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(AdminManagerTest, TestGetGrantedPermission, TestSize.Level1)
{
    std::vector<std::string> permissions;
    ErrCode res = adminMgr_->GetGrantedPermission(permissions, AdminType::NORMAL);
    ASSERT_TRUE(res == ERR_OK);

    permissions = {"ohos.permission.EDM_TEST_PERMISSION_FAIL", "ohos.permission.EDM_TEST_PERMISSION"};
    res = adminMgr_->GetGrantedPermission(permissions, AdminType::NORMAL);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(permissions.size() == 1);

    permissions = {"ohos.permission.EDM_TEST_PERMISSION_FAIL", "ohos.permission.EDM_TEST_PERMISSION"};
    res = adminMgr_->GetGrantedPermission(permissions, AdminType::ENT);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(permissions.size() == 1);

    permissions = {"ohos.permission.EDM_TEST_ENT_PERMISSION", "ohos.permission.EDM_TEST_PERMISSION"};
    res = adminMgr_->GetGrantedPermission(permissions, AdminType::NORMAL);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(permissions.size() == 1);

    permissions = {"ohos.permission.EDM_TEST_ENT_PERMISSION", "ohos.permission.EDM_TEST_PERMISSION"};
    res = adminMgr_->GetGrantedPermission(permissions, AdminType::ENT);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(permissions.size() == 2);
}

/**
 * @tc.name: TestGetAdminByUserId
 * @tc.desc: Test AdminManager::GetAdminByUserId function.
 * @tc.type: FUNC
 */
HWTEST_F(AdminManagerTest, TestGetAdminByUserId, TestSize.Level1)
{
    ErrCode res;
    std::vector<std::shared_ptr<Admin>> userAdmin;
    std::vector<std::string> permissions;
    AppExecFwk::ExtensionAbilityInfo abilityInfo;
    abilityInfo.bundleName = "com.edm.test.demo";
    abilityInfo.name = "testDemo";
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "technology company in wuhan";
    permissions = {"ohos.permission.EDM_TEST_PERMISSION"};
    Admin admin(abilityInfo, AdminType::NORMAL, entInfo, permissions, false);
    res = adminMgr_->SetAdminValue(DEFAULT_USER_ID, admin);
    ASSERT_TRUE(res == ERR_OK);
    adminMgr_->GetAdminByUserId(DEFAULT_USER_ID, userAdmin);
    ASSERT_TRUE(userAdmin.size() == 1);

    admin.adminInfo_.adminType_ = AdminType::ENT;
    admin.adminInfo_.packageName_ = "com.edm.test.demo1";
    admin.adminInfo_.permission_ = {"ohos.permission.EDM_TEST_PERMISSION", "ohos.permission.EDM_TEST_ENT_PERMISSION"};
    res = adminMgr_->SetAdminValue(DEFAULT_USER_ID, admin);
    ASSERT_TRUE(res == ERR_OK);

    adminMgr_->GetAdminByUserId(DEFAULT_USER_ID, userAdmin);
    ASSERT_TRUE(userAdmin.size() == 2);
}

/**
 * @tc.name: TestGetAdminByPkgName
 * @tc.desc: Test AdminManager::GetAdminByPkgName function.
 * @tc.type: FUNC
 */
HWTEST_F(AdminManagerTest, TestGetAdminByPkgName, TestSize.Level1)
{
    ErrCode res;
    std::vector<std::shared_ptr<Admin>> allAdmin;
    std::vector<std::string> permissions;
    AppExecFwk::ExtensionAbilityInfo abilityInfo;
    abilityInfo.bundleName = "com.edm.test.demo";
    abilityInfo.name = "testDemo";
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "technology company in wuhan";
    permissions = {"ohos.permission.EDM_TEST_PERMISSION"};
    Admin edmAdmin(abilityInfo, AdminType::NORMAL, entInfo, permissions, false);
    res = adminMgr_->SetAdminValue(DEFAULT_USER_ID, edmAdmin);
    ASSERT_TRUE(res == ERR_OK);

    edmAdmin.adminInfo_.adminType_ = AdminType::ENT;
    edmAdmin.adminInfo_.packageName_ = "com.edm.test.demo1";
    edmAdmin.adminInfo_.className_ = "testDemo";
    edmAdmin.adminInfo_.entInfo_.enterpriseName = "company";
    edmAdmin.adminInfo_.entInfo_.description = "technology company in wuhan";
    edmAdmin.adminInfo_.permission_ = {"ohos.permission.EDM_TEST_PERMISSION",
        "ohos.permission.EDM_TEST_ENT_PERMISSION"};
    res = adminMgr_->SetAdminValue(DEFAULT_USER_ID, edmAdmin);
    ASSERT_TRUE(res == ERR_OK);

    std::shared_ptr<Admin> admin;
    admin = adminMgr_->GetAdminByPkgName("com.edm.test.demo", DEFAULT_USER_ID);
    ASSERT_TRUE(admin != nullptr);

    admin = adminMgr_->GetAdminByPkgName("com.edm.test.demo1", DEFAULT_USER_ID);
    ASSERT_TRUE(admin != nullptr);
}

/**
 * @tc.name: TestDeleteAdmin
 * @tc.desc: Test AdminManager::DeleteAdmin function.
 * @tc.type: FUNC
 */
HWTEST_F(AdminManagerTest, TestDeleteAdmin, TestSize.Level1)
{
    ErrCode res;
    std::vector<std::shared_ptr<Admin>> userAdmin;
    std::vector<std::string> permissions;
    AppExecFwk::ExtensionAbilityInfo abilityInfo;
    abilityInfo.bundleName = "com.edm.test.demo";
    abilityInfo.name = "testDemo";
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "technology company in wuhan";
    permissions = {"ohos.permission.EDM_TEST_PERMISSION"};
    Admin edmAdmin(abilityInfo, AdminType::NORMAL, entInfo, permissions, false);
    res = adminMgr_->SetAdminValue(DEFAULT_USER_ID, edmAdmin);
    ASSERT_TRUE(res == ERR_OK);

    edmAdmin.adminInfo_.adminType_ = AdminType::ENT;
    edmAdmin.adminInfo_.packageName_ = "com.edm.test.demo1";
    edmAdmin.adminInfo_.permission_ = {"ohos.permission.EDM_TEST_PERMISSION",
        "ohos.permission.EDM_TEST_ENT_PERMISSION"};
    res = adminMgr_->SetAdminValue(DEFAULT_USER_ID, edmAdmin);
    ASSERT_TRUE(res == ERR_OK);

    res = adminMgr_->DeleteAdmin("com.edm.test.demo", DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);
    adminMgr_->GetAdminByUserId(DEFAULT_USER_ID, userAdmin);
    ASSERT_TRUE(userAdmin.size() == 1);

    res = adminMgr_->DeleteAdmin("com.edm.test.demo1", DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);
    adminMgr_->GetAdminByUserId(DEFAULT_USER_ID, userAdmin);
    ASSERT_TRUE(userAdmin.empty());
}

/**
 * @tc.name: TestSetAdminValue
 * @tc.desc: Test AdminManager::SetAdminValue function.
 * @tc.type: FUNC
 */
HWTEST_F(AdminManagerTest, TestSetAdminValue, TestSize.Level1)
{
    std::shared_ptr<Admin> admin;
    std::string bundleName = "com.edm.test.demo";
    ErrCode res;
    AppExecFwk::ExtensionAbilityInfo abilityInfo;
    abilityInfo.bundleName = bundleName;
    abilityInfo.name = "testDemo";
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "technology company in wuhan";
    std::vector<std::string> permissions;

    abilityInfo.bundleName = bundleName + "1";
    permissions = {};
    Admin edmAdmin(abilityInfo, AdminType::NORMAL, entInfo, permissions, false);
    res = adminMgr_->SetAdminValue(DEFAULT_USER_ID, edmAdmin);
    ASSERT_TRUE(res == ERR_OK);
    admin = adminMgr_->GetAdminByPkgName(edmAdmin.adminInfo_.packageName_, DEFAULT_USER_ID);
    ASSERT_TRUE(admin != nullptr);

    edmAdmin.adminInfo_.packageName_ = bundleName + "2";
    edmAdmin.adminInfo_.permission_ = {"ohos.permission.EDM_TEST_ENT_PERMISSION"};
    res = adminMgr_->SetAdminValue(DEFAULT_USER_ID, edmAdmin);
    ASSERT_TRUE(res != ERR_OK);
    admin = adminMgr_->GetAdminByPkgName(edmAdmin.adminInfo_.packageName_, DEFAULT_USER_ID);
    ASSERT_TRUE(admin == nullptr);

    edmAdmin.adminInfo_.packageName_ = bundleName + "3";
    edmAdmin.adminInfo_.permission_ = {"ohos.permission.EDM_TEST_PERMISSION_FAIL",
        "ohos.permission.EDM_TEST_PERMISSION"};
    res = adminMgr_->SetAdminValue(DEFAULT_USER_ID, edmAdmin);
    ASSERT_TRUE(res == ERR_OK);
    admin = adminMgr_->GetAdminByPkgName(edmAdmin.adminInfo_.packageName_, DEFAULT_USER_ID);
    ASSERT_TRUE(admin != nullptr);

    edmAdmin.adminInfo_.packageName_ = bundleName + "4";
    edmAdmin.adminInfo_.permission_ = {"ohos.permission.EDM_TEST_PERMISSION"};
    res = adminMgr_->SetAdminValue(DEFAULT_USER_ID, edmAdmin);
    ASSERT_TRUE(res == ERR_OK);
    admin = adminMgr_->GetAdminByPkgName(edmAdmin.adminInfo_.packageName_, DEFAULT_USER_ID);
    ASSERT_TRUE(admin != nullptr);

    edmAdmin.adminInfo_.adminType_ = AdminType::ENT;
    edmAdmin.adminInfo_.packageName_ = bundleName + "5";
    edmAdmin.adminInfo_.permission_ = {"ohos.permission.EDM_TEST_ENT_PERMISSION",
        "ohos.permission.EDM_TEST_PERMISSION"};
    res = adminMgr_->SetAdminValue(DEFAULT_USER_ID, edmAdmin);
    ASSERT_TRUE(res == ERR_OK);
    admin = adminMgr_->GetAdminByPkgName(edmAdmin.adminInfo_.packageName_, DEFAULT_USER_ID);
    ASSERT_TRUE(admin != nullptr);
}

/**
 * @tc.name: TestSetAdminValueHuge
 * @tc.desc: Test AdminManager::SetAdminValue function.
 * @tc.type: FUNC
 */
HWTEST_F(AdminManagerTest, TestSetAdminValueHuge, TestSize.Level1)
{
    std::shared_ptr<Admin> admin;
    std::string bundleName = "com.edm.test.demo";
    ErrCode res;
    AppExecFwk::ExtensionAbilityInfo abilityInfo;
    abilityInfo.bundleName = bundleName;
    abilityInfo.name = "testDemo";
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "technology company in wuhan";
    std::vector<std::string> permissions;
    Admin edmAdmin(abilityInfo, AdminType::NORMAL, entInfo, permissions, false);
    for (int i = 0; i < HUGE_ADMIN_SIZE; ++i) {
        edmAdmin.adminInfo_.packageName_ = bundleName + std::to_string(i);
        edmAdmin.adminInfo_.permission_ = {"ohos.permission.EDM_TEST_PERMISSION"};
        res = adminMgr_->SetAdminValue(DEFAULT_USER_ID, edmAdmin);
        ASSERT_TRUE(res == ERR_OK);
        admin = adminMgr_->GetAdminByPkgName(edmAdmin.adminInfo_.packageName_, DEFAULT_USER_ID);
        ASSERT_TRUE(admin != nullptr);
    }
    std::vector<std::shared_ptr<Admin>> userAdmin;
    adminMgr_->GetAdminByUserId(DEFAULT_USER_ID, userAdmin);
    ASSERT_TRUE(userAdmin.size() == HUGE_ADMIN_SIZE);
}

/**
 * @tc.name: TestUpdateAdmin
 * @tc.desc: Test AdminManager::UpdateAdmin function.
 * @tc.type: FUNC
 */
HWTEST_F(AdminManagerTest, TestUpdateAdmin, TestSize.Level1)
{
    std::string bundleName = "com.edm.test.demo";

    ErrCode res;
    AppExecFwk::ExtensionAbilityInfo abilityInfo;
    abilityInfo.bundleName = bundleName;
    abilityInfo.name = "testDemo";
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "technology company in wuhan";

    std::vector<std::string> permissions = {"ohos.permission.EDM_TEST_PERMISSION_FAIL",
        "ohos.permission.EDM_TEST_ENT_PERMISSION"};
    res = adminMgr_->GetGrantedPermission(permissions, AdminType::ENT);
    ASSERT_TRUE(res == ERR_OK);
    Admin edmAdmin(abilityInfo, AdminType::ENT, entInfo, permissions, false);
    adminMgr_->SetAdminValue(DEFAULT_USER_ID, edmAdmin);
    std::vector<std::shared_ptr<Admin>> userAdmin;
    adminMgr_->GetAdminByUserId(DEFAULT_USER_ID, userAdmin);
    ASSERT_TRUE(userAdmin.size() == 1);
    ASSERT_TRUE(userAdmin.at(0)->adminInfo_.permission_.size() == 1);

    permissions = {"ohos.permission.EDM_TEST_PERMISSION_FAIL", "ohos.permission.EDM_TEST_PERMISSION",
        "ohos.permission.EDM_TEST_ENT_PERMISSION"};
    res = adminMgr_->UpdateAdmin(abilityInfo, permissions, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);
    adminMgr_->GetAdminByUserId(DEFAULT_USER_ID, userAdmin);
    ASSERT_TRUE(userAdmin.size() == 1);
    ASSERT_TRUE(userAdmin.at(0)->adminInfo_.permission_.size() == 2);
}

/**
 * @tc.name: TestIsSuperAdmin
 * @tc.desc: Test AdminManager::IsSuperAdmin function.
 * @tc.type: FUNC
 */
HWTEST_F(AdminManagerTest, TestIsSuperAdmin, TestSize.Level1)
{
    std::string bundleName = "com.edm.test.demo";
    AppExecFwk::ExtensionAbilityInfo abilityInfo;
    abilityInfo.bundleName = bundleName;
    abilityInfo.name = "testDemo";
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "technology company in wuhan";

    std::vector<std::string> permissions = {"ohos.permission.EDM_TEST_ENT_PERMISSION"};
    Admin edmAdmin(abilityInfo, AdminType::ENT, entInfo, permissions, false);
    adminMgr_->SetAdminValue(DEFAULT_USER_ID, edmAdmin);
    ASSERT_TRUE(adminMgr_->IsSuperOrSubSuperAdmin(bundleName));
}

/**
 * @tc.name: TestIsSuperAdminExist
 * @tc.desc: Test AdminManager::IsSuperAdminExist function.
 * @tc.type: FUNC
 */
HWTEST_F(AdminManagerTest, TestIsSuperAdminExist, TestSize.Level1)
{
    std::string bundleName = "com.edm.test.demo";
    AppExecFwk::ExtensionAbilityInfo abilityInfo;
    abilityInfo.bundleName = bundleName;
    abilityInfo.name = "testDemo";
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "technology company in wuhan";

    std::vector<std::string> permissions = {"ohos.permission.EDM_TEST_ENT_PERMISSION"};
    Admin edmAdmin(abilityInfo, AdminType::ENT, entInfo, permissions, false);
    adminMgr_->SetAdminValue(DEFAULT_USER_ID, edmAdmin);
    edmAdmin.adminInfo_.adminType_ = AdminType::NORMAL;
    edmAdmin.adminInfo_.permission_ = {"ohos.permission.EDM_TEST_PERMISSION"};
    adminMgr_->SetAdminValue(DEFAULT_USER_ID, edmAdmin);
    ASSERT_TRUE(!adminMgr_->IsSuperAdminExist());
}

/**
 * @tc.name: TestGetAdminBySubscribeEvent
 * @tc.desc: Test AdminManager::GetAdminBySubscribeEvent function.
 * @tc.type: FUNC
 */
HWTEST_F(AdminManagerTest, TestGetAdminBySubscribeEvent, TestSize.Level1)
{
    AppExecFwk::ExtensionAbilityInfo abilityInfo;
    abilityInfo.bundleName = "com.edm.test.demo";
    abilityInfo.name = "testDemo";
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "technology company in wuhan";
    std::vector<std::string> permissions = {"ohos.permission.EDM_TEST_PERMISSION"};
    Admin edmAdmin(abilityInfo, AdminType::NORMAL, entInfo, permissions, false);
    adminMgr_->SetAdminValue(DEFAULT_USER_ID, edmAdmin);
    edmAdmin.adminInfo_.packageName_ = "com.edm.test.demo1";
    edmAdmin.adminInfo_.className_ = "testDemo1";
    edmAdmin.adminInfo_.entInfo_.enterpriseName = "company1";
    edmAdmin.adminInfo_.entInfo_.description = "technology company in wuhan1";
    adminMgr_->SetAdminValue(DEFAULT_USER_ID, edmAdmin);
    edmAdmin.adminInfo_.packageName_ = "com.edm.test.demo2";
    edmAdmin.adminInfo_.className_ = "testDemo2";
    edmAdmin.adminInfo_.entInfo_.enterpriseName = "company2";
    edmAdmin.adminInfo_.entInfo_.description = "technology company in wuhan2";
    adminMgr_->SetAdminValue(TEST_USER_ID, edmAdmin);

    const std::vector<uint32_t> events = {0, 1};
    adminMgr_->SaveSubscribeEvents(events, "com.edm.test.demo", DEFAULT_USER_ID);
    const std::vector<uint32_t> events1 = {1};
    adminMgr_->SaveSubscribeEvents(events1, "com.edm.test.demo2", TEST_USER_ID);

    std::unordered_map<int32_t, std::vector<std::shared_ptr<Admin>>> subscribeAdmins;
    adminMgr_->GetAdminBySubscribeEvent(ManagedEvent::BUNDLE_ADDED, subscribeAdmins);
    ASSERT_TRUE(subscribeAdmins[DEFAULT_USER_ID].size() == 1);
    ASSERT_TRUE(subscribeAdmins.find(TEST_USER_ID) == subscribeAdmins.end());
}

/**
 * @tc.name: TestSaveSubscribeEvents
 * @tc.desc: Test AdminManager::SaveSubscribeEvents function.
 * @tc.type: FUNC
 */
HWTEST_F(AdminManagerTest, TestSaveSubscribeEvents, TestSize.Level1)
{
    AppExecFwk::ExtensionAbilityInfo abilityInfo;
    abilityInfo.bundleName = "com.edm.test.demo";
    abilityInfo.name = "testDemo";
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "technology company in wuhan";
    std::vector<std::string> permissions = {"ohos.permission.EDM_TEST_PERMISSION"};
    Admin edmAdmin(abilityInfo, AdminType::NORMAL, entInfo, permissions, false);
    adminMgr_->SetAdminValue(DEFAULT_USER_ID, edmAdmin);

    std::shared_ptr<Admin> admin = adminMgr_->GetAdminByPkgName(abilityInfo.bundleName, DEFAULT_USER_ID);
    ASSERT_TRUE(admin != nullptr);
    std::vector<uint32_t> events = {0};
    adminMgr_->SaveSubscribeEvents(events, abilityInfo.bundleName, DEFAULT_USER_ID);
    ASSERT_TRUE(admin->adminInfo_.managedEvents_.size() == 1);
    events.push_back(1);
    adminMgr_->SaveSubscribeEvents(events, abilityInfo.bundleName, DEFAULT_USER_ID);
    ASSERT_TRUE(admin->adminInfo_.managedEvents_.size() > 1);
}

/**
 * @tc.name: TestRemoveSubscribeEvents
 * @tc.desc: Test AdminManager::RemoveSubscribeEvents function.
 * @tc.type: FUNC
 */
HWTEST_F(AdminManagerTest, TestRemoveSubscribeEvents, TestSize.Level1)
{
    AppExecFwk::ExtensionAbilityInfo abilityInfo;
    abilityInfo.bundleName = "com.edm.test.demo";
    abilityInfo.name = "testDemo";
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "technology company in wuhan";
    std::vector<std::string> permissions = {"ohos.permission.EDM_TEST_PERMISSION"};
    Admin edmAdmin(abilityInfo, AdminType::NORMAL, entInfo, permissions, false);
    adminMgr_->SetAdminValue(DEFAULT_USER_ID, edmAdmin);

    std::shared_ptr<Admin> admin = adminMgr_->GetAdminByPkgName(abilityInfo.bundleName, DEFAULT_USER_ID);
    ASSERT_TRUE(admin != nullptr);
    admin->adminInfo_.managedEvents_.push_back(ManagedEvent::BUNDLE_ADDED);

    std::vector<uint32_t> events = {1};
    adminMgr_->RemoveSubscribeEvents(events, abilityInfo.bundleName, DEFAULT_USER_ID);
    ASSERT_TRUE(admin->adminInfo_.managedEvents_.size() == 1);
    events.push_back(0);
    adminMgr_->RemoveSubscribeEvents(events, abilityInfo.bundleName, DEFAULT_USER_ID);
    ASSERT_TRUE(admin->adminInfo_.managedEvents_.empty());
}

/**
 * @tc.name: TestSaveAuthorizedAdminWithoutSDA
 * @tc.desc: Test AdminManager::SaveAuthorizedAdmin without super admin.
 * @tc.type: FUNC
 */
HWTEST_F(AdminManagerTest, TestSaveAuthorizedAdminWithoutSDA, TestSize.Level1)
{
    std::vector<std::string> permissions{"ohos.permission.EDM_TEST_PERMISSION"};
    ErrCode res = adminMgr_->SaveAuthorizedAdmin("com.edm.test.demo1", permissions, "com.edm.test.demo");
    ASSERT_TRUE(res == ERR_SAVE_AUTHORIZED_ADMIN_FAILED);
}

/**
 * @tc.name: TestSaveAuthorizedAdmin
 * @tc.desc: Test AdminManager::SaveAuthorizedAdmin.
 * @tc.type: FUNC
 */
HWTEST_F(AdminManagerTest, TestSaveAuthorizedAdmin, TestSize.Level1)
{
    std::vector<std::shared_ptr<Admin>> allAdmin;
    AppExecFwk::ExtensionAbilityInfo abilityInfo;
    abilityInfo.bundleName = "com.edm.test.demo";
    abilityInfo.name = "testDemo";
    EntInfo entInfo("test", "this is test");
    std::vector<std::string> permissions{"ohos.permission.EDM_TEST_PERMISSION"};
    Admin edmAdmin(abilityInfo, AdminType::ENT, entInfo, permissions, false);
    ErrCode res = adminMgr_->SetAdminValue(DEFAULT_USER_ID, edmAdmin);
    ASSERT_TRUE(res == ERR_OK);

    std::string subSuperAdmin = "com.edm.test.demo1";
    res = adminMgr_->SaveAuthorizedAdmin(subSuperAdmin, permissions, "com.edm.test.demo2");
    ASSERT_TRUE(res == ERR_OK);
    res = adminMgr_->SaveAuthorizedAdmin(subSuperAdmin, permissions, abilityInfo.bundleName);
    ASSERT_TRUE(res == ERR_OK);

    std::shared_ptr<Admin> admin;
    admin = adminMgr_->GetAdminByPkgName(subSuperAdmin, DEFAULT_USER_ID);
    ASSERT_TRUE(admin != nullptr);
    ASSERT_TRUE(admin->GetAdminType() == AdminType::SUB_SUPER_ADMIN);
    ASSERT_TRUE(admin->GetParentAdminName() == abilityInfo.bundleName);

    res = adminMgr_->DeleteAdmin(abilityInfo.bundleName, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);
    res = adminMgr_->DeleteAdmin(subSuperAdmin, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);
}

/**
 * @tc.name: TestGetSubSuperAdminsByParentName
 * @tc.desc: Test AdminManager::GetSubSuperAdminsByParentName.
 * @tc.type: FUNC
 */
HWTEST_F(AdminManagerTest, TestGetSubSuperAdminsByParentName, TestSize.Level1)
{
    std::vector<std::string> subAdminNames;
    ErrCode res = adminMgr_->GetSubSuperAdminsByParentName("com.edm.test.demo1", subAdminNames);
    ASSERT_TRUE(res == ERR_EDM_SUPER_ADMIN_NOT_FOUND);

    std::vector<std::shared_ptr<Admin>> allAdmin;
    AppExecFwk::ExtensionAbilityInfo abilityInfo;
    abilityInfo.bundleName = "com.edm.test.demo";
    abilityInfo.name = "testDemo";
    EntInfo entInfo("test", "this is test");
    std::vector<std::string> permissions{"ohos.permission.EDM_TEST_PERMISSION"};
    Admin edmAdmin(abilityInfo, AdminType::ENT, entInfo, permissions, false);
    res = adminMgr_->SetAdminValue(DEFAULT_USER_ID, edmAdmin);
    ASSERT_TRUE(res == ERR_OK);
    std::string subSuperAdmin = "com.edm.test.demo1";
    res = adminMgr_->SaveAuthorizedAdmin(subSuperAdmin, permissions, abilityInfo.bundleName);
    ASSERT_TRUE(res == ERR_OK);

    res = adminMgr_->GetSubSuperAdminsByParentName("com.edm.test.demo2", subAdminNames);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(subAdminNames.empty());

    res = adminMgr_->GetSubSuperAdminsByParentName(abilityInfo.bundleName, subAdminNames);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(std::find(subAdminNames.begin(), subAdminNames.end(), subSuperAdmin) != subAdminNames.end());
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS