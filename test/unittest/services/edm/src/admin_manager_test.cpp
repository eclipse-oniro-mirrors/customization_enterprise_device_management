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

#include "admin_container.h"
#include "admin_manager.h"
#include "iplugin.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
constexpr int32_t TEST_USER_ID = 101;
constexpr int HUGE_ADMIN_SIZE = 100;

void AdminManagerTest::SetUp()
{
    adminMgr_ = AdminManager::GetInstance();
    adminMgr_->Init();
    adminMgr_->ClearAdmins();
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
    adminMgr_->ClearAdmins();
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
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "technology company in wuhan";
    permissions = {"ohos.permission.EDM_TEST_PERMISSION"};
    AdminInfo adminInfo = {.packageName_ = "com.edm.test.demo", .className_ = "testDemo", .entInfo_ = entInfo,
        .permission_ = permissions, .adminType_ = AdminType::NORMAL, .isDebug_ = false};
    res = adminMgr_->SetAdminValue(DEFAULT_USER_ID, adminInfo);
    ASSERT_TRUE(res == ERR_OK);
    adminMgr_->GetAdminByUserId(DEFAULT_USER_ID, userAdmin);
    ASSERT_TRUE(userAdmin.size() == 1);

    adminInfo.adminType_ = AdminType::ENT;
    adminInfo.packageName_ = "com.edm.test.demo1";
    adminInfo.permission_ = {"ohos.permission.EDM_TEST_PERMISSION", "ohos.permission.EDM_TEST_ENT_PERMISSION"};
    res = adminMgr_->SetAdminValue(DEFAULT_USER_ID, adminInfo);
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
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "technology company in wuhan";
    permissions = {"ohos.permission.EDM_TEST_PERMISSION"};
    AdminInfo adminInfo = {.packageName_ = "com.edm.test.demo", .className_ = "testDemo", .entInfo_ = entInfo,
        .permission_ = permissions, .adminType_ = AdminType::NORMAL, .isDebug_ = false};
    res = adminMgr_->SetAdminValue(DEFAULT_USER_ID, adminInfo);
    ASSERT_TRUE(res == ERR_OK);

    adminInfo.adminType_ = AdminType::ENT;
    adminInfo.packageName_ = "com.edm.test.demo1";
    adminInfo.className_ = "testDemo";
    adminInfo.entInfo_.enterpriseName = "company";
    adminInfo.entInfo_.description = "technology company in wuhan";
    adminInfo.permission_ = {"ohos.permission.EDM_TEST_PERMISSION",
        "ohos.permission.EDM_TEST_ENT_PERMISSION"};
    res = adminMgr_->SetAdminValue(DEFAULT_USER_ID, adminInfo);
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
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "technology company in wuhan";
    permissions = {"ohos.permission.EDM_TEST_PERMISSION"};
    AdminInfo adminInfo = {.packageName_ = "com.edm.test.demo", .className_ = "testDemo", .entInfo_ = entInfo,
        .permission_ = permissions, .adminType_ = AdminType::NORMAL, .isDebug_ = false};
    res = adminMgr_->SetAdminValue(DEFAULT_USER_ID, adminInfo);
    ASSERT_TRUE(res == ERR_OK);

    adminInfo.adminType_ = AdminType::ENT;
    adminInfo.packageName_ = "com.edm.test.demo1";
    adminInfo.permission_ = {"ohos.permission.EDM_TEST_PERMISSION",
        "ohos.permission.EDM_TEST_ENT_PERMISSION"};
    res = adminMgr_->SetAdminValue(DEFAULT_USER_ID, adminInfo);
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
HWTEST_F(AdminManagerTest, TestSetAdminValue, TestSize.Level0)
{
    std::shared_ptr<Admin> admin;
    std::string bundleName = "com.edm.test.demo";
    ErrCode res;
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "technology company in wuhan";
    std::vector<std::string> permissions;

    bundleName = bundleName + "1";
    permissions = {};
    AdminInfo adminInfo = {.packageName_ = "com.edm.test.demo", .className_ = "testDemo", .entInfo_ = entInfo,
        .permission_ = permissions, .adminType_ = AdminType::NORMAL, .isDebug_ = false};
    res = adminMgr_->SetAdminValue(DEFAULT_USER_ID, adminInfo);
    ASSERT_TRUE(res == ERR_OK);
    admin = adminMgr_->GetAdminByPkgName(adminInfo.packageName_, DEFAULT_USER_ID);
    ASSERT_TRUE(admin != nullptr);

    adminInfo.packageName_ = bundleName + "2";
    adminInfo.permission_ = {"ohos.permission.EDM_TEST_ENT_PERMISSION"};
    res = adminMgr_->SetAdminValue(DEFAULT_USER_ID, adminInfo);
    ASSERT_TRUE(res == ERR_OK);
    admin = adminMgr_->GetAdminByPkgName(adminInfo.packageName_, DEFAULT_USER_ID);
    ASSERT_TRUE(admin != nullptr);

    adminInfo.packageName_ = bundleName + "3";
    adminInfo.permission_ = {"ohos.permission.EDM_TEST_PERMISSION_FAIL",
        "ohos.permission.EDM_TEST_PERMISSION"};
    res = adminMgr_->SetAdminValue(DEFAULT_USER_ID, adminInfo);
    ASSERT_TRUE(res == ERR_OK);
    admin = adminMgr_->GetAdminByPkgName(adminInfo.packageName_, DEFAULT_USER_ID);
    ASSERT_TRUE(admin != nullptr);

    adminInfo.packageName_ = bundleName + "4";
    adminInfo.permission_ = {"ohos.permission.EDM_TEST_PERMISSION"};
    res = adminMgr_->SetAdminValue(DEFAULT_USER_ID, adminInfo);
    ASSERT_TRUE(res == ERR_OK);
    admin = adminMgr_->GetAdminByPkgName(adminInfo.packageName_, DEFAULT_USER_ID);
    ASSERT_TRUE(admin != nullptr);

    adminInfo.adminType_ = AdminType::ENT;
    adminInfo.packageName_ = bundleName + "5";
    adminInfo.permission_ = {"ohos.permission.EDM_TEST_ENT_PERMISSION",
        "ohos.permission.EDM_TEST_PERMISSION"};
    res = adminMgr_->SetAdminValue(DEFAULT_USER_ID, adminInfo);
    ASSERT_TRUE(res == ERR_OK);
    admin = adminMgr_->GetAdminByPkgName(adminInfo.packageName_, DEFAULT_USER_ID);
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
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "technology company in wuhan";
    std::vector<std::string> permissions;
    AdminInfo adminInfo = {.packageName_ = "com.edm.test.demo", .className_ = "testDemo", .entInfo_ = entInfo,
        .permission_ = permissions, .adminType_ = AdminType::NORMAL, .isDebug_ = false};
    for (int i = 0; i < HUGE_ADMIN_SIZE; ++i) {
        adminInfo.packageName_ = bundleName + std::to_string(i);
        adminInfo.permission_ = {"ohos.permission.EDM_TEST_PERMISSION"};
        res = adminMgr_->SetAdminValue(DEFAULT_USER_ID, adminInfo);
        ASSERT_TRUE(res == ERR_OK);
        admin = adminMgr_->GetAdminByPkgName(adminInfo.packageName_, DEFAULT_USER_ID);
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
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "technology company in wuhan";

    std::vector<std::string> permissions = {"ohos.permission.EDM_TEST_PERMISSION_FAIL",
        "ohos.permission.EDM_TEST_ENT_PERMISSION"};
    AdminInfo adminInfo = {.packageName_ = "com.edm.test.demo", .className_ = "testDemo", .entInfo_ = entInfo,
        .permission_ = permissions, .adminType_ = AdminType::ENT, .isDebug_ = false};
    adminMgr_->SetAdminValue(DEFAULT_USER_ID, adminInfo);
    std::vector<std::shared_ptr<Admin>> userAdmin;
    adminMgr_->GetAdminByUserId(DEFAULT_USER_ID, userAdmin);
    ASSERT_TRUE(userAdmin.size() == 1);
    ASSERT_TRUE(userAdmin.at(0)->adminInfo_.permission_.size() == 2);

    permissions = {"ohos.permission.EDM_TEST_PERMISSION_FAIL", "ohos.permission.EDM_TEST_PERMISSION",
        "ohos.permission.EDM_TEST_ENT_PERMISSION"};
    AdminInfo updateAdminInfo = {.packageName_ = "com.edm.test.demo", .className_ = "testDemo", .entInfo_ = entInfo,
        .permission_ = permissions, .adminType_ = AdminType::ENT, .isDebug_ = false};
    res = adminMgr_->UpdateAdmin(DEFAULT_USER_ID, updateAdminInfo,
        CLASS_NAME | ENTI_NFO | PERMISSION | ACCESSIBLE_POLICIES | RUNNING_MODE);
    ASSERT_TRUE(res == ERR_OK);
    adminMgr_->GetAdminByUserId(DEFAULT_USER_ID, userAdmin);
    ASSERT_TRUE(userAdmin.size() == 1);
    ASSERT_TRUE(userAdmin.at(0)->adminInfo_.permission_.size() == 3);
}

/**
 * @tc.name: TestIsSuperAdmin
 * @tc.desc: Test AdminManager::IsSuperAdmin function.
 * @tc.type: FUNC
 */
HWTEST_F(AdminManagerTest, TestIsSuperAdmin, TestSize.Level1)
{
    std::string bundleName = "com.edm.test.demo";
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "technology company in wuhan";

    std::vector<std::string> permissions = {"ohos.permission.EDM_TEST_ENT_PERMISSION"};
    AdminInfo adminInfo = {.packageName_ = "com.edm.test.demo", .className_ = "testDemo", .entInfo_ = entInfo,
        .permission_ = permissions, .adminType_ = AdminType::ENT, .isDebug_ = false};
    adminMgr_->SetAdminValue(DEFAULT_USER_ID, adminInfo);
    ASSERT_TRUE(adminMgr_->IsSuperOrSubSuperAdmin(bundleName));
}

/**
 * @tc.name: TestIsByodAdmin001
 * @tc.desc: Test AdminManager::IsByodAdmin function.
 * @tc.type: FUNC
 */
HWTEST_F(AdminManagerTest, TestIsByodAdmin001, TestSize.Level1)
{
    std::string bundleName = "com.edm.test.demo";
    ASSERT_TRUE(!adminMgr_->IsByodAdmin(bundleName, DEFAULT_USER_ID));
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "technology company in wuhan";

    std::vector<std::string> permissions = {"ohos.permission.EDM_TEST_ENT_PERMISSION"};
    AdminInfo adminInfo = {.packageName_ = "com.edm.test.demo", .className_ = "testDemo", .entInfo_ = entInfo,
        .permission_ = permissions, .adminType_ = AdminType::BYOD, .isDebug_ = false};
    adminMgr_->SetAdminValue(DEFAULT_USER_ID, adminInfo);
    ASSERT_TRUE(adminMgr_->IsByodAdmin(bundleName, DEFAULT_USER_ID));
}

/**
 * @tc.name: TestIsByodAdmin002
 * @tc.desc: Test AdminManager::IsByodAdmin admin is normal
 * @tc.type: FUNC
 */
HWTEST_F(AdminManagerTest, TestIsByodAdmin002, TestSize.Level1)
{
    std::string bundleName = "com.edm.test.demo";
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "technology company in wuhan";

    std::vector<std::string> permissions = {"ohos.permission.EDM_TEST_ENT_PERMISSION"};
    AdminInfo adminInfo = {.packageName_ = "com.edm.test.demo", .className_ = "testDemo", .entInfo_ = entInfo,
        .permission_ = permissions, .adminType_ = AdminType::NORMAL, .isDebug_ = false};
    adminMgr_->SetAdminValue(DEFAULT_USER_ID, adminInfo);
    ASSERT_TRUE(!adminMgr_->IsByodAdmin(bundleName, DEFAULT_USER_ID));
}

/**
 * @tc.name: TestIsSuperAdminExist
 * @tc.desc: Test AdminManager::IsSuperAdminExist function.
 * @tc.type: FUNC
 */
HWTEST_F(AdminManagerTest, TestIsSuperAdminExist, TestSize.Level1)
{
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "technology company in wuhan";

    std::vector<std::string> permissions = {"ohos.permission.EDM_TEST_ENT_PERMISSION"};
    AdminInfo adminInfo = {.packageName_ = "com.edm.test.demo", .className_ = "testDemo",
        .entInfo_ = entInfo, .permission_ = permissions, .adminType_ = AdminType::ENT, .isDebug_ = false};
    adminMgr_->SetAdminValue(DEFAULT_USER_ID, adminInfo);
    adminInfo.adminType_ = AdminType::NORMAL;
    adminInfo.permission_ = {"ohos.permission.EDM_TEST_PERMISSION"};
    adminMgr_->SetAdminValue(DEFAULT_USER_ID, adminInfo);
    ASSERT_TRUE(adminMgr_->IsSuperAdminExist());
}

/**
 * @tc.name: TestIsByodAdminExist
 * @tc.desc: Test AdminManager::IsByodAdminExist function.
 * @tc.type: FUNC
 */
HWTEST_F(AdminManagerTest, TestIsByodAdminExist, TestSize.Level1)
{
    std::string bundleName = "com.edm.test.demo";
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "technology company in wuhan";
    ASSERT_FALSE(adminMgr_->IsByodAdminExist());
    std::vector<std::string> permissions = {"ohos.permission.EDM_TEST_ENT_PERMISSION"};
    AdminInfo adminInfo = {.packageName_ = bundleName, .className_ = "testDemo", .entInfo_ = entInfo,
        .permission_ = permissions, .adminType_ = AdminType::BYOD, .isDebug_ = false};
    adminMgr_->SetAdminValue(DEFAULT_USER_ID, adminInfo);
    adminInfo.adminType_ = AdminType::NORMAL;
    adminInfo.permission_ = {"ohos.permission.EDM_TEST_PERMISSION"};
    adminMgr_->SetAdminValue(DEFAULT_USER_ID, adminInfo);
    ASSERT_TRUE(adminMgr_->IsByodAdminExist());
}

/**
 * @tc.name: TestGetAdminBySubscribeEvent
 * @tc.desc: Test AdminManager::GetAdminBySubscribeEvent function.
 * @tc.type: FUNC
 */
HWTEST_F(AdminManagerTest, TestGetAdminBySubscribeEvent, TestSize.Level1)
{
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "technology company in wuhan";
    std::vector<std::string> permissions = {"ohos.permission.EDM_TEST_PERMISSION"};
    AdminInfo adminInfo = {.packageName_ = "com.edm.test.demo", .className_ = "testDemo", .entInfo_ = entInfo,
        .permission_ = permissions, .adminType_ = AdminType::NORMAL, .isDebug_ = false};
    adminMgr_->SetAdminValue(DEFAULT_USER_ID, adminInfo);
    adminInfo.packageName_ = "com.edm.test.demo1";
    adminInfo.className_ = "testDemo1";
    adminInfo.entInfo_.enterpriseName = "company1";
    adminInfo.entInfo_.description = "technology company in wuhan1";
    adminMgr_->SetAdminValue(DEFAULT_USER_ID, adminInfo);
    adminInfo.packageName_ = "com.edm.test.demo2";
    adminInfo.className_ = "testDemo2";
    adminInfo.entInfo_.enterpriseName = "company2";
    adminInfo.entInfo_.description = "technology company in wuhan2";
    adminMgr_->SetAdminValue(TEST_USER_ID, adminInfo);

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
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "technology company in wuhan";
    std::vector<std::string> permissions = {"ohos.permission.EDM_TEST_PERMISSION"};
    std::string bundleName = "com.edm.test.demo";
    AdminInfo adminInfo = {.packageName_ = bundleName, .className_ = "testDemo", .entInfo_ = entInfo,
        .permission_ = permissions, .adminType_ = AdminType::NORMAL, .isDebug_ = false};
    adminMgr_->SetAdminValue(DEFAULT_USER_ID, adminInfo);

    std::shared_ptr<Admin> admin = adminMgr_->GetAdminByPkgName(bundleName, DEFAULT_USER_ID);
    ASSERT_TRUE(admin != nullptr);
    std::vector<uint32_t> events = {0};
    adminMgr_->SaveSubscribeEvents(events, bundleName, DEFAULT_USER_ID);
    admin = adminMgr_->GetAdminByPkgName(bundleName, DEFAULT_USER_ID);
    ASSERT_TRUE(admin->adminInfo_.managedEvents_.size() == 1);
    events.push_back(1);
    adminMgr_->SaveSubscribeEvents(events, bundleName, DEFAULT_USER_ID);
    admin = adminMgr_->GetAdminByPkgName(bundleName, DEFAULT_USER_ID);
    ASSERT_TRUE(admin->adminInfo_.managedEvents_.size() > 1);
}

/**
 * @tc.name: TestRemoveSubscribeEvents
 * @tc.desc: Test AdminManager::RemoveSubscribeEvents function.
 * @tc.type: FUNC
 */
HWTEST_F(AdminManagerTest, TestRemoveSubscribeEvents, TestSize.Level1)
{
    std::string bundleName = "com.edm.test.demo";
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "technology company in wuhan";
    std::vector<std::string> permissions = {"ohos.permission.EDM_TEST_PERMISSION"};
    AdminInfo adminInfo = {.packageName_ = bundleName, .className_ = "testDemo", .entInfo_ = entInfo,
        .permission_ = permissions, .adminType_ = AdminType::NORMAL, .isDebug_ = false};
    adminMgr_->SetAdminValue(DEFAULT_USER_ID, adminInfo);

    std::shared_ptr<Admin> admin = adminMgr_->GetAdminByPkgName(bundleName, DEFAULT_USER_ID);
    ASSERT_TRUE(admin != nullptr);

    std::vector<uint32_t> events = {0};
    adminMgr_->SaveSubscribeEvents(events, bundleName, DEFAULT_USER_ID);

    events = {1};
    adminMgr_->RemoveSubscribeEvents(events, bundleName, DEFAULT_USER_ID);
    admin = adminMgr_->GetAdminByPkgName(bundleName, DEFAULT_USER_ID);
    ASSERT_TRUE(admin->adminInfo_.managedEvents_.size() == 1);
    events.push_back(0);
    adminMgr_->RemoveSubscribeEvents(events, bundleName, DEFAULT_USER_ID);
    admin = adminMgr_->GetAdminByPkgName(bundleName, DEFAULT_USER_ID);
    ASSERT_TRUE(admin->adminInfo_.managedEvents_.empty());
}

/**
 * @tc.name: TestSaveAuthorizedAdmin
 * @tc.desc: Test AdminManager::SaveAuthorizedAdmin.
 * @tc.type: FUNC
 */
HWTEST_F(AdminManagerTest, TestSaveAuthorizedAdmin, TestSize.Level1)
{
    std::vector<std::shared_ptr<Admin>> allAdmin;
    std::string bundleName = "com.edm.test.demo";
    EntInfo entInfo("test", "this is test");
    std::vector<std::string> permissions{"ohos.permission.EDM_TEST_PERMISSION"};
    AdminInfo adminInfo = {.packageName_ = bundleName, .className_ = "testDemo",
        .entInfo_ = entInfo, .permission_ = permissions, .adminType_ = AdminType::ENT, .isDebug_ = false};
    ErrCode res = adminMgr_->SetAdminValue(DEFAULT_USER_ID, adminInfo);
    ASSERT_TRUE(res == ERR_OK);

    std::string subBundleName = "com.edm.test.demo1";
    AdminInfo subSuperAdminInfo = {.packageName_ = subBundleName, .className_ = "testDemo",
        .parentAdminName_ = bundleName, .entInfo_ = entInfo, .permission_ = permissions,
        .adminType_ = AdminType::SUB_SUPER_ADMIN, .isDebug_ = true};
    res = adminMgr_->SetAdminValue(DEFAULT_USER_ID, subSuperAdminInfo);
    ASSERT_TRUE(res == ERR_OK);

    std::shared_ptr<Admin> admin;
    admin = adminMgr_->GetAdminByPkgName(subBundleName, DEFAULT_USER_ID);
    ASSERT_TRUE(admin != nullptr);
    ASSERT_TRUE(admin->GetAdminType() == AdminType::SUB_SUPER_ADMIN);
    ASSERT_TRUE(admin->GetParentAdminName() == bundleName);

    res = adminMgr_->DeleteAdmin(bundleName, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);
    res = adminMgr_->DeleteAdmin(subBundleName, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);
}

/**
 * @tc.name: TestGetSubSuperAdminsBasic
 * @tc.desc: Test AdminManager::GetSubSuperAdmins.
 * @tc.type: FUNC
 */
HWTEST_F(AdminManagerTest, TestGetSubSuperAdminsBasic, TestSize.Level1)
{
    std::vector<std::shared_ptr<Admin>> subAdmins;
    adminMgr_->GetSubSuperAdmins(DEFAULT_USER_ID, subAdmins);
    EXPECT_EQ(subAdmins.size(), 0);
}

/**
 * @tc.name: TestGetSubSuperAdminsNoSubSuperAdmin
 * @tc.desc: Test AdminManager::GetSubSuperAdmins.
 * @tc.type: FUNC
 */
HWTEST_F(AdminManagerTest, TestGetSubSuperAdminsNoSubSuperAdmin, TestSize.Level1)
{
    EntInfo entInfo("test", "this is test");
    std::vector<std::string> permissions{"ohos.permission.EDM_TEST_PERMISSION"};
    AdminInfo adminInfo = {.packageName_ = "com.edm.test.demo", .className_ = "testDemo",
        .entInfo_ = entInfo, .permission_ = permissions, .adminType_ = AdminType::ENT, .isDebug_ = false};
    ErrCode res = adminMgr_->SetAdminValue(DEFAULT_USER_ID, adminInfo);
    EXPECT_EQ(res, ERR_OK);
    std::vector<std::shared_ptr<Admin>> subAdmins;
    adminMgr_->GetSubSuperAdmins(DEFAULT_USER_ID, subAdmins);
    EXPECT_EQ(subAdmins.size(), 0);
}

/**
 * @tc.name: TestGetSubSuperAdminsWithSubSuperAdmin
 * @tc.desc: Test AdminManager::GetSubSuperAdmins.
 * @tc.type: FUNC
 */
HWTEST_F(AdminManagerTest, TestGetSubSuperAdminsWithSubSuperAdmin, TestSize.Level1)
{
    std::string bundleName = "com.edm.test.demo";
    EntInfo entInfo("test", "this is test");
    std::vector<std::string> permissions{"ohos.permission.EDM_TEST_PERMISSION"};
    AdminInfo adminInfo = {.packageName_ = bundleName, .className_ = "testDemo",
        .entInfo_ = entInfo, .permission_ = permissions, .adminType_ = AdminType::ENT, .isDebug_ = false};
    ErrCode res = adminMgr_->SetAdminValue(DEFAULT_USER_ID, adminInfo);
    EXPECT_EQ(res, ERR_OK);

    std::string subBundleName = "com.edm.test.demo1";
    AdminInfo subSuperAdminInfo = {.packageName_ = subBundleName, .className_ = "testDemo",
        .parentAdminName_ = bundleName, .entInfo_ = entInfo, .permission_ = permissions,
        .adminType_ = AdminType::SUB_SUPER_ADMIN, .isDebug_ = false};
    res = adminMgr_->SetAdminValue(DEFAULT_USER_ID, subSuperAdminInfo);
    ASSERT_TRUE(res == ERR_OK);

    std::vector<std::shared_ptr<Admin>> subAdmins;
    adminMgr_->GetSubSuperAdmins(DEFAULT_USER_ID, subAdmins);
    EXPECT_EQ(subAdmins.size(), 1);
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
    std::string bundleName = "com.edm.test.demo";
    EntInfo entInfo("test", "this is test");
    std::vector<std::string> permissions{"ohos.permission.EDM_TEST_PERMISSION"};
    AdminInfo adminInfo = {.packageName_ = bundleName, .className_ = "testDemo",
        .entInfo_ = entInfo, .permission_ = permissions, .adminType_ = AdminType::ENT, .isDebug_ = false};
    res = adminMgr_->SetAdminValue(DEFAULT_USER_ID, adminInfo);
    adminMgr_->Dump();
    std::string subBundleName = "com.edm.test.demo1";
    AdminInfo subSuperAdminInfo = {.packageName_ = subBundleName, .className_ = "testDemo",
        .parentAdminName_ = bundleName, .entInfo_ = entInfo, .permission_ = permissions,
        .adminType_ = AdminType::SUB_SUPER_ADMIN, .isDebug_ = false};
    res = adminMgr_->SetAdminValue(DEFAULT_USER_ID, subSuperAdminInfo);
    ASSERT_TRUE(res == ERR_OK);

    res = adminMgr_->GetSubSuperAdminsByParentName("com.edm.test.demo2", subAdminNames);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(subAdminNames.empty());

    res = adminMgr_->GetSubSuperAdminsByParentName(bundleName, subAdminNames);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(std::find(subAdminNames.begin(), subAdminNames.end(), subBundleName) !=
        subAdminNames.end());
}

/**
 * @tc.name: TestGetAdmins
 * @tc.desc: Test AdminManager::TestGetAdmins.
 * @tc.type: FUNC
 */
HWTEST_F(AdminManagerTest, TestGetAdmins, TestSize.Level1)
{
    ErrCode res;
    std::vector<std::string> permissions;
    std::string bundleName = "com.edm.test.demo";
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "technology company in wuhan";
    permissions = {"ohos.permission.EDM_TEST_PERMISSION"};
    AdminInfo adminInfo = {.packageName_ = bundleName, .className_ = "testDemo", .entInfo_ = entInfo,
        .permission_ = permissions, .adminType_ = AdminType::NORMAL, .isDebug_ = false};
    res = adminMgr_->SetAdminValue(DEFAULT_USER_ID, adminInfo);
    ASSERT_TRUE(res == ERR_OK);

    std::vector<std::shared_ptr<Admin>> userAdmins;
    adminMgr_->GetAdmins(userAdmins, TEST_USER_ID);
    int32_t sizeofAdmin = userAdmins.size();
    ASSERT_TRUE(sizeofAdmin == 1);
    std::shared_ptr<Admin> userAdmin = userAdmins[0];
    ASSERT_TRUE(userAdmin != nullptr);
    ASSERT_TRUE(userAdmin->adminInfo_.adminType_ == AdminType::NORMAL);
    userAdmins.clear();
    res = adminMgr_->DeleteAdmin(bundleName, TEST_USER_ID);
    ASSERT_TRUE(res == ERR_OK);

    adminInfo.adminType_ = AdminType::BYOD;
    adminInfo.packageName_ = "com.edm.test.demo1";
    adminInfo.permission_ = {"ohos.permission.EDM_TEST_PERMISSION", "ohos.permission.EDM_TEST_ENT_PERMISSION"};
    res = adminMgr_->SetAdminValue(DEFAULT_USER_ID, adminInfo);
    ASSERT_TRUE(res == ERR_OK);
    adminInfo.adminType_ = AdminType::ENT;
    adminInfo.packageName_ = "com.edm.test.demo2";
    adminInfo.permission_ = {"ohos.permission.EDM_TEST_PERMISSION", "ohos.permission.EDM_TEST_ENT_PERMISSION"};
    res = adminMgr_->SetAdminValue(DEFAULT_USER_ID, adminInfo);
    ASSERT_TRUE(res == ERR_OK);

    adminMgr_->GetAdmins(userAdmins, DEFAULT_USER_ID);
    sizeofAdmin = userAdmins.size();
    ASSERT_TRUE(sizeofAdmin == 2);
    userAdmin = userAdmins[0];
    ASSERT_TRUE(userAdmin != nullptr);
    ASSERT_TRUE(userAdmin->adminInfo_.adminType_ == AdminType::BYOD);
    userAdmin = userAdmins[1];
    ASSERT_TRUE(userAdmin != nullptr);
    ASSERT_TRUE(userAdmin->adminInfo_.adminType_ == AdminType::ENT);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
