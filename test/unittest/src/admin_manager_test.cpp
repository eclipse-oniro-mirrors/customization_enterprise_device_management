/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "cmd_utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
constexpr int32_t DEFAULT_USER_ID = 100;
constexpr int32_t TEST_USER_ID = 101;
constexpr int HUGE_ADMIN_SIZE = 100;
const std::string TEAR_DOWN_CMD = "rm /data/service/el1/public/edm/admin_policies.json";

void AdminManagerTest::SetUp()
{
    PermissionManager::GetInstance()->AddPermission("ohos.permission.EDM_TEST_PERMISSION");
    PermissionManager::GetInstance()->AddPermission("ohos.permission.EDM_TEST_ENT_PERMISSION");
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
    adminMgr_->instance_.reset();
    adminMgr_.reset();
    PermissionManager::DestroyInstance();

    CmdUtils::ExecCmdSync(TEAR_DOWN_CMD);
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
    permissions = {
        "ohos.permission.EDM_TEST_PERMISSION_FAIL", "ohos.permission.EDM_TEST_PERMISSION"
    };
    adminMgr_->GetReqPermission(permissions, reqPermission);
    ASSERT_TRUE(reqPermission.size() == 1);

    permissions = {
        "ohos.permission.EDM_TEST_PERMISSION_FAIL", "ohos.permission.EDM_TEST_PERMISSION",
        "ohos.permission.EDM_TEST_ENT_PERMISSION"
    };
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
    ErrCode res;
    std::vector<std::string> permissions;
    AppExecFwk::ExtensionAbilityInfo abilityInfo;
    abilityInfo.bundleName = "com.edm.test.demo";
    abilityInfo.name = "testDemo";
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "technology company in china";

    permissions = {};
    res = adminMgr_->GetGrantedPermission(abilityInfo, permissions, AdminType::NORMAL);
    ASSERT_TRUE(res == ERR_OK);

    permissions = {
        "ohos.permission.EDM_TEST_PERMISSION_FAIL", "ohos.permission.EDM_TEST_PERMISSION"
    };
    res = adminMgr_->GetGrantedPermission(abilityInfo, permissions, AdminType::NORMAL);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(permissions.size() == 1);

    permissions = {
        "ohos.permission.EDM_TEST_PERMISSION_FAIL", "ohos.permission.EDM_TEST_PERMISSION"
    };
    res = adminMgr_->GetGrantedPermission(abilityInfo, permissions, AdminType::ENT);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(permissions.size() == 1);

    permissions = {
        "ohos.permission.EDM_TEST_ENT_PERMISSION", "ohos.permission.EDM_TEST_PERMISSION"
    };
    res = adminMgr_->GetGrantedPermission(abilityInfo, permissions, AdminType::NORMAL);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(permissions.size() == 1);

    permissions = {
        "ohos.permission.EDM_TEST_ENT_PERMISSION", "ohos.permission.EDM_TEST_PERMISSION"
    };
    res = adminMgr_->GetGrantedPermission(abilityInfo, permissions, AdminType::ENT);
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
    permissions = {
        "ohos.permission.EDM_TEST_PERMISSION"
    };
    res = adminMgr_->SetAdminValue(abilityInfo, entInfo, AdminType::NORMAL, permissions, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);
    adminMgr_->GetAdminByUserId(DEFAULT_USER_ID, userAdmin);
    ASSERT_TRUE(userAdmin.size() == 1);

    abilityInfo.bundleName = "com.edm.test.demo1";
    permissions = {
        "ohos.permission.EDM_TEST_PERMISSION", "ohos.permission.EDM_TEST_ENT_PERMISSION"
    };
    res = adminMgr_->SetAdminValue(abilityInfo, entInfo, AdminType::ENT, permissions, DEFAULT_USER_ID);
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
    permissions = {
        "ohos.permission.EDM_TEST_PERMISSION"
    };
    res = adminMgr_->SetAdminValue(abilityInfo, entInfo, AdminType::NORMAL, permissions, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);

    abilityInfo.bundleName = "com.edm.test.demo1";
    abilityInfo.name = "testDemo";
    entInfo.enterpriseName = "company";
    entInfo.description = "technology company in wuhan";

    permissions = {
        "ohos.permission.EDM_TEST_PERMISSION", "ohos.permission.EDM_TEST_ENT_PERMISSION"
    };
    res = adminMgr_->SetAdminValue(abilityInfo, entInfo, AdminType::ENT, permissions, DEFAULT_USER_ID);
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
    permissions = {
        "ohos.permission.EDM_TEST_PERMISSION"
    };
    res = adminMgr_->SetAdminValue(abilityInfo, entInfo, AdminType::NORMAL, permissions, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);

    abilityInfo.bundleName = "com.edm.test.demo1";
    permissions = {
        "ohos.permission.EDM_TEST_PERMISSION", "ohos.permission.EDM_TEST_ENT_PERMISSION"
    };
    res = adminMgr_->SetAdminValue(abilityInfo, entInfo, AdminType::ENT, permissions, DEFAULT_USER_ID);
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
    res = adminMgr_->SetAdminValue(abilityInfo, entInfo, AdminType::NORMAL, permissions, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);
    admin = adminMgr_->GetAdminByPkgName(abilityInfo.bundleName, DEFAULT_USER_ID);
    ASSERT_TRUE(admin != nullptr);

    abilityInfo.bundleName = bundleName + "2";
    permissions = { "ohos.permission.EDM_TEST_ENT_PERMISSION" };
    res = adminMgr_->SetAdminValue(abilityInfo, entInfo, AdminType::NORMAL, permissions, DEFAULT_USER_ID);
    ASSERT_TRUE(res != ERR_OK);
    admin = adminMgr_->GetAdminByPkgName(abilityInfo.bundleName, DEFAULT_USER_ID);
    ASSERT_TRUE(admin == nullptr);

    abilityInfo.bundleName = bundleName + "3";
    permissions = {
        "ohos.permission.EDM_TEST_PERMISSION_FAIL", "ohos.permission.EDM_TEST_PERMISSION"
    };
    res = adminMgr_->SetAdminValue(abilityInfo, entInfo, AdminType::NORMAL, permissions, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);
    admin = adminMgr_->GetAdminByPkgName(abilityInfo.bundleName, DEFAULT_USER_ID);
    ASSERT_TRUE(admin != nullptr);

    abilityInfo.bundleName = bundleName + "4";
    permissions = { "ohos.permission.EDM_TEST_PERMISSION" };
    res = adminMgr_->SetAdminValue(abilityInfo, entInfo, AdminType::NORMAL, permissions, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);
    admin = adminMgr_->GetAdminByPkgName(abilityInfo.bundleName, DEFAULT_USER_ID);
    ASSERT_TRUE(admin != nullptr);

    abilityInfo.bundleName = bundleName + "5";
    permissions = { "ohos.permission.EDM_TEST_ENT_PERMISSION", "ohos.permission.EDM_TEST_PERMISSION" };
    res = adminMgr_->SetAdminValue(abilityInfo, entInfo, AdminType::ENT, permissions, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);
    admin = adminMgr_->GetAdminByPkgName(abilityInfo.bundleName, DEFAULT_USER_ID);
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

    for (int i = 0; i < HUGE_ADMIN_SIZE; ++i) {
        abilityInfo.bundleName = bundleName + std::to_string(i);
        permissions = {
            "ohos.permission.EDM_TEST_PERMISSION"
        };
        res = adminMgr_->SetAdminValue(abilityInfo, entInfo, AdminType::NORMAL, permissions, DEFAULT_USER_ID);
        ASSERT_TRUE(res == ERR_OK);
        admin = adminMgr_->GetAdminByPkgName(abilityInfo.bundleName, DEFAULT_USER_ID);
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

    std::vector<std::string> permissions = {
        "ohos.permission.EDM_TEST_PERMISSION_FAIL", "ohos.permission.EDM_TEST_ENT_PERMISSION"
    };
    res = adminMgr_->GetGrantedPermission(abilityInfo, permissions, AdminType::ENT);
    ASSERT_TRUE(res == ERR_OK);
    adminMgr_->SetAdminValue(abilityInfo, entInfo, AdminType::ENT, permissions, DEFAULT_USER_ID);
    std::vector<std::shared_ptr<Admin>> userAdmin;
    adminMgr_->GetAdminByUserId(DEFAULT_USER_ID, userAdmin);
    ASSERT_TRUE(userAdmin.size() == 1);
    ASSERT_TRUE(userAdmin.at(0)->adminInfo_.permission_.size() == 1);

    permissions = {
        "ohos.permission.EDM_TEST_PERMISSION_FAIL", "ohos.permission.EDM_TEST_PERMISSION",
        "ohos.permission.EDM_TEST_ENT_PERMISSION"
    };
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

    std::vector<std::string> permissions = { "ohos.permission.EDM_TEST_ENT_PERMISSION" };
    adminMgr_->SetAdminValue(abilityInfo, entInfo, AdminType::ENT, permissions, DEFAULT_USER_ID);
    ASSERT_TRUE(adminMgr_->IsSuperAdmin(bundleName));
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

    std::vector<std::string> permissions = { "ohos.permission.EDM_TEST_ENT_PERMISSION" };
    adminMgr_->SetAdminValue(abilityInfo, entInfo, AdminType::ENT, permissions, DEFAULT_USER_ID);
    permissions = { "ohos.permission.EDM_TEST_PERMISSION" };
    adminMgr_->SetAdminValue(abilityInfo, entInfo, AdminType::NORMAL, permissions, DEFAULT_USER_ID);
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
    std::vector<std::string> permissions = { "ohos.permission.EDM_TEST_PERMISSION" };
    adminMgr_->SetAdminValue(abilityInfo, entInfo, AdminType::NORMAL, permissions, DEFAULT_USER_ID);
    abilityInfo.bundleName = "com.edm.test.demo1";
    abilityInfo.name = "testDemo1";
    entInfo.enterpriseName = "company1";
    entInfo.description = "technology company in wuhan1";
    adminMgr_->SetAdminValue(abilityInfo, entInfo, AdminType::NORMAL, permissions, DEFAULT_USER_ID);
    abilityInfo.bundleName = "com.edm.test.demo2";
    abilityInfo.name = "testDemo2";
    entInfo.enterpriseName = "company2";
    entInfo.description = "technology company in wuhan2";
    adminMgr_->SetAdminValue(abilityInfo, entInfo, AdminType::NORMAL, permissions, TEST_USER_ID);

    std::shared_ptr<Admin> adminItem = adminMgr_->GetAdminByPkgName("com.edm.test.demo", DEFAULT_USER_ID);
    const std::vector<uint32_t> events = {0, 1};
    adminMgr_->SaveSubscribeEvents(events, adminItem, DEFAULT_USER_ID);
    const std::vector<uint32_t> events1 = {1};
    std::shared_ptr<Admin> adminItem1 = adminMgr_->GetAdminByPkgName("com.edm.test.demo2", TEST_USER_ID);
    adminMgr_->SaveSubscribeEvents(events1, adminItem1, TEST_USER_ID);

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
    std::shared_ptr<Admin> admin = std::make_shared<Admin>();
    admin->adminInfo_.managedEvents_.push_back(ManagedEvent::BUNDLE_ADDED);
    std::vector<uint32_t> events = {0};
    AppExecFwk::ExtensionAbilityInfo abilityInfo;
    abilityInfo.bundleName = "com.edm.test.demo";
    abilityInfo.name = "testDemo";
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "technology company in wuhan";
    std::vector<std::string> permissions = { "ohos.permission.EDM_TEST_PERMISSION" };
    adminMgr_->SetAdminValue(abilityInfo, entInfo, AdminType::NORMAL, permissions, DEFAULT_USER_ID);
    adminMgr_->SaveSubscribeEvents(events, admin, DEFAULT_USER_ID);
    ASSERT_TRUE(admin->adminInfo_.managedEvents_.size() == 1);
    events.push_back(1);
    adminMgr_->SaveSubscribeEvents(events, admin, DEFAULT_USER_ID);
    ASSERT_TRUE(admin->adminInfo_.managedEvents_.size() > 1);
}

/**
 * @tc.name: TestRemoveSubscribeEvents
 * @tc.desc: Test AdminManager::RemoveSubscribeEvents function.
 * @tc.type: FUNC
 */
HWTEST_F(AdminManagerTest, TestRemoveSubscribeEvents, TestSize.Level1)
{
    std::shared_ptr<Admin> admin = std::make_shared<Admin>();
    admin->adminInfo_.managedEvents_.push_back(ManagedEvent::BUNDLE_ADDED);
    std::vector<uint32_t> events = {1};
    AppExecFwk::ExtensionAbilityInfo abilityInfo;
    abilityInfo.bundleName = "com.edm.test.demo";
    abilityInfo.name = "testDemo";
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "technology company in wuhan";
    std::vector<std::string> permissions = { "ohos.permission.EDM_TEST_PERMISSION" };
    adminMgr_->SetAdminValue(abilityInfo, entInfo, AdminType::NORMAL, permissions, DEFAULT_USER_ID);
    adminMgr_->RemoveSubscribeEvents(events, admin, DEFAULT_USER_ID);
    ASSERT_TRUE(admin->adminInfo_.managedEvents_.size() == 1);
    events.push_back(0);
    adminMgr_->RemoveSubscribeEvents(events, admin, DEFAULT_USER_ID);
    ASSERT_TRUE(admin->adminInfo_.managedEvents_.empty());
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS