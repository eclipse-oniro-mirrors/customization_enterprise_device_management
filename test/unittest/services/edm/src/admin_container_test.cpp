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

#include "admin_container_test.h"
#include <vector>
 
#include "admin_container.h"
 
using namespace testing::ext;
 
namespace OHOS {
namespace EDM {
namespace TEST {
constexpr int32_t TEST_USER_ID = 101;
 
void AdminManagerTest::SetUp()
{
    adminContainer_ = AdminContainer::GetInstance();
    adminContainer_->InitAdmins();
    adminContainer_->ClearAdmins();
}

void AdminManagerTest::TearDown()
{
    std::vector<std::shared_ptr<Admin>> userAdmin;
    adminContainer_->GetAdminByUserId(DEFAULT_USER_ID, userAdmin);
    for (const auto &admin : userAdmin) {
        adminContainer_->DeleteAdmin(admin->adminInfo_.packageName_, DEFAULT_USER_ID);
    }
    adminMgr_->GetAdminByUserId(TEST_USER_ID, userAdmin);
    for (const auto &admin : userAdmin) {
        adminContainer_->DeleteAdmin(admin->adminInfo_.packageName_, TEST_USER_ID);
    }
    adminContainer_->ClearAdmins();
}

/**
 * @tc.name: TestGetAdminByUserId
 * @tc.desc: Test AdminContainer::GetAdminByUserId function.
 * @tc.type: FUNC
 */
HWTEST_F(AdminContainerTest, TestGetAdminByUserId, TestSize.Level1)
{
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
    adminContainer_->SetAdminByUserId(DEFAULT_USER_ID, admin);
    adminContainer_->GetAdminByUserId(DEFAULT_USER_ID, userAdmin);
    ASSERT_TRUE(userAdmin.size() == 1);

    admin.adminInfo_.adminType_ = AdminType::ENT;
    admin.adminInfo_.packageName_ = "com.edm.test.demo1";
    admin.adminInfo_.permission_ = {"ohos.permission.EDM_TEST_PERMISSION", "ohos.permission.EDM_TEST_ENT_PERMISSION"};
    adminContainer_->SetAdminByUserId(DEFAULT_USER_ID, admin);
    adminContainer_->GetAdminByUserId(DEFAULT_USER_ID, userAdmin);
    ASSERT_TRUE(userAdmin.size() == 2);
}

/**
 * @tc.name: TestGetAdminBySubscribeEvent
 * @tc.desc: Test AdminContainer::GetAdminBySubscribeEvent function.
 * @tc.type: FUNC
 */
HWTEST_F(AdminContainerTest, TestGetAdminBySubscribeEvent, TestSize.Level1)
{
    AppExecFwk::ExtensionAbilityInfo abilityInfo;
    abilityInfo.bundleName = "com.edm.test.demo";
    abilityInfo.name = "testDemo";
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "technology company in wuhan";
    std::vector<std::string> permissions = {"ohos.permission.EDM_TEST_PERMISSION"};
    Admin edmAdmin(abilityInfo, AdminType::NORMAL, entInfo, permissions, false);
    adminContainer_->SetAdminByUserId(DEFAULT_USER_ID, edmAdmin);
    edmAdmin.adminInfo_.managedEvents_ = {ManagedEvent::BUNDLE_ADDED, ManagedEvent::BUNDLE_REMOVED};
    adminContainer_->UpdateAdmin(DEFAULT_USER_ID, "com.edm.test.demo", MANAGED_EVENTS, edmAdmin);

    edmAdmin.adminInfo_.packageName_ = "com.edm.test.demo1";
    edmAdmin.adminInfo_.className_ = "testDemo1";
    edmAdmin.adminInfo_.entInfo_.enterpriseName = "company1";
    edmAdmin.adminInfo_.entInfo_.description = "technology company in wuhan1";
    adminContainer_->SetAdminByUserId(DEFAULT_USER_ID, edmAdmin);

    edmAdmin.adminInfo_.packageName_ = "com.edm.test.demo2";
    edmAdmin.adminInfo_.className_ = "testDemo2";
    edmAdmin.adminInfo_.entInfo_.enterpriseName = "company2";
    edmAdmin.adminInfo_.entInfo_.description = "technology company in wuhan2";
    adminContainer_->SetAdminByUserId(TEST_USER_ID, edmAdmin);
    edmAdmin.adminInfo_.managedEvents_ = {ManagedEvent::BUNDLE_REMOVED};
    adminContainer_->UpdateAdmin(DEFAULT_USER_ID, "com.edm.test.demo", MANAGED_EVENTS, edmAdmin);

    std::unordered_map<int32_t, std::vector<std::shared_ptr<Admin>>> subscribeAdmins;
    adminContainer_->GetAdminBySubscribeEvent(ManagedEvent::BUNDLE_ADDED, subscribeAdmins);
    ASSERT_TRUE(subscribeAdmins[DEFAULT_USER_ID].size() == 1);
    ASSERT_TRUE(subscribeAdmins.find(TEST_USER_ID) == subscribeAdmins.end());
}

/**
 * @tc.name: TestUpdateAdmin
 * @tc.desc: Test AdminContainer::UpdateAdmin function.
 * @tc.type: FUNC
 */
HWTEST_F(AdminContainerTest, TestUpdateAdmin, TestSize.Level1)
{
    std::string bundleName = "com.edm.test.demo";
    std::string className = "testDemo";

    ErrCode res;
    EntInfo entInfo1;
    entInfo1.enterpriseName = "company1";
    entInfo1.description = "technology company in wuhan";
    std::vector<std::string> permissions = {"ohos.permission.EDM_TEST_PERMISSION"};

    Admin edmAdmin;
    edmAdmin.adminInfo_.packageName_ = bundleName;
    edmAdmin.adminInfo_.className_ = testDemo;
    edmAdmin.adminInfo_.entInfo_ = entInfo1;
    edmAdmin.adminInfo_.permission_= permission;
    edmAdmin.adminInfo_.managedEvents_ = {ManagedEvent::BUNDLE_REMOVED};
    edmAdmin.adminInfo_.parentAdminName_ = "com.edm.test.demo1";
    edmAdmin.adminInfo_.accessiblePolicies_ = "ploicy1";
    edmAdmin.adminInfo_.adminType_ = ADMIN_TYPE:ENT;
    edmAdmin.adminInfo_.runningMode_ = RUNNING_MODE:DEFAULT;
    adminContainer_->SetAdminByUserId(DEFAULT_USER_ID, edmAdmin);

    EntInfo entInfo2;
    entInfo2.enterpriseName = "company2";
    entInfo2.description = "technology company in xian";
    std::vector<std::string> permissions = {"ohos.permission.EDM_TEST_PERMISSION_FAIL"};

    Admin updateAdmin;
    updateAdmin.adminInfo_.packageName_ = bundleName;
    updateAdmin.adminInfo_.className_ = testDemo;
    updateAdmin.adminInfo_.entInfo_ = entInfo2;
    updateAdmin.adminInfo_.permission_= permission;
    updateAdmin.adminInfo_.managedEvents_ = {ManagedEvent::BUNDLE_ADDED};
    updateAdmin.adminInfo_.parentAdminName_ = "com.edm.test.demo2";
    updateAdmin.adminInfo_.accessiblePolicies_ = "ploicy2";
    updateAdmin.adminInfo_.adminType_ = ADMIN_TYPE:NORMAL;
    updateAdmin.adminInfo_.runningMode_ = RUNNING_MODE::MULTI_USER;

    adminContainer_->UpdateAdmin(DEFAULT_USER_ID, bundleName, CLASS_NAME | ENTI_NFO | PERMISSION | MANAGED_EVENTS |
        PARENT_ADMIN_NAME | ACCESSIBLE_POLICIES | ADMIN_TYPE | IS_DEBUG | RUNNING_MODE, updateAdmin);

    std::vector<std::shared_ptr<Admin>> userAdmin;
    adminContainer_->GetAdminCopyByUserId(DEFAULT_USER_ID, userAdmin);
    ASSERT_TRUE(userAdmin.size() == 1);
    std::shared_ptr<Admin> admin = userAdmin.at(0);

    ASSERT_EQ(admin->adminInfo_.className_, updateAdmin.adminInfo_.className);
    ASSERT_EQ(admin->adminInfo_.entInfo_.description, updateAdmin.adminInfo_.entInfo_.description);
    ASSERT_EQ(admin->adminInfo_.entInfo_.enterpriseName, updateAdmin.adminInfo_.entInfo_.enterpriseName);
    ASSERT_EQ(admin->adminInfo_.permission_[0], updateAdmin.adminInfo_.permission_[0]);
    ASSERT_EQ(admin->adminInfo_.managedEvents_[0], updateAdmin.adminInfo_.managedEvents_[0]);
    ASSERT_EQ(admin->adminInfo_.parentAdminName_, updateAdmin.adminInfo_.parentAdminName_);
    ASSERT_EQ(admin->adminInfo_.accessiblePolicies_, updateAdmin.adminInfo_.accessiblePolicies_);
    ASSERT_EQ(admin->adminInfo_.adminType_, updateAdmin.adminInfo_.adminType_);
    ASSERT_EQ(admin->adminInfo_.runningMode_, updateAdmin.adminInfo_.runningMode_);
}

/**
 * @tc.name: TestDeleteAdmin
 * @tc.desc: Test AdminContainer::DeleteAdmin function.
 * @tc.type: FUNC
 */
HWTEST_F(AdminContainerTest, TestDeleteAdmin, TestSize.Level1)
{
    bool res;
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
    adminContainer_->SetAdminByUserId(DEFAULT_USER_ID, edmAdmin);

    edmAdmin.adminInfo_.adminType_ = AdminType::ENT;
    edmAdmin.adminInfo_.packageName_ = "com.edm.test.demo1";
    edmAdmin.adminInfo_.permission_ = {"ohos.permission.EDM_TEST_PERMISSION",
        "ohos.permission.EDM_TEST_ENT_PERMISSION"};
    adminContainer_->SetAdminByUserId(DEFAULT_USER_ID, edmAdmin);

    res = adminContainer_->DeleteAdmin("com.edm.test.demo", DEFAULT_USER_ID);
    ASSERT_TRUE(res);
    adminContainer_->GetAdminCopyByUserId(DEFAULT_USER_ID, userAdmin);
    ASSERT_TRUE(userAdmin.size() == 1);

    res = adminContainer_->DeleteAdmin("com.edm.test.demo1", DEFAULT_USER_ID);
    ASSERT_TRUE(res);
    adminContainer_->GetAdminCopyByUserId(DEFAULT_USER_ID, userAdmin);
    ASSERT_TRUE(userAdmin.empty());
}

/**
 * @tc.name: TestSetAdminValue
 * @tc.desc: Test AdminContainer::SetAdminByUserId function.
 * @tc.type: FUNC
 */
HWTEST_F(AdminContainerTest, TestSetAdminByUserId, TestSize.Level0)
{
    std::shared_ptr<Admin> admin;
    bool res;
    AppExecFwk::ExtensionAbilityInfo abilityInfo;
    std::string bundleName = "com.edm.test.demo";
    abilityInfo.bundleName = bundleName;
    abilityInfo.name = "testDemo";
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "technology company in wuhan";
    std::vector<std::string> permissions {"ohos.permission.EDM_TEST_ENT_PERMISSION"};
    Admin edmAdmin(abilityInfo, AdminType::NORMAL, entInfo, permissions, false);
    adminContainer_->SetAdminByUserId(DEFAULT_USER_ID, edmAdmin);
    std::vector<std::shared_ptr<Admin>> userAdmin;
    admin = adminContainer_->GetAdminCopyByUserId(DEFAULT_USER_ID, userAdmin);
    ASSERT_EQ(userAdmin.size(), 1);
    ASSERT_EQ(userAdmin[0]->adminInfo_.packageName_, bundleName);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS