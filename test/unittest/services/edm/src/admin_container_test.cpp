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
#define private public
#include "admin_container_test.h"
#undef private
#include <vector>
 
#include "admin_container.h"
 
using namespace testing::ext;
 
namespace OHOS {
namespace EDM {
namespace TEST {
constexpr int32_t DEFAULT_USER_ID = 100;
constexpr int32_t TEST_USER_ID = 101;
 
void AdminContainerTest::SetUp()
{
    adminContainer_ = AdminContainer::GetInstance();
    std::unordered_map<int32_t, std::vector<AdminInfo>> admins;
    adminContainer_->InitAdmins(admins);
    adminContainer_->ClearAdmins();
}

void AdminContainerTest::TearDown()
{
    std::vector<std::shared_ptr<Admin>> userAdmin;
    adminContainer_->GetAdminCopyByUserId(DEFAULT_USER_ID, userAdmin);
    for (const auto &admin : userAdmin) {
        adminContainer_->DeleteAdmin(admin->adminInfo_.packageName_, DEFAULT_USER_ID);
    }
    adminContainer_->GetAdminCopyByUserId(TEST_USER_ID, userAdmin);
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
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "technology company in wuhan";
    permissions = {"ohos.permission.EDM_TEST_PERMISSION"};
    AdminInfo adminInfo = {.packageName_ = "com.edm.test.demo", .className_ = "testDemo", .entInfo_ = entInfo,
        .permission_ = permissions, .adminType_ = AdminType::NORMAL, .isDebug_ = false};
    adminContainer_->SetAdminByUserId(DEFAULT_USER_ID, adminInfo);
    adminContainer_->GetAdminByUserId(DEFAULT_USER_ID, userAdmin);
    ASSERT_TRUE(userAdmin.size() == 1);

    adminInfo.adminType_ = AdminType::ENT;
    adminInfo.packageName_ = "com.edm.test.demo1";
    adminInfo.permission_ = {"ohos.permission.EDM_TEST_PERMISSION", "ohos.permission.EDM_TEST_ENT_PERMISSION"};
    adminContainer_->SetAdminByUserId(DEFAULT_USER_ID, adminInfo);
    adminContainer_->GetAdminByUserId(DEFAULT_USER_ID, userAdmin);
    ASSERT_TRUE(userAdmin.size() == 2);
}

/**
 * @tc.name: TestGetAdminCopyBySubscribeEvent
 * @tc.desc: Test AdminContainer::GetAdminCopyBySubscribeEvent function.
 * @tc.type: FUNC
 */
HWTEST_F(AdminContainerTest, TestGetAdminCopyBySubscribeEvent, TestSize.Level1)
{
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "technology company in wuhan";
    std::vector<std::string> permissions = {"ohos.permission.EDM_TEST_PERMISSION"};
    AdminInfo adminInfo = {.packageName_ = "com.edm.test.demo", .className_ = "testDemo", .entInfo_ = entInfo,
        .permission_ = permissions, .adminType_ = AdminType::NORMAL, .isDebug_ = false};
    adminInfo.managedEvents_ = {ManagedEvent::BUNDLE_ADDED, ManagedEvent::BUNDLE_REMOVED};
    adminContainer_->SetAdminByUserId(DEFAULT_USER_ID, adminInfo);

    adminInfo.packageName_ = "com.edm.test.demo1";
    adminInfo.className_ = "testDemo1";
    adminInfo.entInfo_.enterpriseName = "company1";
    adminInfo.entInfo_.description = "technology company in wuhan1";
    adminInfo.managedEvents_ = {};
    adminContainer_->SetAdminByUserId(DEFAULT_USER_ID, adminInfo);

    adminInfo.packageName_ = "com.edm.test.demo2";
    adminInfo.className_ = "testDemo2";
    adminInfo.entInfo_.enterpriseName = "company2";
    adminInfo.entInfo_.description = "technology company in wuhan2";
    adminInfo.managedEvents_ = {ManagedEvent::BUNDLE_REMOVED};
    adminContainer_->SetAdminByUserId(TEST_USER_ID, adminInfo);

    std::unordered_map<int32_t, std::vector<std::shared_ptr<Admin>>> subscribeAdmins;
    adminContainer_->GetAdminCopyBySubscribeEvent(ManagedEvent::BUNDLE_ADDED, subscribeAdmins);
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

    EntInfo entInfo1;
    entInfo1.enterpriseName = "company1";
    entInfo1.description = "technology company in wuhan";
    std::vector<std::string> permissions = {"ohos.permission.EDM_TEST_PERMISSION"};

    AdminInfo edmAdminInfo;
    edmAdminInfo.packageName_ = bundleName;
    edmAdminInfo.className_ = className;
    edmAdminInfo.entInfo_ = entInfo1;
    edmAdminInfo.permission_= permissions;
    edmAdminInfo.managedEvents_ = {ManagedEvent::BUNDLE_REMOVED};
    edmAdminInfo.parentAdminName_ = "com.edm.test.demo1";
    edmAdminInfo.accessiblePolicies_ = {"ploicy1"};
    edmAdminInfo.adminType_ = AdminType::ENT;
    edmAdminInfo.runningMode_ = RunningMode::DEFAULT;
    adminContainer_->SetAdminByUserId(DEFAULT_USER_ID, edmAdminInfo);

    EntInfo entInfo2;
    entInfo2.enterpriseName = "company2";
    entInfo2.description = "technology company in xian";
    permissions = {"ohos.permission.EDM_TEST_PERMISSION_FAIL"};

    AdminInfo updateAdminInfo;
    updateAdminInfo.packageName_ = bundleName;
    updateAdminInfo.className_ = className;
    updateAdminInfo.entInfo_ = entInfo2;
    updateAdminInfo.permission_= permissions;
    updateAdminInfo.managedEvents_ = {ManagedEvent::BUNDLE_ADDED};
    updateAdminInfo.parentAdminName_ = "com.edm.test.demo2";
    updateAdminInfo.accessiblePolicies_ = {"ploicy2"};
    updateAdminInfo.adminType_ = AdminType::NORMAL;
    updateAdminInfo.runningMode_ = RunningMode::MULTI_USER;

    adminContainer_->UpdateAdmin(DEFAULT_USER_ID, bundleName, CLASS_NAME | ENTI_NFO | PERMISSION | MANAGED_EVENTS |
        PARENT_ADMIN_NAME | ACCESSIBLE_POLICIES | ADMIN_TYPE | IS_DEBUG | RUNNING_MODE, updateAdminInfo);

    std::vector<std::shared_ptr<Admin>> userAdmin;
    adminContainer_->GetAdminCopyByUserId(DEFAULT_USER_ID, userAdmin);
    ASSERT_TRUE(userAdmin.size() == 1);
    std::shared_ptr<Admin> admin = userAdmin.at(0);

    ASSERT_EQ(admin->adminInfo_.className_, updateAdminInfo.className_);
    ASSERT_EQ(admin->adminInfo_.entInfo_.description, updateAdminInfo.entInfo_.description);
    ASSERT_EQ(admin->adminInfo_.entInfo_.enterpriseName, updateAdminInfo.entInfo_.enterpriseName);
    ASSERT_EQ(admin->adminInfo_.permission_[0], updateAdminInfo.permission_[0]);
    ASSERT_EQ(admin->adminInfo_.managedEvents_[0], updateAdminInfo.managedEvents_[0]);
    ASSERT_EQ(admin->adminInfo_.parentAdminName_, updateAdminInfo.parentAdminName_);
    ASSERT_EQ(admin->adminInfo_.accessiblePolicies_, updateAdminInfo.accessiblePolicies_);
    ASSERT_EQ(admin->adminInfo_.adminType_, updateAdminInfo.adminType_);
    ASSERT_EQ(admin->adminInfo_.runningMode_, updateAdminInfo.runningMode_);
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
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "technology company in wuhan";
    permissions = {"ohos.permission.EDM_TEST_PERMISSION"};
    AdminInfo adminInfo = {.packageName_ = "com.edm.test.demo", .className_ = "testDemo", .entInfo_ = entInfo,
        .permission_ = permissions, .adminType_ = AdminType::NORMAL, .isDebug_ = false};
    adminContainer_->SetAdminByUserId(DEFAULT_USER_ID, adminInfo);

    adminInfo.adminType_ = AdminType::ENT;
    adminInfo.packageName_ = "com.edm.test.demo1";
    adminInfo.permission_ = {"ohos.permission.EDM_TEST_PERMISSION",
        "ohos.permission.EDM_TEST_ENT_PERMISSION"};
    adminContainer_->SetAdminByUserId(DEFAULT_USER_ID, adminInfo);

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
    std::string bundleName = "com.edm.test.demo";
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "technology company in wuhan";
    std::vector<std::string> permissions {"ohos.permission.EDM_TEST_ENT_PERMISSION"};
    AdminInfo adminInfo = {.packageName_ = "com.edm.test.demo", .className_ = "testDemo", .entInfo_ = entInfo,
        .permission_ = permissions, .adminType_ = AdminType::NORMAL, .isDebug_ = false};
    adminContainer_->SetAdminByUserId(DEFAULT_USER_ID, adminInfo);
    std::vector<std::shared_ptr<Admin>> userAdmin;
    adminContainer_->GetAdminCopyByUserId(DEFAULT_USER_ID, userAdmin);
    ASSERT_EQ(userAdmin.size(), 1);
    ASSERT_EQ(userAdmin[0]->adminInfo_.packageName_, bundleName);
}

/**
 * @tc.name: TestSetAdminByUserIdWithWrongAdminType
 * @tc.desc: Test AdminContainer::SetAdminByUserId function.
 * @tc.type: FUNC
 */
HWTEST_F(AdminContainerTest, TestSetAdminByUserIdWithWrongAdminType, TestSize.Level0)
{
    std::shared_ptr<Admin> admin;
    std::string bundleName = "com.edm.test.demo";
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "technology company in wuhan";
    std::vector<std::string> permissions {"ohos.permission.EDM_TEST_ENT_PERMISSION"};
    AdminInfo adminInfo = {.packageName_ = "com.edm.test.demo", .className_ = "testDemo", .entInfo_ = entInfo,
        .permission_ = permissions, .adminType_ = AdminType::UNKNOWN, .isDebug_ = false};
    adminContainer_->SetAdminByUserId(DEFAULT_USER_ID, adminInfo);
    std::vector<std::shared_ptr<Admin>> userAdmin;
    adminContainer_->GetAdminCopyByUserId(DEFAULT_USER_ID, userAdmin);
    ASSERT_EQ(userAdmin.size(), 0);
}

/**
 * @tc.name: TestDeleteAdminFailed
 * @tc.desc: Test AdminContainer::DeleteAdmin function.
 * @tc.type: FUNC
 */
HWTEST_F(AdminContainerTest, TestDeleteAdminFailed, TestSize.Level0)
{
    std::string bundleName = "com.edm.test.demo";
    bool ret = adminContainer_->DeleteAdmin(bundleName, DEFAULT_USER_ID);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: TestIsExistTargetAdmin
 * @tc.desc: Test AdminContainer::IsExistTargetAdmin function.
 * @tc.type: FUNC
 */
HWTEST_F(AdminContainerTest, TestIsExistTargetAdmin, TestSize.Level0)
{
    std::string bundleName = "com.edm.test.demo";
    bool ret = adminContainer_->IsExistTargetAdmin(true);
    EXPECT_FALSE(ret);

    AdminInfo adminInfo = {.packageName_ = bundleName, .adminType_ = AdminType::ENT, .isDebug_ = true};
    adminContainer_->SetAdminByUserId(DEFAULT_USER_ID, adminInfo);
    ret = adminContainer_->IsExistTargetAdmin(false);
    EXPECT_FALSE(ret);

    ret = adminContainer_->IsExistTargetAdmin(true);
    EXPECT_TRUE(ret);

    EXPECT_TRUE(adminContainer_->DeleteAdmin(bundleName, DEFAULT_USER_ID));
}

/**
 * @tc.name: TestGetSuperDeviceAdminAndDeviceAdminCount
 * @tc.desc: Test AdminContainer::GetSuperDeviceAdminAndDeviceAdminCount function.
 * @tc.type: FUNC
 */
HWTEST_F(AdminContainerTest, TestGetSuperDeviceAdminAndDeviceAdminCount, TestSize.Level0)
{
    int32_t ret = adminContainer_->GetSuperDeviceAdminAndDeviceAdminCount();
    EXPECT_EQ(ret, 0);

    AdminInfo adminInfo = {.packageName_ = "com.edm.test.demo", .adminType_ = AdminType::ENT, .isDebug_ = false};
    adminContainer_->SetAdminByUserId(DEFAULT_USER_ID, adminInfo);
    AdminInfo adminInfo1 = {.packageName_ = "com.edm.test.demo1", .adminType_ = AdminType::NORMAL, .isDebug_ = false};
    adminContainer_->SetAdminByUserId(DEFAULT_USER_ID, adminInfo1);
    AdminInfo adminInfo2 = {.packageName_ = "com.edm.test.demo2", .adminType_ = AdminType::BYOD, .isDebug_ = false};
    adminContainer_->SetAdminByUserId(DEFAULT_USER_ID, adminInfo2);

    ret = adminContainer_->GetSuperDeviceAdminAndDeviceAdminCount();
    EXPECT_EQ(ret, 2);

    EXPECT_TRUE(adminContainer_->DeleteAdmin("com.edm.test.demo", DEFAULT_USER_ID));
    EXPECT_TRUE(adminContainer_->DeleteAdmin("com.edm.test.demo1", DEFAULT_USER_ID));
    EXPECT_TRUE(adminContainer_->DeleteAdmin("com.edm.test.demo2", DEFAULT_USER_ID));
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS