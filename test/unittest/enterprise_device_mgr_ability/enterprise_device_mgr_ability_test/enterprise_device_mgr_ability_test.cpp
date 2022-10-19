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

#include <fcntl.h>
#include <gtest/gtest.h>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>
#include "cmd_utils.h"
#include "plugin_manager_test.h"
#include "edm_sys_manager_mock.h"
#include "bundle_manager_mock.h"
#include "system_ability_definition.h"
#define private public
#define protected public
#include "enterprise_device_mgr_ability.h"
#undef protected
#undef private

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
constexpr int32_t DEFAULT_USER_ID = 100;
constexpr int32_t ADMIN_TYPE_MAX = 999;
const std::string TEAR_DOWN_CMD = "rm /data/service/el1/public/edm/admin_policies*.json";
class EnterpriseDeviceMgrAbilityTest : public testing::Test {
protected:
    // Sets up the test fixture.
    void SetUp() override;

    // Tears down the test fixture.
    void TearDown() override;
    sptr<EnterpriseDeviceMgrAbility> edmMgr_;
    std::shared_ptr<EdmSysManager> edmSysManager_ = nullptr;
    int32_t TestDump();
};

int32_t EnterpriseDeviceMgrAbilityTest::TestDump()
{
    int32_t fd = open("/data/edmDumpTest.txt",
        O_RDWR | O_APPEND | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
    if (fd < 0) {
        GTEST_LOG_(INFO) << "mock EnterpriseDeviceMgrAbilityTest open fail!";
        return -1;
    }
    std::vector<std::u16string> args;
    int32_t res = edmMgr_->Dump(fd, args);
    close(fd);
    return res;
}

void EnterpriseDeviceMgrAbilityTest::SetUp()
{
    edmMgr_ = EnterpriseDeviceMgrAbility::GetInstance();
    edmMgr_->adminMgr_ = AdminManager::GetInstance();
    edmMgr_->policyMgr_ = PolicyManager::GetInstance();
    edmMgr_->pluginMgr_ = PluginManager::GetInstance();

    edmSysManager_ = std::make_shared<EdmSysManager>();
    sptr<IRemoteObject> object = new (std::nothrow) AppExecFwk::BundleMgrService();
    edmSysManager_->RegisterSystemAbilityOfRemoteObject(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID, object);
}

void EnterpriseDeviceMgrAbilityTest::TearDown()
{
    edmMgr_ = nullptr;
    edmSysManager_->UnregisterSystemAbilityOfRemoteObject(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
}

/**
 * @tc.name: TestGetAllPermissionsByAdminFail
 * @tc.desc: Test GetAllPermissionsByAdminFail func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestGetAllPermissionsByAdminFail, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo");
    admin.SetAbilityName("com.edm.test.demo.MainAbility");
    EntInfo entInfo("test", "this is test");

    ErrCode res = edmMgr_->EnableAdmin(admin, entInfo, AdminType::NORMAL, 0);
    EXPECT_TRUE(res == EdmReturnErrCode::COMPONENT_INVALID);
}

/**
 * @tc.name: TestBMSQueryExtensionAbilityInfos
 * @tc.desc: Test QueryExtensionAbilityInfos func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestBMSQueryExtensionAbilityInfos, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo");
    admin.SetAbilityName("com.edm.test.demo.MainAbility");
    EntInfo entInfo("test", "this is test");

    ErrCode res = edmMgr_->EnableAdmin(admin, entInfo, AdminType::NORMAL, 1);
    EXPECT_TRUE(res == EdmReturnErrCode::COMPONENT_INVALID);

    bool isEnable = edmMgr_->IsAdminEnabled(admin, DEFAULT_USER_ID);
    EXPECT_TRUE(isEnable == false);
}

/**
 * @tc.name: TestEnableAdmin22
 * @tc.desc: Test EnableAdmin com.edm.test.demo22 func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestEnableAdmin22, TestSize.Level1)
{
    PermissionManager::GetInstance()->AddPermission("ohos.permission.EDM_TEST_PERMISSION");
    PermissionManager::GetInstance()->AddPermission("ohos.permission.EDM_TEST_ENT_PERMISSION");
    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo22");
    admin.SetAbilityName("com.edm.test.demo.MainAbility");
    EntInfo entInfo("test", "this is test");

    ErrCode res = edmMgr_->EnableAdmin(admin, entInfo, AdminType::NORMAL, DEFAULT_USER_ID);
    EXPECT_TRUE(res == ERR_OK);

    bool isEnable = edmMgr_->IsAdminEnabled(admin, DEFAULT_USER_ID);
    EXPECT_TRUE(isEnable == false);

    res = edmMgr_->DisableAdmin(admin, DEFAULT_USER_ID);
    EXPECT_TRUE(res != ERR_OK);

    AppExecFwk::ElementName admin1;
    admin1.SetBundleName("");
    admin1.SetAbilityName("com.edm.test.demo.MainAbility");
    res = edmMgr_->DisableAdmin(admin1, DEFAULT_USER_ID);
    EXPECT_TRUE(res == ERR_OK);
}

/**
 * @tc.name: TestEnableAdmin2
 * @tc.desc: Test EnableAdmin com.edm.test.demo func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestEnableAdmin2, TestSize.Level1)
{
    PermissionManager::GetInstance()->AddPermission("ohos.permission.EDM_TEST_PERMISSION");
    PermissionManager::GetInstance()->AddPermission("ohos.permission.EDM_TEST_ENT_PERMISSION");
    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo");
    admin.SetAbilityName("com.edm.test.demo.MainAbility");
    EntInfo entInfo("test", "this is test");

    ErrCode res = edmMgr_->EnableAdmin(admin, entInfo, AdminType::NORMAL, DEFAULT_USER_ID);
    EXPECT_TRUE(res == ERR_OK);

    bool isEnable = edmMgr_->IsAdminEnabled(admin, DEFAULT_USER_ID);
    EXPECT_TRUE(isEnable == true);

    res = edmMgr_->DisableAdmin(admin, DEFAULT_USER_ID);
    EXPECT_TRUE(res == ERR_OK);
}

/**
 * @tc.name: TestEnableAdmin33
 * @tc.desc: Test EnableAdmin com.edm.test.demo33 func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestEnableAdmin33, TestSize.Level1)
{
    PermissionManager::GetInstance()->AddPermission("ohos.permission.EDM_TEST_PERMISSION");
    PermissionManager::GetInstance()->AddPermission("ohos.permission.EDM_TEST_ENT_PERMISSION");
    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo33");
    admin.SetAbilityName("com.edm.test.demo.MainAbility");
    EntInfo entInfo("test", "this is test");

    ErrCode res = edmMgr_->EnableAdmin(admin, entInfo, AdminType::NORMAL, DEFAULT_USER_ID);
    EXPECT_TRUE(res == ERR_OK);

    bool isEnable = edmMgr_->IsAdminEnabled(admin, DEFAULT_USER_ID);
    EXPECT_TRUE(isEnable == false);

    res = edmMgr_->DisableAdmin(admin, DEFAULT_USER_ID);
    EXPECT_TRUE(res != ERR_OK);

    AppExecFwk::ElementName admin1;
    admin1.SetBundleName("");
    admin1.SetAbilityName("com.edm.test.demo.MainAbility");
    res = edmMgr_->DisableAdmin(admin1, DEFAULT_USER_ID);
    EXPECT_TRUE(res == ERR_OK);
}

/**
 * @tc.name: TestEnableAdmin3
 * @tc.desc: Test EnableAdmin com.edm.test.demo11 func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestEnableAdmin3, TestSize.Level1)
{
    PermissionManager::GetInstance()->AddPermission("ohos.permission.EDM_TEST_PERMISSION");
    PermissionManager::GetInstance()->AddPermission("ohos.permission.EDM_TEST_ENT_PERMISSION");
    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo11");
    admin.SetAbilityName("com.edm.test.demo.MainAbility");
    EntInfo entInfo("test", "this is test");

    ErrCode res = edmMgr_->EnableAdmin(admin, entInfo, AdminType::NORMAL, DEFAULT_USER_ID);
    EXPECT_TRUE(res == ERR_OK);

    bool isEnable = edmMgr_->IsAdminEnabled(admin, DEFAULT_USER_ID);
    EXPECT_TRUE(isEnable == true);

    res = edmMgr_->DisableAdmin(admin, DEFAULT_USER_ID);
    EXPECT_TRUE(res == ERR_OK);
}

/**
 * @tc.name: TestEnableAdmin4
 * @tc.desc: Test EnableAdmin permission empty func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestEnableAdmin4, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.permission.empty");
    admin.SetAbilityName("com.edm.test.demo.MainAbility");
    EntInfo entInfo("test", "this is test");

    ErrCode res = edmMgr_->EnableAdmin(admin, entInfo, AdminType::NORMAL, DEFAULT_USER_ID);
    EXPECT_TRUE(res == ERR_OK);

    std::vector<std::string> enabledAdminList;
    edmMgr_->GetEnabledAdmin(AdminType::NORMAL, enabledAdminList); // normal admin not empty
    EXPECT_TRUE(enabledAdminList.empty() == false);

    bool isEnable = edmMgr_->IsAdminEnabled(admin, DEFAULT_USER_ID);
    EXPECT_TRUE(isEnable == true);

    std::string bundleName{"com.edm.test.permission.empty"};
    isEnable = edmMgr_->IsSuperAdmin(bundleName);
    EXPECT_TRUE(isEnable == false);

    res = edmMgr_->DisableAdmin(admin, DEFAULT_USER_ID);
    EXPECT_TRUE(res == ERR_OK);

    res = edmMgr_->DisableSuperAdmin(bundleName);
    EXPECT_TRUE(res != ERR_OK);
}

/**
 * @tc.name: TestDisableSuperAdmin22
 * @tc.desc: Test DisableSuperAdmin com.edm.test.demo22 func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestDisableSuperAdmin22, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo22");
    admin.SetAbilityName("com.edm.test.demo.MainAbility");
    EntInfo entInfo("test", "this is test");

    ErrCode res = edmMgr_->EnableAdmin(admin, entInfo, AdminType::ENT, DEFAULT_USER_ID);
    EXPECT_TRUE(res == ERR_OK);

    std::string bundleName{"com.edm.test.demo22"};
    bool isEnable = edmMgr_->IsSuperAdmin(bundleName); // admin is null
    EXPECT_TRUE(isEnable == false);

    res = edmMgr_->DisableSuperAdmin(bundleName);
    EXPECT_TRUE(res != ERR_OK);

    bundleName = "";
    res = edmMgr_->DisableSuperAdmin(bundleName);
    EXPECT_TRUE(res == ERR_OK);
}

/**
 * @tc.name: TestDisableSuperAdminTwoAdmin
 * @tc.desc: Test DisableSuperAdmin Two Admin func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestDisableSuperAdminTwoAdmin, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo");
    admin.SetAbilityName("com.edm.test.demo.MainAbility");
    EntInfo entInfo("test", "this is test");

    std::vector<std::u16string> args;
    ErrCode res = edmMgr_->Dump(-1, args);
    EXPECT_TRUE(res != ERR_OK);

    res = TestDump(); // empty
    EXPECT_TRUE(res == ERR_OK);

    res = edmMgr_->EnableAdmin(admin, entInfo, AdminType::ENT, DEFAULT_USER_ID);
    EXPECT_TRUE(res == ERR_OK);

    std::string bundleName{"com.edm.test.demo"};
    bool isEnable = edmMgr_->IsSuperAdmin(bundleName);
    EXPECT_TRUE(isEnable == true);

    res = TestDump(); // not empty
    EXPECT_TRUE(res == ERR_OK);
    CmdUtils::ExecCmdSync("rm -f /data/edmDumpTest.txt");

    // other admin
    AppExecFwk::ElementName admin1;
    admin1.SetBundleName("com.edm.test.demo11");
    admin1.SetAbilityName("com.edm.test.demo.MainAbility");
    EntInfo entInfo1("test", "this is test");

    res = edmMgr_->EnableAdmin(admin1, entInfo1, AdminType::NORMAL, DEFAULT_USER_ID);
    EXPECT_TRUE(res == ERR_OK);
    bundleName = "com.edm.test.demo11";
    res = edmMgr_->DisableSuperAdmin(bundleName);
    EXPECT_TRUE(res != ERR_OK);

    res = edmMgr_->DisableAdmin(admin1, DEFAULT_USER_ID);
    EXPECT_TRUE(res == ERR_OK);

    res = edmMgr_->DisableAdmin(admin, DEFAULT_USER_ID); // admintype is super
    EXPECT_TRUE(res != ERR_OK);

    bundleName = "com.edm.test.demo";
    res = edmMgr_->DisableSuperAdmin(bundleName); // FAILS
    EXPECT_TRUE(res != ERR_OK);
}

/**
 * @tc.name: TestDisableSuperAdmin
 * @tc.desc: Test DisableSuperAdmin fail func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestDisableSuperAdmin, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo");
    admin.SetAbilityName("com.edm.test.demo.MainAbility");
    EntInfo entInfo("test", "this is test");

    ErrCode res = edmMgr_->EnableAdmin(admin, entInfo, AdminType::ENT, DEFAULT_USER_ID);
    EXPECT_TRUE(res == ERR_OK);

    std::string bundleName{"com.edm.test.demo"};
    bool isEnable = edmMgr_->IsSuperAdmin(bundleName);
    EXPECT_TRUE(isEnable == true);

    res = edmMgr_->DisableSuperAdmin(bundleName); // FAILS
    EXPECT_TRUE(res != ERR_OK);

    // the same edmMgr_->adminMgr_ two super admin
    res = edmMgr_->adminMgr_->DeleteAdmin(bundleName, DEFAULT_USER_ID);
    EXPECT_TRUE(res == ERR_OK);
}

/**
 * @tc.name: TestDisableSuperAdminIpcSuc
 * @tc.desc: Test DisableSuperAdmin Ipc Suc func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestDisableSuperAdminIpcSuc, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo.ipc.suc");
    admin.SetAbilityName("com.edm.test.demo.MainAbility");
    EntInfo entInfo("test", "this is test");

    ErrCode res = edmMgr_->EnableAdmin(admin, entInfo, AdminType::ENT, DEFAULT_USER_ID);
    EXPECT_TRUE(res == ERR_OK);

    std::string bundleName{"com.edm.test.demo.ipc.suc"};
    bool isEnable = edmMgr_->IsSuperAdmin(bundleName);
    EXPECT_TRUE(isEnable == true);

    res = edmMgr_->DisableSuperAdmin(bundleName);
    EXPECT_TRUE(res == ERR_OK);
}

/**
 * @tc.name: TestDisableSuperAdminIpcFail
 * @tc.desc: Test DisableSuperAdmin Ipc Fail func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestDisableSuperAdminIpcFail, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo.ipc.fail");
    admin.SetAbilityName("com.edm.test.demo.MainAbility");
    EntInfo entInfo("test", "this is test");

    ErrCode res = edmMgr_->EnableAdmin(admin, entInfo, AdminType::ENT, DEFAULT_USER_ID);
    EXPECT_TRUE(res == ERR_OK);

    std::string bundleName{"com.edm.test.demo.ipc.fail"};
    bool isEnable = edmMgr_->IsSuperAdmin(bundleName);
    EXPECT_TRUE(isEnable == true);

    res = edmMgr_->DisableSuperAdmin(bundleName);
    EXPECT_TRUE(res != ERR_OK);

    // the same edmMgr_->adminMgr_ two super admin
    res = edmMgr_->adminMgr_->DeleteAdmin(bundleName, DEFAULT_USER_ID);
    EXPECT_TRUE(res == ERR_OK);
}

/**
 * @tc.name: TestSetEnterpriseInfo
 * @tc.desc: Test SetEnterpriseInfo func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestSetEnterpriseInfo, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo.ipc.suc"); // com.edm.test.demo
    admin.SetAbilityName("com.edm.test.demo.MainAbility");
    EntInfo entInfo("test", "this is test");

    MessageParcel reply;
    ErrCode res = edmMgr_->GetEnterpriseInfo(admin, reply);
    EXPECT_TRUE(res != ERR_OK);

    EntInfo entInfo1("test1", "this is test1");
    res = edmMgr_->SetEnterpriseInfo(admin, entInfo1);
    EXPECT_TRUE(res != ERR_OK);

    res = edmMgr_->EnableAdmin(admin, entInfo, AdminType::ENT, DEFAULT_USER_ID);
    EXPECT_TRUE(res == ERR_OK);

    res = edmMgr_->GetEnterpriseInfo(admin, reply);
    EXPECT_TRUE(res == ERR_OK);

    res = edmMgr_->SetEnterpriseInfo(admin, entInfo1);
    EXPECT_TRUE(res == ERR_OK);

    std::vector<std::string> enabledAdminList;
    edmMgr_->GetEnabledAdmin(AdminType::NORMAL, enabledAdminList);
    EXPECT_TRUE(enabledAdminList.empty() == false);

    enabledAdminList.clear();
    edmMgr_->GetEnabledAdmin(AdminType::ENT, enabledAdminList);
    EXPECT_TRUE(enabledAdminList.empty() == false);

    enabledAdminList.clear();
    edmMgr_->GetEnabledAdmin(AdminType::UNKNOWN, enabledAdminList);
    EXPECT_TRUE(enabledAdminList.empty() == true);

    enabledAdminList.clear();
    res = edmMgr_->GetEnabledAdmin(static_cast<AdminType>(ADMIN_TYPE_MAX), enabledAdminList);
    EXPECT_TRUE(res != ERR_OK);

    std::string bundleName{"com.edm.test.demo.ipc.suc"};
    res = edmMgr_->DisableSuperAdmin(bundleName);
    EXPECT_TRUE(res == ERR_OK);
}

/**
 * @tc.name: TestSetEnterpriseInfoNoSame
 * @tc.desc: Test SetEnterpriseInfo No Same func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestSetEnterpriseInfoNoSame, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo"); // com.edm.test.demo
    admin.SetAbilityName("com.edm.test.demo.MainAbility");
    EntInfo entInfo("test", "this is test");

    ErrCode res = edmMgr_->EnableAdmin(admin, entInfo, AdminType::ENT, DEFAULT_USER_ID);
    EXPECT_TRUE(res == ERR_OK);

    MessageParcel reply;
    res = edmMgr_->GetEnterpriseInfo(admin, reply);
    EXPECT_TRUE(res == ERR_OK);

    EntInfo entInfo1("test1", "this is test1");
    res = edmMgr_->SetEnterpriseInfo(admin, entInfo1);
    EXPECT_TRUE(res != ERR_OK);

    std::vector<std::string> enabledAdminList;
    edmMgr_->GetEnabledAdmin(AdminType::NORMAL, enabledAdminList);
    EXPECT_TRUE(enabledAdminList.empty() == false);

    enabledAdminList.clear();
    edmMgr_->GetEnabledAdmin(AdminType::ENT, enabledAdminList);
    EXPECT_TRUE(enabledAdminList.empty() == false);

    enabledAdminList.clear();
    edmMgr_->GetEnabledAdmin(AdminType::UNKNOWN, enabledAdminList);
    EXPECT_TRUE(enabledAdminList.empty() == true);

    enabledAdminList.clear();
    res = edmMgr_->GetEnabledAdmin(static_cast<AdminType>(ADMIN_TYPE_MAX), enabledAdminList);
    EXPECT_TRUE(res != ERR_OK);

    std::string bundleName{"com.edm.test.demo"};
    res = edmMgr_->DisableSuperAdmin(bundleName);
    EXPECT_TRUE(res != ERR_OK);

    std::shared_ptr<AdminManager> adminMgr1 = std::make_shared<AdminManager>();
    adminMgr1->Init();
    auto ptr = adminMgr1->GetAdminByPkgName(bundleName, DEFAULT_USER_ID);
    EXPECT_TRUE(ptr != nullptr);

    // the same edmMgr_->adminMgr_ two super admin
    res = edmMgr_->adminMgr_->DeleteAdmin(bundleName, DEFAULT_USER_ID);
    EXPECT_TRUE(res == ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
