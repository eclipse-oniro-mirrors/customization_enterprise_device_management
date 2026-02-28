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

#define private public
#define protected public
#include "admin_container.h"
#include "enterprise_device_mgr_ability.h"
#include "plugin_manager.h"
#undef protected
#undef private

#include "update_policy_conflict_test.h"

#include <string>
#include <vector>

#include "external_module_adapter_mock.h"
#include "update_policy_utils.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
constexpr int32_t TEST_SLEEP_TIME = 5;
const std::string ADMIN_PACKAGENAME = "com.edm.test";
const std::string ADMIN_PACKAGENAME_1 = "com.edm.test_1";


void UpdatePolicyConflictTest::SetUp()
{
    bundleMgrMock_ = std::make_shared<EdmBundleManagerImplMock>();
    osAccountMgrMock_ = std::make_shared<EdmOsAccountManagerImplMock>();
    accessTokenMgrMock_ = std::make_shared<EdmAccessTokenManagerImplMock>();
    factoryMock_ = std::make_shared<ExternalManagerFactoryMock>();
    permissionCheckerMock_ = std::make_shared<PermissionCheckerMock>();
    edmMgr_ = new (std::nothrow) EnterpriseDeviceMgrAbilityMock();
    edmMgr_->adminMgr_ = AdminManager::GetInstance();
    edmMgr_->policyMgr_ = PolicyManager::GetInstance();
    EXPECT_CALL(*edmMgr_, GetExternalManagerFactory).WillRepeatedly(DoAll(Return(factoryMock_)));
    EXPECT_CALL(*edmMgr_, GetPermissionChecker).WillRepeatedly(DoAll(Return(permissionCheckerMock_)));
    EXPECT_CALL(*permissionCheckerMock_, GetExternalManagerFactory).WillRepeatedly(DoAll(Return(factoryMock_)));
    EXPECT_CALL(*factoryMock_, CreateBundleManager).WillRepeatedly(DoAll(Return(bundleMgrMock_)));
    EXPECT_CALL(*factoryMock_, CreateOsAccountManager).WillRepeatedly(DoAll(Return(osAccountMgrMock_)));
    EXPECT_CALL(*factoryMock_, CreateAccessTokenManager).WillRepeatedly(DoAll(Return(accessTokenMgrMock_)));
}

void UpdatePolicyConflictTest::TearDown()
{
    edmMgr_->adminMgr_->ClearAdmins();
    edmMgr_->policyMgr_.reset();
    edmMgr_->instance_.clear();
    edmMgr_.clear();
}

void UpdatePolicyConflictTest::SetUpTestSuite()
{
}

void UpdatePolicyConflictTest::TearDownTestSuite()
{
    PluginManager::GetInstance()->NotifyUnloadAllPlugin();
    std::this_thread::sleep_for(std::chrono::seconds(TEST_SLEEP_TIME));
}

AdminInfo UpdatePolicyConflictTest::CreateAdminInfo(AdminType adminType, const std::string &bundleName)
{
    AdminInfo adminInfo;
    adminInfo.adminType_ = adminType;
    adminInfo.packageName_ = bundleName;
    adminInfo.permission_ = {EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SYSTEM};
    if (adminType == AdminType::VIRTUAL_ADMIN) {
        adminInfo.accessiblePolicies_ = {
            PolicyName::POLICY_SET_UPDATE_POLICY, PolicyName::POLICY_NOTIFY_UPGRADE_PACKAGES};
    }
    return adminInfo;
}

void UpdatePolicyConflictTest::TestSetUpdatePolicy(std::shared_ptr<Admin> admin, UpdatePolicyType updatePolicyType,
    ErrCode expectedRet)
{
    std::string bundleName = admin->adminInfo_.packageName_;
    std::vector<int32_t> ids = {DEFAULT_USER_ID};
    EXPECT_CALL(*osAccountMgrMock_, IsOsAccountExists).WillOnce(DoAll(SetArgReferee<1>(true), Return(ERR_OK)));
    EXPECT_CALL(*osAccountMgrMock_, QueryActiveOsAccountIds).WillRepeatedly(DoAll(SetArgReferee<0>(ids),
        Return(ERR_OK)));
    EXPECT_CALL(*bundleMgrMock_, GetNameForUid).WillOnce(DoAll(SetArgReferee<1>(bundleName), Return(ERR_OK)));
    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillOnce(DoAll(Return(true)));
    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission(_, StrEq(EdmPermission::PERMISSION_MANAGE_EDM_POLICY)))
        .WillOnce(Return(false));

    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::SET_OTA_UPDATE_POLICY);
    auto plugin = PluginManager::GetInstance()->GetPluginByFuncCode(code);
    if (admin->HasPermissionToHandlePolicy(PolicyName::POLICY_SET_UPDATE_POLICY, FuncOperateType::SET)) {
        if (plugin && plugin->extensionPlugin_) {
            auto externalModuleAdapterMock = std::make_shared<ExternalModuleAdapterMock>();
            plugin->extensionPlugin_->externalModuleAdapter_ = externalModuleAdapterMock;
            EXPECT_CALL(*externalModuleAdapterMock, GetCallingBundleName).WillOnce(DoAll(Return(bundleName)));
            if (expectedRet != EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED) {
                EXPECT_CALL(*externalModuleAdapterMock, SetUpdatePolicy).WillOnce(DoAll(Return(ERR_OK)));
            }
        }
    }

    AppExecFwk::ElementName elementName;
    elementName.SetBundleName(bundleName);
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("");
    UpdatePolicy updatePolicy;
    updatePolicy.type = updatePolicyType;
    UpdatePolicyUtils::WriteUpdatePolicy(data, updatePolicy);
    ErrCode res = edmMgr_->HandleDevicePolicy(code, elementName, data, reply, DEFAULT_USER_ID);
    if (!admin->HasPermissionToHandlePolicy(PolicyName::POLICY_SET_UPDATE_POLICY, FuncOperateType::SET)) {
        EXPECT_EQ(res, EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED);
    } else if ((!plugin || !plugin->extensionPlugin_)) {
        EXPECT_EQ(res, EdmReturnErrCode::INTERFACE_UNSUPPORTED);
    } else {
        EXPECT_EQ(res, expectedRet);
    }
}

void UpdatePolicyConflictTest::TestNotifyUpgradePackages(std::shared_ptr<Admin> admin, ErrCode expectedRet)
{
    std::string bundleName = admin->adminInfo_.packageName_;
    std::vector<int32_t> ids = {DEFAULT_USER_ID};
    EXPECT_CALL(*osAccountMgrMock_, IsOsAccountExists).WillOnce(DoAll(SetArgReferee<1>(true), Return(ERR_OK)));
    EXPECT_CALL(*osAccountMgrMock_, QueryActiveOsAccountIds).WillRepeatedly(DoAll(SetArgReferee<0>(ids),
        Return(ERR_OK)));
    EXPECT_CALL(*bundleMgrMock_, GetNameForUid).WillOnce(DoAll(SetArgReferee<1>(bundleName), Return(ERR_OK)));
    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillOnce(DoAll(Return(true)));
    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission(_, StrEq(EdmPermission::PERMISSION_MANAGE_EDM_POLICY)))
        .WillOnce(Return(false));

    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::NOTIFY_UPGRADE_PACKAGES);
    auto plugin = PluginManager::GetInstance()->GetPluginByFuncCode(code);
    if (admin->HasPermissionToHandlePolicy(PolicyName::POLICY_NOTIFY_UPGRADE_PACKAGES, FuncOperateType::SET)) {
        if (plugin && plugin->extensionPlugin_) {
            auto externalModuleAdapterMock = std::make_shared<ExternalModuleAdapterMock>();
            plugin->extensionPlugin_->externalModuleAdapter_ = externalModuleAdapterMock;
            EXPECT_CALL(*externalModuleAdapterMock, GetCallingBundleName).WillOnce(DoAll(Return(bundleName)));
            if (expectedRet != EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED) {
                EXPECT_CALL(*externalModuleAdapterMock, NotifyUpgradePackages).WillOnce(DoAll(Return(ERR_OK)));
            }
        }
    }

    AppExecFwk::ElementName elementName;
    elementName.SetBundleName(bundleName);
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("");
    UpgradePackageInfo packageInfo;
    Package package;
    packageInfo.packages = {package};
    UpdatePolicyUtils::WriteUpgradePackageInfo(data, packageInfo);
    ErrCode res = edmMgr_->HandleDevicePolicy(code, elementName, data, reply, DEFAULT_USER_ID);
    if (!admin->HasPermissionToHandlePolicy(PolicyName::POLICY_NOTIFY_UPGRADE_PACKAGES, FuncOperateType::SET)) {
        EXPECT_EQ(res, EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED);
    } else if ((!plugin || !plugin->extensionPlugin_)) {
        EXPECT_EQ(res, EdmReturnErrCode::INTERFACE_UNSUPPORTED);
    } else {
        EXPECT_EQ(res, expectedRet);
    }
}

INSTANTIATE_TEST_CASE_P(TestWithParam, UpdatePolicyConflictTest,
    testing::ValuesIn(std::vector<UpdatePolicyTestParam>(
{
    // update policy != DEFAULT
    UpdatePolicyTestParam(AdminType::ENT, UpdatePolicyType::PROHIBIT, false,
        AdminType::ENT, TestMethod::SET_UPDATE_POLICY, ERR_OK),
    UpdatePolicyTestParam(AdminType::ENT, UpdatePolicyType::PROHIBIT, false,
        AdminType::SUB_SUPER_ADMIN, TestMethod::SET_UPDATE_POLICY, ERR_OK),
    UpdatePolicyTestParam(AdminType::ENT, UpdatePolicyType::PROHIBIT, false,
        AdminType::VIRTUAL_ADMIN, TestMethod::SET_UPDATE_POLICY, ERR_OK),
    UpdatePolicyTestParam(AdminType::ENT, UpdatePolicyType::PROHIBIT, false,
        AdminType::NORMAL, TestMethod::SET_UPDATE_POLICY, EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED),

    UpdatePolicyTestParam(AdminType::SUB_SUPER_ADMIN, UpdatePolicyType::PROHIBIT, false,
        AdminType::ENT, TestMethod::SET_UPDATE_POLICY, ERR_OK),
    UpdatePolicyTestParam(AdminType::SUB_SUPER_ADMIN, UpdatePolicyType::PROHIBIT, false,
        AdminType::SUB_SUPER_ADMIN, TestMethod::SET_UPDATE_POLICY, ERR_OK),
    UpdatePolicyTestParam(AdminType::SUB_SUPER_ADMIN, UpdatePolicyType::PROHIBIT, false,
        AdminType::VIRTUAL_ADMIN, TestMethod::SET_UPDATE_POLICY, ERR_OK),
    UpdatePolicyTestParam(AdminType::SUB_SUPER_ADMIN, UpdatePolicyType::PROHIBIT, false,
        AdminType::NORMAL, TestMethod::SET_UPDATE_POLICY, EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED),

    UpdatePolicyTestParam(AdminType::VIRTUAL_ADMIN, UpdatePolicyType::PROHIBIT, false,
        AdminType::ENT, TestMethod::SET_UPDATE_POLICY, ERR_OK),
    UpdatePolicyTestParam(AdminType::VIRTUAL_ADMIN, UpdatePolicyType::PROHIBIT, false,
        AdminType::SUB_SUPER_ADMIN, TestMethod::SET_UPDATE_POLICY, ERR_OK),
    UpdatePolicyTestParam(AdminType::VIRTUAL_ADMIN, UpdatePolicyType::PROHIBIT, false,
        AdminType::VIRTUAL_ADMIN, TestMethod::SET_UPDATE_POLICY, ERR_OK),
    UpdatePolicyTestParam(AdminType::VIRTUAL_ADMIN, UpdatePolicyType::PROHIBIT, false,
        AdminType::NORMAL, TestMethod::SET_UPDATE_POLICY, EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED),
#ifdef FEATURE_PC_ONLY
    UpdatePolicyTestParam(AdminType::NORMAL, UpdatePolicyType::PROHIBIT, false,
        AdminType::ENT, TestMethod::SET_UPDATE_POLICY, EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED),
    UpdatePolicyTestParam(AdminType::NORMAL, UpdatePolicyType::PROHIBIT, false,
        AdminType::SUB_SUPER_ADMIN, TestMethod::SET_UPDATE_POLICY, EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED),
    UpdatePolicyTestParam(AdminType::NORMAL, UpdatePolicyType::PROHIBIT, false,
        AdminType::VIRTUAL_ADMIN, TestMethod::SET_UPDATE_POLICY, EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED),
    UpdatePolicyTestParam(AdminType::NORMAL, UpdatePolicyType::PROHIBIT, false,
        AdminType::NORMAL, TestMethod::SET_UPDATE_POLICY, EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED),
#else
    UpdatePolicyTestParam(AdminType::NORMAL, UpdatePolicyType::PROHIBIT, false,
        AdminType::ENT, TestMethod::SET_UPDATE_POLICY, ERR_OK),
    UpdatePolicyTestParam(AdminType::NORMAL, UpdatePolicyType::PROHIBIT, false,
        AdminType::SUB_SUPER_ADMIN, TestMethod::SET_UPDATE_POLICY, ERR_OK),
    UpdatePolicyTestParam(AdminType::NORMAL, UpdatePolicyType::PROHIBIT, false,
        AdminType::VIRTUAL_ADMIN, TestMethod::SET_UPDATE_POLICY, ERR_OK),
    UpdatePolicyTestParam(AdminType::NORMAL, UpdatePolicyType::PROHIBIT, false,
        AdminType::NORMAL, TestMethod::SET_UPDATE_POLICY, EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED),
#endif
    // update policy == DEFAULT, but not notify
    UpdatePolicyTestParam(AdminType::ENT, UpdatePolicyType::DEFAULT, false,
        AdminType::ENT, TestMethod::SET_UPDATE_POLICY, ERR_OK),
    UpdatePolicyTestParam(AdminType::ENT, UpdatePolicyType::DEFAULT, false,
        AdminType::SUB_SUPER_ADMIN, TestMethod::SET_UPDATE_POLICY, ERR_OK),
    UpdatePolicyTestParam(AdminType::ENT, UpdatePolicyType::DEFAULT, false,
        AdminType::VIRTUAL_ADMIN, TestMethod::SET_UPDATE_POLICY, ERR_OK),
    UpdatePolicyTestParam(AdminType::ENT, UpdatePolicyType::DEFAULT, false,
        AdminType::NORMAL, TestMethod::SET_UPDATE_POLICY, ERR_OK),

    UpdatePolicyTestParam(AdminType::SUB_SUPER_ADMIN, UpdatePolicyType::DEFAULT, false,
        AdminType::ENT, TestMethod::SET_UPDATE_POLICY, ERR_OK),
    UpdatePolicyTestParam(AdminType::SUB_SUPER_ADMIN, UpdatePolicyType::DEFAULT, false,
        AdminType::SUB_SUPER_ADMIN, TestMethod::SET_UPDATE_POLICY, ERR_OK),
    UpdatePolicyTestParam(AdminType::SUB_SUPER_ADMIN, UpdatePolicyType::DEFAULT, false,
        AdminType::VIRTUAL_ADMIN, TestMethod::SET_UPDATE_POLICY, ERR_OK),
    UpdatePolicyTestParam(AdminType::SUB_SUPER_ADMIN, UpdatePolicyType::DEFAULT, false,
        AdminType::NORMAL, TestMethod::SET_UPDATE_POLICY, ERR_OK),

    UpdatePolicyTestParam(AdminType::VIRTUAL_ADMIN, UpdatePolicyType::DEFAULT, false,
        AdminType::ENT, TestMethod::SET_UPDATE_POLICY, ERR_OK),
    UpdatePolicyTestParam(AdminType::VIRTUAL_ADMIN, UpdatePolicyType::DEFAULT, false,
        AdminType::SUB_SUPER_ADMIN, TestMethod::SET_UPDATE_POLICY, ERR_OK),
    UpdatePolicyTestParam(AdminType::VIRTUAL_ADMIN, UpdatePolicyType::DEFAULT, false,
        AdminType::VIRTUAL_ADMIN, TestMethod::SET_UPDATE_POLICY, ERR_OK),
    UpdatePolicyTestParam(AdminType::VIRTUAL_ADMIN, UpdatePolicyType::DEFAULT, false,
        AdminType::NORMAL, TestMethod::SET_UPDATE_POLICY, ERR_OK),

    UpdatePolicyTestParam(AdminType::NORMAL, UpdatePolicyType::DEFAULT, false,
        AdminType::ENT, TestMethod::SET_UPDATE_POLICY, ERR_OK),
    UpdatePolicyTestParam(AdminType::NORMAL, UpdatePolicyType::DEFAULT, false,
        AdminType::SUB_SUPER_ADMIN, TestMethod::SET_UPDATE_POLICY, ERR_OK),
    UpdatePolicyTestParam(AdminType::NORMAL, UpdatePolicyType::DEFAULT, false,
        AdminType::VIRTUAL_ADMIN, TestMethod::SET_UPDATE_POLICY, ERR_OK),
    UpdatePolicyTestParam(AdminType::NORMAL, UpdatePolicyType::DEFAULT, false,
        AdminType::NORMAL, TestMethod::SET_UPDATE_POLICY, ERR_OK),

    // update policy == DEFAULT, and notify
    UpdatePolicyTestParam(AdminType::ENT, UpdatePolicyType::DEFAULT, true,
        AdminType::ENT, TestMethod::SET_UPDATE_POLICY, ERR_OK),
    UpdatePolicyTestParam(AdminType::ENT, UpdatePolicyType::DEFAULT, true,
        AdminType::SUB_SUPER_ADMIN, TestMethod::SET_UPDATE_POLICY, ERR_OK),
    UpdatePolicyTestParam(AdminType::ENT, UpdatePolicyType::DEFAULT, true,
        AdminType::VIRTUAL_ADMIN, TestMethod::SET_UPDATE_POLICY, ERR_OK),
    UpdatePolicyTestParam(AdminType::ENT, UpdatePolicyType::DEFAULT, true,
        AdminType::NORMAL, TestMethod::SET_UPDATE_POLICY, EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED),

    UpdatePolicyTestParam(AdminType::SUB_SUPER_ADMIN, UpdatePolicyType::DEFAULT, true,
        AdminType::ENT, TestMethod::SET_UPDATE_POLICY, ERR_OK),
    UpdatePolicyTestParam(AdminType::SUB_SUPER_ADMIN, UpdatePolicyType::DEFAULT, true,
        AdminType::SUB_SUPER_ADMIN, TestMethod::SET_UPDATE_POLICY, ERR_OK),
    UpdatePolicyTestParam(AdminType::SUB_SUPER_ADMIN, UpdatePolicyType::DEFAULT, true,
        AdminType::VIRTUAL_ADMIN, TestMethod::SET_UPDATE_POLICY, ERR_OK),
    UpdatePolicyTestParam(AdminType::SUB_SUPER_ADMIN, UpdatePolicyType::DEFAULT, true,
        AdminType::NORMAL, TestMethod::SET_UPDATE_POLICY, EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED),

    UpdatePolicyTestParam(AdminType::VIRTUAL_ADMIN, UpdatePolicyType::DEFAULT, true,
        AdminType::ENT, TestMethod::SET_UPDATE_POLICY, ERR_OK),
    UpdatePolicyTestParam(AdminType::VIRTUAL_ADMIN, UpdatePolicyType::DEFAULT, true,
        AdminType::SUB_SUPER_ADMIN, TestMethod::SET_UPDATE_POLICY, ERR_OK),
    UpdatePolicyTestParam(AdminType::VIRTUAL_ADMIN, UpdatePolicyType::DEFAULT, true,
        AdminType::VIRTUAL_ADMIN, TestMethod::SET_UPDATE_POLICY, ERR_OK),
    UpdatePolicyTestParam(AdminType::VIRTUAL_ADMIN, UpdatePolicyType::DEFAULT, true,
        AdminType::NORMAL, TestMethod::SET_UPDATE_POLICY, EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED),
#ifdef FEATURE_PC_ONLY
    UpdatePolicyTestParam(AdminType::NORMAL, UpdatePolicyType::DEFAULT, true,
        AdminType::ENT, TestMethod::SET_UPDATE_POLICY, EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED),
    UpdatePolicyTestParam(AdminType::NORMAL, UpdatePolicyType::DEFAULT, true,
        AdminType::SUB_SUPER_ADMIN, TestMethod::SET_UPDATE_POLICY, EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED),
    UpdatePolicyTestParam(AdminType::NORMAL, UpdatePolicyType::DEFAULT, true,
        AdminType::VIRTUAL_ADMIN, TestMethod::SET_UPDATE_POLICY, EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED),
    UpdatePolicyTestParam(AdminType::NORMAL, UpdatePolicyType::DEFAULT, true,
        AdminType::NORMAL, TestMethod::SET_UPDATE_POLICY, EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED),
#else
    UpdatePolicyTestParam(AdminType::NORMAL, UpdatePolicyType::DEFAULT, true,
        AdminType::ENT, TestMethod::SET_UPDATE_POLICY, ERR_OK),
    UpdatePolicyTestParam(AdminType::NORMAL, UpdatePolicyType::DEFAULT, true,
        AdminType::SUB_SUPER_ADMIN, TestMethod::SET_UPDATE_POLICY, ERR_OK),
    UpdatePolicyTestParam(AdminType::NORMAL, UpdatePolicyType::DEFAULT, true,
        AdminType::VIRTUAL_ADMIN, TestMethod::SET_UPDATE_POLICY, ERR_OK),
    UpdatePolicyTestParam(AdminType::NORMAL, UpdatePolicyType::DEFAULT, true,
        AdminType::NORMAL, TestMethod::SET_UPDATE_POLICY, EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED),
#endif
})));

/**
 * @tc.name: TestSetUpdatePolicy
 * @tc.desc: Test SetUpdatePolicy with sda and sub-sda.
 * @tc.type: FUNC
 */
HWTEST_P(UpdatePolicyConflictTest, TestSetUpdatePolicy, TestSize.Level1)
{
    auto param = GetParam();
    AdminInfo adminInfo1 = CreateAdminInfo(param.adminType1, ADMIN_PACKAGENAME);
    AdminInfo adminInfo2 = CreateAdminInfo(param.adminType2, ADMIN_PACKAGENAME_1);
    auto admin1 = AdminContainer::GetInstance()->CreateAdmin(adminInfo1);
    auto admin2 = AdminContainer::GetInstance()->CreateAdmin(adminInfo2);
    std::vector<std::shared_ptr<Admin>> adminVec = {admin1, admin2};
    edmMgr_->adminMgr_->InsertAdmins(DEFAULT_USER_ID, adminVec);

    if (param.isNotifyPackages) {
        TestNotifyUpgradePackages(admin1, ERR_OK);
    }
    TestSetUpdatePolicy(admin1, param.updatePolicyType, ERR_OK);

    if (param.testMethod == TestMethod::SET_UPDATE_POLICY) {
        TestSetUpdatePolicy(admin2, UpdatePolicyType::PROHIBIT, param.expectedRet);
    } else {
        TestNotifyUpgradePackages(admin2, param.expectedRet);
    }

    ErrCode res = ERR_INVALID_VALUE;
    res = edmMgr_->policyMgr_->SetPolicy(adminInfo1.packageName_, PolicyName::POLICY_SET_UPDATE_POLICY, "", "");
    EXPECT_EQ(res, ERR_OK);
    res = edmMgr_->policyMgr_->SetPolicy(adminInfo2.packageName_, PolicyName::POLICY_SET_UPDATE_POLICY, "", "");
    EXPECT_EQ(res, ERR_OK);
    res = edmMgr_->policyMgr_->SetPolicy(adminInfo1.packageName_, PolicyName::POLICY_NOTIFY_UPGRADE_PACKAGES, "", "");
    EXPECT_EQ(res, ERR_OK);
    res = edmMgr_->policyMgr_->SetPolicy(adminInfo2.packageName_, PolicyName::POLICY_NOTIFY_UPGRADE_PACKAGES, "", "");
    EXPECT_EQ(res, ERR_OK);
    res = edmMgr_->policyMgr_->SetPolicy("", PolicyName::POLICY_SET_UPDATE_POLICY, "", "");
    EXPECT_EQ(res, ERR_OK);
    res = edmMgr_->policyMgr_->SetPolicy("", PolicyName::POLICY_NOTIFY_UPGRADE_PACKAGES, "", "");
    EXPECT_EQ(res, ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
