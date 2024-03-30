/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "enterprise_device_mgr_ability.h"
#include "plugin_singleton.h"
#undef protected
#undef private

#include "enterprise_device_mgr_ability_test.h"

#include <fcntl.h>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <vector>

#include "iplugin_template_test.h"
#include "plugin_manager_test.h"
#include "utils.h"
#include "edm_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
constexpr int32_t TEST_USER_ID = 101;
constexpr int32_t ARRAY_MAP_TESTPLUGIN_POLICYCODE = 13;
constexpr int32_t HANDLE_POLICY_BIFUNCTIONPLG_POLICYCODE = 23;
constexpr int32_t HANDLE_POLICY_JSON_BIFUNCTIONPLG_POLICYCODE = 30;
constexpr int32_t HANDLE_POLICY_BIFUNCTION_UNSAVE_PLG_POLICYCODE = 31;
constexpr int32_t INVALID_POLICYCODE = 123456;
constexpr int32_t ERROR_USER_ID_REMOVE = 0;
constexpr size_t COMMON_EVENT_FUNC_MAP_SIZE = 4;
constexpr uint32_t INVALID_MANAGED_EVENT_TEST = 20;
constexpr uint32_t BUNDLE_ADDED_EVENT = static_cast<uint32_t>(ManagedEvent::BUNDLE_ADDED);
constexpr uint32_t BUNDLE_REMOVED_EVENT = static_cast<uint32_t>(ManagedEvent::BUNDLE_REMOVED);
constexpr uint32_t APP_START_EVENT = static_cast<uint32_t>(ManagedEvent::APP_START);
constexpr uint32_t APP_STOP_EVENT = static_cast<uint32_t>(ManagedEvent::APP_STOP);
constexpr int32_t INDEX_TWO = 2;
constexpr int32_t INDEX_FOUR = 4;
const std::string PERMISSION_MANAGE_ENTERPRISE_DEVICE_ADMIN_TEST = "ohos.permission.MANAGE_ENTERPRISE_DEVICE_ADMIN";
const std::string PERMISSION_SET_ENTERPRISE_INFO_TEST = "ohos.permission.SET_ENTERPRISE_INFO";
const std::string PERMISSION_ENTERPRISE_SUBSCRIBE_MANAGED_EVENT_TEST =
    "ohos.permission.ENTERPRISE_SUBSCRIBE_MANAGED_EVENT";
const std::string PERMISSION_RUNNING_STATE_OBSERVER = "ohos.permission.RUNNING_STATE_OBSERVER";
const std::string ADMIN_PACKAGENAME = "com.edm.test";
const std::string ADMIN_PACKAGENAME_1 = "com.edm.test_1";
const std::string ADMIN_PACKAGENAME_ABILITY = "com.edm.test.MainAbility";
const std::string ADMIN_PACKAGENAME_ABILITY_1 = "com.edm.test.MainAbility_1";
const std::string ADMIN_PACKAGENAME_FAILED = "com.edm.test.demo.ipc.fail";
const std::string ADMIN_PACKAGENAME_NOT_ACTIVE = "com.edm.test.not.active";
const std::string EDM_MANAGE_DATETIME_PERMISSION = "ohos.permission.SET_TIME";
const std::string EDM_TEST_PERMISSION = "ohos.permission.EDM_TEST_PERMISSION";
const std::string EDM_TEST_ENT_PERMISSION = "ohos.permission.EDM_TEST_ENT_PERMISSION";
const std::string TEST_POLICY_VALUE = "test_policy_value";

void EnterpriseDeviceMgrAbilityTest::SetUp()
{
    plugin_ = PLUGIN::ArrayMapTestPlugin::GetPlugin();
    appMgrMock_ = std::make_shared<EdmAppManagerImplMock>();
    bundleMgrMock_ = std::make_shared<EdmBundleManagerImplMock>();
    osAccountMgrMock_ = std::make_shared<EdmOsAccountManagerImplMock>();
    accessTokenMgrMock_ = std::make_shared<EdmAccessTokenManagerImplMock>();
    factoryMock_ = std::make_shared<ExternalManagerFactoryMock>();
    edmMgr_ = new (std::nothrow) EnterpriseDeviceMgrAbilityMock();
    edmMgr_->adminMgr_ = AdminManager::GetInstance();
    edmMgr_->pluginMgr_ = PluginManager::GetInstance();
    edmMgr_->policyMgr_ = std::make_shared<PolicyManager>();
    EXPECT_CALL(*edmMgr_, GetExternalManagerFactory).WillRepeatedly(DoAll(Return(factoryMock_)));
    EXPECT_CALL(*factoryMock_, CreateBundleManager).WillRepeatedly(DoAll(Return(bundleMgrMock_)));
    EXPECT_CALL(*factoryMock_, CreateAppManager).WillRepeatedly(DoAll(Return(appMgrMock_)));
    EXPECT_CALL(*factoryMock_, CreateOsAccountManager).WillRepeatedly(DoAll(Return(osAccountMgrMock_)));
    EXPECT_CALL(*factoryMock_, CreateAccessTokenManager).WillRepeatedly(DoAll(Return(accessTokenMgrMock_)));
}

void EnterpriseDeviceMgrAbilityTest::TearDown()
{
    edmMgr_->adminMgr_->instance_.reset();
    edmMgr_->pluginMgr_->instance_.reset();
    edmMgr_->policyMgr_.reset();
    edmMgr_->instance_.clear();
    edmMgr_.clear();
}

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

// Give testAdmin and plugin_ Initial value
void EnterpriseDeviceMgrAbilityTest::PrepareBeforeHandleDevicePolicy()
{
    Admin testAdmin;
    testAdmin.adminInfo_.packageName_ = ADMIN_PACKAGENAME;
    testAdmin.adminInfo_.permission_ = {EDM_MANAGE_DATETIME_PERMISSION};
    std::vector<std::shared_ptr<Admin>> adminVec = {std::make_shared<Admin>(testAdmin)};

    testAdmin.adminInfo_.packageName_ = ADMIN_PACKAGENAME_FAILED;
    adminVec.push_back(std::make_shared<Admin>(testAdmin));
    edmMgr_->adminMgr_->admins_.insert(
        std::pair<int32_t, std::vector<std::shared_ptr<Admin>>>(DEFAULT_USER_ID, adminVec));
    plugin_->permissionConfig_.permission = EDM_MANAGE_DATETIME_PERMISSION;
    edmMgr_->pluginMgr_->AddPlugin(plugin_);
}

void EnterpriseDeviceMgrAbilityTest::GetPolicySuccess(int32_t userId, const std::string& adminName,
    const std::string& policyName)
{
    std::string policyValue;
    EXPECT_TRUE(SUCCEEDED(edmMgr_->policyMgr_->GetPolicy(adminName, policyName, policyValue, userId)));
    EXPECT_EQ(policyValue, TEST_POLICY_VALUE);
    policyValue.clear();
    EXPECT_TRUE(SUCCEEDED(edmMgr_->policyMgr_->GetPolicy("", policyName, policyValue, userId)));
    EXPECT_EQ(policyValue, TEST_POLICY_VALUE);
}

void EnterpriseDeviceMgrAbilityTest::GetPolicyFailed(int32_t userId, const std::string& adminName,
    const std::string& policyName)
{
    std::string policyValue;
    EXPECT_TRUE(FAILED(edmMgr_->policyMgr_->GetPolicy(adminName, policyName, policyValue, userId)));
    EXPECT_TRUE(FAILED(edmMgr_->policyMgr_->GetPolicy("", policyName, policyValue, userId)));
}

void EnterpriseDeviceMgrAbilityTest::SetPolicy(const std::string& adminName, const std::string& policyName)
{
    edmMgr_->policyMgr_->SetPolicy(adminName, policyName, TEST_POLICY_VALUE, TEST_POLICY_VALUE, DEFAULT_USER_ID);
    edmMgr_->policyMgr_->SetPolicy(adminName, policyName, TEST_POLICY_VALUE, TEST_POLICY_VALUE, TEST_USER_ID);
}

void EnterpriseDeviceMgrAbilityTest::EnableAdminSuc(AppExecFwk::ElementName &admin, AdminType adminType, int userId,
    bool isDebug)
{
    EntInfo entInfo("test", "this is test");
    EXPECT_CALL(*accessTokenMgrMock_, IsDebug).WillOnce(DoAll(Return(isDebug)));
    if (!isDebug) {
        EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillOnce(DoAll(Return(true)));
    }
    QueryExtensionAbilityInfosMock(true, admin.GetBundleName());
    GetBundleInfoMock(true, EDM_TEST_PERMISSION);
    EXPECT_TRUE(SUCCEEDED(edmMgr_->EnableAdmin(admin, entInfo, adminType, userId)));
}

void EnterpriseDeviceMgrAbilityTest::DisableAdminSuc(AppExecFwk::ElementName &admin, int32_t userId)
{
    EXPECT_CALL(*accessTokenMgrMock_, IsDebug).WillOnce(DoAll(Return(false)));
    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillOnce(DoAll(Return(true)));
    EXPECT_TRUE(SUCCEEDED(edmMgr_->DisableAdmin(admin, userId)));
}

void EnterpriseDeviceMgrAbilityTest::DisableSuperAdminSuc(const std::string &bundleName)
{
    EXPECT_CALL(*accessTokenMgrMock_, IsDebug).WillOnce(DoAll(Return(false)));
    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillOnce(DoAll(Return(true)));
    EXPECT_TRUE(SUCCEEDED(edmMgr_->DisableSuperAdmin(bundleName)));
}

void EnterpriseDeviceMgrAbilityTest::AuthorizeAdminSuc(const AppExecFwk::ElementName &admin,
    const std::string &subSuperAdminBundleName)
{
    EXPECT_CALL(*bundleMgrMock_, GetNameForUid).WillOnce(DoAll(SetArgReferee<1>(admin.GetBundleName()),
        Return(ERR_OK)));
    GetBundleInfoMock(true, EDM_TEST_PERMISSION);
    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillOnce(DoAll(Return(true)));
    EXPECT_TRUE(SUCCEEDED(edmMgr_->AuthorizeAdmin(admin, subSuperAdminBundleName)));
}

void EnterpriseDeviceMgrAbilityTest::QueryExtensionAbilityInfosMock(bool ret, const std::string& bundleName,
    bool isExtensionInfoEmpty)
{
    std::vector<AppExecFwk::ExtensionAbilityInfo> extensionInfos;
    if (!isExtensionInfoEmpty) {
        AppExecFwk::ExtensionAbilityInfo extensionAbilityInfo;
        extensionAbilityInfo.bundleName = bundleName;
        extensionAbilityInfo.name = ADMIN_PACKAGENAME_ABILITY;
        extensionInfos.emplace_back(extensionAbilityInfo);
    }
    EXPECT_CALL(*bundleMgrMock_, QueryExtensionAbilityInfos)
        .WillOnce(DoAll(SetArgReferee<INDEX_FOUR>(extensionInfos), Return(ret)));
}

void EnterpriseDeviceMgrAbilityTest::GetBundleInfoMock(bool ret, const std::string &permission)
{
    AppExecFwk::BundleInfo bundleInfo;
    if (!permission.empty()) {
        bundleInfo.reqPermissions.emplace_back(permission);
    }
    EXPECT_CALL(*bundleMgrMock_, GetBundleInfo).WillOnce(DoAll(SetArgReferee<INDEX_TWO>(bundleInfo), Return(ret)));
}

/**
 * @tc.name: TestHandleDevicePolicyWithUserNotExsist
 * @tc.desc: Test HandleDevicePolicy function with userId is not exist.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestHandleDevicePolicyWithUserNotExsist, TestSize.Level1)
{
    PrepareBeforeHandleDevicePolicy();

    EXPECT_CALL(*osAccountMgrMock_, IsOsAccountExists).WillOnce(DoAll(SetArgReferee<1>(false), Return(ERR_OK)));

    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, ARRAY_MAP_TESTPLUGIN_POLICYCODE);
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName(ADMIN_PACKAGENAME_FAILED);
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("");
    ErrCode res = edmMgr_->HandleDevicePolicy(code, elementName, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(res == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestHandleDevicePolicyWithoutAdmin
 * @tc.desc: Test HandleDevicePolicy with none admmin.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestHandleDevicePolicyWithoutAdmin, TestSize.Level1)
{
    PrepareBeforeHandleDevicePolicy();

    std::vector<int32_t> ids = {DEFAULT_USER_ID};
    EXPECT_CALL(*osAccountMgrMock_, IsOsAccountExists).WillOnce(DoAll(SetArgReferee<1>(true), Return(ERR_OK)));
    EXPECT_CALL(*osAccountMgrMock_, QueryActiveOsAccountIds).WillOnce(DoAll(SetArgReferee<0>(ids), Return(ERR_OK)));

    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, ARRAY_MAP_TESTPLUGIN_POLICYCODE);
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName(ADMIN_PACKAGENAME_NOT_ACTIVE);
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("");
    ErrCode res = edmMgr_->HandleDevicePolicy(code, elementName, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(res == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestHandleDevicePolicyCheckCallingUidFailed
 * @tc.desc: Test HandleDevicePolicy function with check callingUid failed.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestHandleDevicePolicyCheckCallingUidFailed, TestSize.Level1)
{
    PrepareBeforeHandleDevicePolicy();

    std::vector<int32_t> ids = {DEFAULT_USER_ID};
    EXPECT_CALL(*osAccountMgrMock_, IsOsAccountExists).WillOnce(DoAll(SetArgReferee<1>(true), Return(ERR_OK)));
    EXPECT_CALL(*osAccountMgrMock_, QueryActiveOsAccountIds).WillOnce(DoAll(SetArgReferee<0>(ids), Return(ERR_OK)));
    EXPECT_CALL(*bundleMgrMock_, GetNameForUid).WillOnce(DoAll(Return(1)));

    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, ARRAY_MAP_TESTPLUGIN_POLICYCODE);
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName(ADMIN_PACKAGENAME);
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("");
    ErrCode res = edmMgr_->HandleDevicePolicy(code, elementName, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(res == EdmReturnErrCode::PERMISSION_DENIED);
}

/**
 * @tc.name: TestHandleDevicePolicyWithInvalidPlugin
 * @tc.desc: Test HandleDevicePolicy function with invalid policy code.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestHandleDevicePolicyWithInvalidPlugin, TestSize.Level1)
{
    PrepareBeforeHandleDevicePolicy();

    std::vector<int32_t> ids = {DEFAULT_USER_ID};
    EXPECT_CALL(*osAccountMgrMock_, IsOsAccountExists).WillOnce(DoAll(SetArgReferee<1>(true), Return(ERR_OK)));
    EXPECT_CALL(*osAccountMgrMock_, QueryActiveOsAccountIds).WillOnce(DoAll(SetArgReferee<0>(ids), Return(ERR_OK)));
    EXPECT_CALL(*bundleMgrMock_, GetNameForUid).WillOnce(DoAll(SetArgReferee<1>(ADMIN_PACKAGENAME), Return(ERR_OK)));

    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, INVALID_POLICYCODE);
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName(ADMIN_PACKAGENAME);
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("");
    ErrCode res = edmMgr_->HandleDevicePolicy(code, elementName, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(res == EdmReturnErrCode::INTERFACE_UNSUPPORTED);
}

/**
 * @tc.name: TestHandleDevicePolicyCheckPermissionFailed
 * @tc.desc: Test HandleDevicePolicy function with check plugin permission failed.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestHandleDevicePolicyCheckPermissionFailed, TestSize.Level1)
{
    PrepareBeforeHandleDevicePolicy();
    Admin testAdmin;
    testAdmin.adminInfo_.packageName_ = ADMIN_PACKAGENAME;
    std::vector<std::shared_ptr<Admin>> adminVec = {std::make_shared<Admin>(testAdmin)};
    edmMgr_->adminMgr_->admins_.clear();
    edmMgr_->adminMgr_->admins_.insert(
        std::pair<int32_t, std::vector<std::shared_ptr<Admin>>>(DEFAULT_USER_ID, adminVec));

    std::vector<int32_t> ids = {DEFAULT_USER_ID};
    EXPECT_CALL(*osAccountMgrMock_, IsOsAccountExists).WillOnce(DoAll(SetArgReferee<1>(true), Return(ERR_OK)));
    EXPECT_CALL(*osAccountMgrMock_, QueryActiveOsAccountIds).WillOnce(DoAll(SetArgReferee<0>(ids), Return(ERR_OK)));
    EXPECT_CALL(*bundleMgrMock_, GetNameForUid).WillOnce(DoAll(SetArgReferee<1>(ADMIN_PACKAGENAME), Return(ERR_OK)));

    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, ARRAY_MAP_TESTPLUGIN_POLICYCODE);
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName(ADMIN_PACKAGENAME);
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("");
    ErrCode res = edmMgr_->HandleDevicePolicy(code, elementName, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(res == EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED);
}

/**
 * @tc.name: TestHandleDevicePolicyVerifyCallingPermissionFailed
 * @tc.desc: Test HandleDevicePolicy function with check calling permission failed.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestHandleDevicePolicyVerifyCallingPermissionFailed, TestSize.Level1)
{
    PrepareBeforeHandleDevicePolicy();
    Admin testAdmin;
    testAdmin.adminInfo_.packageName_ = ADMIN_PACKAGENAME;
    testAdmin.adminInfo_.permission_ = {EDM_TEST_PERMISSION};
    std::vector<std::shared_ptr<Admin>> adminVec = {std::make_shared<Admin>(testAdmin)};
    edmMgr_->adminMgr_->admins_.clear();
    edmMgr_->adminMgr_->admins_.insert(
        std::pair<int32_t, std::vector<std::shared_ptr<Admin>>>(DEFAULT_USER_ID, adminVec));
    plugin_->permissionConfig_.permission = EDM_TEST_PERMISSION;
    edmMgr_->pluginMgr_->pluginsCode_.clear();
    edmMgr_->pluginMgr_->pluginsName_.clear();
    edmMgr_->pluginMgr_->AddPlugin(plugin_);

    std::vector<int32_t> ids = {DEFAULT_USER_ID};
    EXPECT_CALL(*osAccountMgrMock_, IsOsAccountExists).WillOnce(DoAll(SetArgReferee<1>(true), Return(ERR_OK)));
    EXPECT_CALL(*osAccountMgrMock_, QueryActiveOsAccountIds).WillRepeatedly(DoAll(SetArgReferee<0>(ids),
        Return(ERR_OK)));
    EXPECT_CALL(*bundleMgrMock_, GetNameForUid).WillOnce(DoAll(SetArgReferee<1>(ADMIN_PACKAGENAME), Return(ERR_OK)));
    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillOnce(DoAll(Return(false)));

    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, ARRAY_MAP_TESTPLUGIN_POLICYCODE);
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName(ADMIN_PACKAGENAME);
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("");
    ErrCode res = edmMgr_->HandleDevicePolicy(code, elementName, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(res == EdmReturnErrCode::PERMISSION_DENIED);
}

/**
 * @tc.name: TestHandleDevicePolicySuc
 * @tc.desc: Test HandleDevicePolicy function success.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestHandleDevicePolicySuc, TestSize.Level1)
{
    PrepareBeforeHandleDevicePolicy();

    std::vector<int32_t> ids = {DEFAULT_USER_ID};
    EXPECT_CALL(*osAccountMgrMock_, IsOsAccountExists).WillOnce(DoAll(SetArgReferee<1>(true), Return(ERR_OK)));
    EXPECT_CALL(*osAccountMgrMock_, QueryActiveOsAccountIds).WillRepeatedly(DoAll(SetArgReferee<0>(ids),
        Return(ERR_OK)));
    EXPECT_CALL(*bundleMgrMock_, GetNameForUid).WillOnce(DoAll(SetArgReferee<1>(ADMIN_PACKAGENAME), Return(ERR_OK)));
    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillOnce(DoAll(Return(true)));

    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, ARRAY_MAP_TESTPLUGIN_POLICYCODE);
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName(ADMIN_PACKAGENAME);
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("");
    ErrCode res = edmMgr_->HandleDevicePolicy(code, elementName, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);
}


/**
 * @tc.name: HandleDevicePolicyFuncTest006
 * @tc.desc: Test EnterpriseDeviceMgrAbility::HandleDevicePolicy function.
 * @tc.desc: plugin->OnHandlePolicy(code, data, reply, policyValue, isChanged)
 * @tc.desc: Test the result of plugin->OnHandlePolicy is not OK
 * @tc.type: FUNC
 * @tc.require: issueI5PBT1
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, HandleDevicePolicyFuncTest006, TestSize.Level1)
{
    PrepareBeforeHandleDevicePolicy();

    plugin_ = PLUGIN::HandlePolicyBiFunctionPlg::GetPlugin();
    plugin_->permissionConfig_.permission = EDM_MANAGE_DATETIME_PERMISSION;
    edmMgr_->pluginMgr_->pluginsCode_.clear();
    edmMgr_->pluginMgr_->pluginsName_.clear();
    edmMgr_->pluginMgr_->AddPlugin(plugin_);

    std::vector<int32_t> ids = {DEFAULT_USER_ID};
    EXPECT_CALL(*osAccountMgrMock_, IsOsAccountExists).WillRepeatedly(DoAll(SetArgReferee<1>(true), Return(ERR_OK)));
    EXPECT_CALL(*osAccountMgrMock_, QueryActiveOsAccountIds).WillRepeatedly(DoAll(SetArgReferee<0>(ids),
        Return(ERR_OK)));
    EXPECT_CALL(*bundleMgrMock_, GetNameForUid).WillRepeatedly(DoAll(SetArgReferee<1>(ADMIN_PACKAGENAME),
        Return(ERR_OK)));
    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillOnce(DoAll(Return(true)));

    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, HANDLE_POLICY_BIFUNCTIONPLG_POLICYCODE);
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName(ADMIN_PACKAGENAME);
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("");
    data.WriteString("ErrorData");
    ErrCode res = edmMgr_->HandleDevicePolicy(code, elementName, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_EDM_OPERATE_JSON);
}

/**
 * @tc.name: HandleDevicePolicyFuncTest007
 * @tc.desc: Test EnterpriseDeviceMgrAbility::HandleDevicePolicy function.(if (plugin->NeedSavePolicy() && isChanged))
 * @tc.desc: Test run into the branch if (plugin ->NeedSavePolicy() && isChanged)
 * @tc.type: FUNC
 * @tc.require: issueI5PBT1
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, HandleDevicePolicyFuncTest007, TestSize.Level1)
{
    PrepareBeforeHandleDevicePolicy();
    plugin_ = PLUGIN::HandlePolicyBiFunctionPlg::GetPlugin();
    plugin_->permissionConfig_.permission = EDM_MANAGE_DATETIME_PERMISSION;
    edmMgr_->pluginMgr_->pluginsCode_.clear();
    edmMgr_->pluginMgr_->pluginsName_.clear();
    edmMgr_->pluginMgr_->AddPlugin(plugin_);

    std::vector<int32_t> ids = {DEFAULT_USER_ID};
    EXPECT_CALL(*osAccountMgrMock_, IsOsAccountExists).WillRepeatedly(DoAll(SetArgReferee<1>(true), Return(ERR_OK)));
    EXPECT_CALL(*osAccountMgrMock_, QueryActiveOsAccountIds).WillRepeatedly(DoAll(SetArgReferee<0>(ids),
        Return(ERR_OK)));
    EXPECT_CALL(*bundleMgrMock_, GetNameForUid).WillRepeatedly(DoAll(SetArgReferee<1>(ADMIN_PACKAGENAME),
        Return(ERR_OK)));
    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillRepeatedly(DoAll(Return(true)));

    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, HANDLE_POLICY_BIFUNCTIONPLG_POLICYCODE);
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName(ADMIN_PACKAGENAME);
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("");
    data.WriteString("testValue");
    ErrCode res = edmMgr_->HandleDevicePolicy(code, elementName, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);
    res = edmMgr_->policyMgr_->SetPolicy(ADMIN_PACKAGENAME, plugin_->GetPolicyName(), "", "");
    ASSERT_TRUE(res == ERR_OK);

    plugin_ = PLUGIN::HandlePolicyBiFunctionUnsavePlg::GetPlugin();
    plugin_->permissionConfig_.permission = EDM_MANAGE_DATETIME_PERMISSION;
    edmMgr_->pluginMgr_->pluginsCode_.clear();
    edmMgr_->pluginMgr_->pluginsName_.clear();
    edmMgr_->pluginMgr_->AddPlugin(plugin_);
    code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, HANDLE_POLICY_BIFUNCTION_UNSAVE_PLG_POLICYCODE);
    data.WriteString("");
    data.WriteString("{\"name\" : \"testValue\"}");
    res = edmMgr_->HandleDevicePolicy(code, elementName, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);
}

/**
 * @tc.name: HandleDevicePolicyFuncTest008
 * @tc.desc: Test EnterpriseDeviceMgrAbility::HandleDevicePolicy function.
 * @tc.desc: run into plugin->MergePolicyData(admin.GetBundleName(), mergedPolicy)
 * @tc.desc: Test the MergePolicyData processing result is not OK
 * @tc.type: FUNC
 * @tc.require: issueI5PBT1
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, HandleDevicePolicyFuncTest008, TestSize.Level1)
{
    PrepareBeforeHandleDevicePolicy();
    plugin_ = PLUGIN::HandlePolicyJsonBiFunctionPlg::GetPlugin();
    plugin_->permissionConfig_.permission = EDM_MANAGE_DATETIME_PERMISSION;
    edmMgr_->pluginMgr_->pluginsCode_.clear();
    edmMgr_->pluginMgr_->pluginsName_.clear();
    edmMgr_->pluginMgr_->AddPlugin(plugin_);

    std::vector<int32_t> ids = {DEFAULT_USER_ID};
    EXPECT_CALL(*osAccountMgrMock_, IsOsAccountExists).WillRepeatedly(DoAll(SetArgReferee<1>(true), Return(ERR_OK)));
    EXPECT_CALL(*osAccountMgrMock_, QueryActiveOsAccountIds).WillRepeatedly(DoAll(SetArgReferee<0>(ids),
        Return(ERR_OK)));
    EXPECT_CALL(*bundleMgrMock_, GetNameForUid).WillRepeatedly(DoAll(SetArgReferee<1>(ADMIN_PACKAGENAME),
        Return(ERR_OK)));
    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillOnce(DoAll(Return(true)));

    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, HANDLE_POLICY_JSON_BIFUNCTIONPLG_POLICYCODE);
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName(ADMIN_PACKAGENAME);
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("");
    data.WriteString("{\"name\" : \"testValue\"}");
    ErrCode res = edmMgr_->HandleDevicePolicy(code, elementName, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);
    res = edmMgr_->policyMgr_->SetPolicy(ADMIN_PACKAGENAME, plugin_->GetPolicyName(), "", "", DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);
}

/**
 * @tc.name: TestGetDevicePolicyWithUserNotExsist
 * @tc.desc: Test GetDevicePolicy function with userId is not exist.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestGetDevicePolicyWithUserNotExsist, TestSize.Level1)
{
    EXPECT_CALL(*osAccountMgrMock_, IsOsAccountExists).WillOnce(DoAll(SetArgReferee<1>(false), Return(ERR_OK)));

    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, INVALID_POLICYCODE);
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(1);
    ErrCode res = edmMgr_->GetDevicePolicy(code, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(res == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestGetDevicePolicyWithNotExistPlugin
 * @tc.desc: Test GetDevicePolicy function with not exist plugin.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestGetDevicePolicyWithNotExistPlugin, TestSize.Level1)
{
    EXPECT_CALL(*osAccountMgrMock_, IsOsAccountExists).WillOnce(DoAll(SetArgReferee<1>(true), Return(ERR_OK)));

    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, INVALID_POLICYCODE);
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(1);
    ErrCode res = edmMgr_->GetDevicePolicy(code, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(res == EdmReturnErrCode::INTERFACE_UNSUPPORTED);
}

/**
 * @tc.name: TestGetDevicePolicyWithAdminInactive
 * @tc.desc: Test GetDevicePolicy function with admin inactive.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestGetDevicePolicyWithAdminInactive, TestSize.Level1)
{
    EXPECT_CALL(*osAccountMgrMock_, IsOsAccountExists).WillOnce(DoAll(SetArgReferee<1>(true), Return(ERR_OK)));

    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, ARRAY_MAP_TESTPLUGIN_POLICYCODE);
    plugin_->permissionConfig_.permission = EDM_MANAGE_DATETIME_PERMISSION;
    edmMgr_->pluginMgr_->AddPlugin(plugin_);
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME_NOT_ACTIVE);
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("");
    data.WriteInt32(0);
    data.WriteParcelable(&admin);
    ErrCode res = edmMgr_->GetDevicePolicy(code, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(res == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetDevicePolicyWithCheckCallingUidFailed
 * @tc.desc: Test GetDevicePolicy function with check calling uid failed.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestGetDevicePolicyWithCheckCallingUidFailed, TestSize.Level1)
{
    Admin testAdmin;
    testAdmin.adminInfo_.packageName_ = ADMIN_PACKAGENAME;
    testAdmin.adminInfo_.permission_ = {EDM_TEST_PERMISSION};
    std::vector<std::shared_ptr<Admin>> adminVec = {std::make_shared<Admin>(testAdmin)};
    edmMgr_->adminMgr_->admins_.insert(
        std::pair<int32_t, std::vector<std::shared_ptr<Admin>>>(DEFAULT_USER_ID, adminVec));
    plugin_->permissionConfig_.permission = EDM_TEST_PERMISSION;
    edmMgr_->pluginMgr_->AddPlugin(plugin_);

    EXPECT_CALL(*osAccountMgrMock_, IsOsAccountExists).WillOnce(DoAll(SetArgReferee<1>(true), Return(ERR_OK)));
    EXPECT_CALL(*bundleMgrMock_, GetNameForUid).WillOnce(DoAll(SetArgReferee<1>(ADMIN_PACKAGENAME), Return(1)));

    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, ARRAY_MAP_TESTPLUGIN_POLICYCODE);
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("");
    data.WriteInt32(0);
    data.WriteParcelable(&admin);
    ErrCode res = edmMgr_->GetDevicePolicy(code, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(res == EdmReturnErrCode::PERMISSION_DENIED);
}

/**
 * @tc.name: TestGetDevicePolicyWithCheckEdmPermissionFailed
 * @tc.desc: Test GetDevicePolicy function with check edm permission failed.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestGetDevicePolicyWithCheckEdmPermissionFailed, TestSize.Level1)
{
    PrepareBeforeHandleDevicePolicy();
    plugin_->permissionConfig_.permission = EDM_TEST_PERMISSION;
    edmMgr_->pluginMgr_->AddPlugin(plugin_);

    EXPECT_CALL(*osAccountMgrMock_, IsOsAccountExists).WillOnce(DoAll(SetArgReferee<1>(true), Return(ERR_OK)));
    EXPECT_CALL(*bundleMgrMock_, GetNameForUid).WillOnce(DoAll(SetArgReferee<1>(ADMIN_PACKAGENAME), Return(ERR_OK)));

    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, ARRAY_MAP_TESTPLUGIN_POLICYCODE);
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("");
    data.WriteInt32(0);
    data.WriteParcelable(&admin);
    ErrCode res = edmMgr_->GetDevicePolicy(code, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(res == EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED);
}

/**
 * @tc.name: TestGetDevicePolicySuc
 * @tc.desc: Test GetDevicePolicy function success.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestGetDevicePolicySuc, TestSize.Level1)
{
    PrepareBeforeHandleDevicePolicy();

    EXPECT_CALL(*osAccountMgrMock_, IsOsAccountExists).WillOnce(DoAll(SetArgReferee<1>(true), Return(ERR_OK)));
    EXPECT_CALL(*bundleMgrMock_, GetNameForUid).WillOnce(DoAll(SetArgReferee<1>(ADMIN_PACKAGENAME), Return(ERR_OK)));

    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, ARRAY_MAP_TESTPLUGIN_POLICYCODE);
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("");
    data.WriteInt32(0);
    data.WriteParcelable(&admin);
    ErrCode res = edmMgr_->GetDevicePolicy(code, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);
}
/**
 * @tc.name: TestGetDevicePolicyWithoutAdminSuc
 * @tc.desc: Test GetDevicePolicy function success without admin.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestGetDevicePolicyWithoutAdminSuc, TestSize.Level1)
{
    EXPECT_CALL(*osAccountMgrMock_, IsOsAccountExists).WillOnce(DoAll(SetArgReferee<1>(true), Return(ERR_OK)));

    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, ARRAY_MAP_TESTPLUGIN_POLICYCODE);
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(1);
    plugin_->permissionConfig_.permission = EDM_MANAGE_DATETIME_PERMISSION;
    edmMgr_->pluginMgr_->AddPlugin(plugin_);
    ErrCode res = edmMgr_->GetDevicePolicy(code, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);
}

/**
 * @tc.name: GetDevicePolicyFuncTest006
 * @tc.desc: Test EnterpriseDeviceMgrAbility::GetDevicePolicy function.
 * @tc.desc: Test if (plugin->NeedSavePolicy())
 * @tc.type: FUNC
 * @tc.require: issueI5PBT1
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, GetDevicePolicyFuncTest006, TestSize.Level1)
{
    PrepareBeforeHandleDevicePolicy();
    plugin_ = PLUGIN::HandlePolicyBiFunctionUnsavePlg::GetPlugin();
    plugin_->permissionConfig_.permission = EDM_MANAGE_DATETIME_PERMISSION;
    edmMgr_->pluginMgr_->pluginsCode_.clear();
    edmMgr_->pluginMgr_->pluginsName_.clear();
    edmMgr_->pluginMgr_->AddPlugin(plugin_);

    EXPECT_CALL(*osAccountMgrMock_, IsOsAccountExists).WillOnce(DoAll(SetArgReferee<1>(true), Return(ERR_OK)));
    EXPECT_CALL(*bundleMgrMock_, GetNameForUid).WillOnce(DoAll(SetArgReferee<1>(ADMIN_PACKAGENAME), Return(ERR_OK)));

    uint32_t code =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, HANDLE_POLICY_BIFUNCTION_UNSAVE_PLG_POLICYCODE);
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("");
    data.WriteInt32(0);
    data.WriteParcelable(&admin);
    ErrCode res = edmMgr_->GetDevicePolicy(code, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);
}

/**
 * @tc.name: GetDevicePolicyFuncTest007
 * @tc.desc: Test EnterpriseDeviceMgrAbility::GetDevicePolicy function.
 * @tc.desc: Test if admin != nullptr && (deviceAdmin->CheckPermission fail)
 * @tc.type: FUNC
 * @tc.require: issueI5PBT1
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, GetDevicePolicyFuncTest007, TestSize.Level1)
{
    PrepareBeforeHandleDevicePolicy();
    plugin_->permissionConfig_.permission = EDM_TEST_PERMISSION;
    edmMgr_->pluginMgr_->AddPlugin(plugin_);

    EXPECT_CALL(*osAccountMgrMock_, IsOsAccountExists).WillOnce(DoAll(SetArgReferee<1>(true), Return(ERR_OK)));
    EXPECT_CALL(*bundleMgrMock_, GetNameForUid).WillOnce(DoAll(SetArgReferee<1>(ADMIN_PACKAGENAME), Return(ERR_OK)));

    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, ARRAY_MAP_TESTPLUGIN_POLICYCODE);
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME_FAILED);
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("");
    data.WriteInt32(0);
    data.WriteParcelable(&admin);
    ErrCode res = edmMgr_->GetDevicePolicy(code, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(res == EdmReturnErrCode::PERMISSION_DENIED);
}

/**
 * @tc.name: TestOnCommonEventUserRemovedWithPolicy
 * @tc.desc: Test OnCommonEventUserRemoved remove user 101 with policy.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestOnCommonEventUserRemovedWithPolicy, TestSize.Level1)
{
    // enable super admin
    AppExecFwk::ElementName superAdmin;
    superAdmin.SetBundleName(ADMIN_PACKAGENAME);
    superAdmin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EnableAdminSuc(superAdmin, AdminType::ENT, DEFAULT_USER_ID);
    // authorize sub-super admin
    std::string subSuperAdmin = ADMIN_PACKAGENAME_1;
    AuthorizeAdminSuc(superAdmin, ADMIN_PACKAGENAME_1);
    // set policy with userId = 100 and 101
    auto plugin = PLUGIN::StringTestPlugin::GetPlugin();
    edmMgr_->pluginMgr_->AddPlugin(plugin);
    SetPolicy(superAdmin.GetBundleName(), plugin->GetPolicyName());
    SetPolicy(subSuperAdmin, plugin->GetPolicyName());
    // remove user 101
    EventFwk::CommonEventData data;
    data.SetCode(TEST_USER_ID);
    edmMgr_->OnCommonEventUserRemoved(data);
    // get policy of userId = 101
    GetPolicyFailed(TEST_USER_ID, superAdmin.GetBundleName(), plugin->GetPolicyName());
    GetPolicyFailed(TEST_USER_ID, subSuperAdmin, plugin->GetPolicyName());
    // get policy of userId = 100
    GetPolicySuccess(DEFAULT_USER_ID, superAdmin.GetBundleName(), plugin->GetPolicyName());
    GetPolicySuccess(DEFAULT_USER_ID, subSuperAdmin, plugin->GetPolicyName());
    // disable super admin
    DisableSuperAdminSuc(superAdmin.GetBundleName());
}

/**
 * @tc.name: TestOnCommonEventPackageRemovedNormal
 * @tc.desc: Test OnCommonEventPackageRemoved noraml admin func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestOnCommonEventPackageRemovedNormal, TestSize.Level1)
{
    // enable normal admin with userId = 100 and 101
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EnableAdminSuc(admin, AdminType::NORMAL, DEFAULT_USER_ID);
    EnableAdminSuc(admin, AdminType::NORMAL, TEST_USER_ID);
    // remove normal admin under userId = 101
    EventFwk::CommonEventData data;
    AAFwk::Want want;
    want.SetElementName(admin.GetBundleName(), admin.GetAbilityName());
    want.SetParam(AppExecFwk::Constants::USER_ID, TEST_USER_ID);
    data.SetWant(want);
    edmMgr_->OnCommonEventPackageRemoved(data);
    // get naormal admin under userId = 100 and 101
    ASSERT_TRUE(edmMgr_->adminMgr_->GetAdminByPkgName(admin.GetBundleName(), DEFAULT_USER_ID) != nullptr);
    ASSERT_TRUE(edmMgr_->adminMgr_->GetAdminByPkgName(admin.GetBundleName(), TEST_USER_ID) == nullptr);
    // remove normal admin under userId = 100
    want.SetParam(AppExecFwk::Constants::USER_ID, DEFAULT_USER_ID);
    data.SetWant(want);
    edmMgr_->OnCommonEventPackageRemoved(data);
    // get naormal admin under userId = 100 and 101
    ASSERT_TRUE(edmMgr_->adminMgr_->GetAdminByPkgName(admin.GetBundleName(), DEFAULT_USER_ID) == nullptr);
    ASSERT_TRUE(edmMgr_->adminMgr_->GetAdminByPkgName(admin.GetBundleName(), TEST_USER_ID) == nullptr);
}

/**
 * @tc.name: TestOnCommonEventPackageRemovedSub
 * @tc.desc: Test OnCommonEventPackageRemoved sub super admin func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestOnCommonEventPackageRemovedSub, TestSize.Level1)
{
    // enable super admin
    AppExecFwk::ElementName superAdmin;
    superAdmin.SetBundleName(ADMIN_PACKAGENAME);
    superAdmin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EnableAdminSuc(superAdmin, AdminType::ENT, DEFAULT_USER_ID);
    // authorize sub-super admin
    std::string subSuperAdmin = ADMIN_PACKAGENAME_1;
    AuthorizeAdminSuc(superAdmin, subSuperAdmin);
    // sub-super admin set policy with userId = 100 and 101
    auto plugin = PLUGIN::StringTestPlugin::GetPlugin();
    edmMgr_->pluginMgr_->AddPlugin(plugin);
    SetPolicy(subSuperAdmin, plugin->GetPolicyName());

    // remove sub-super admin under userId = 101
    EventFwk::CommonEventData data;
    AAFwk::Want want;
    want.SetBundle(subSuperAdmin);
    want.SetParam(AppExecFwk::Constants::USER_ID, TEST_USER_ID);
    data.SetWant(want);
    edmMgr_->OnCommonEventPackageRemoved(data);
    // get sub-super admin
    ASSERT_TRUE(edmMgr_->adminMgr_->GetAdminByPkgName(subSuperAdmin, DEFAULT_USER_ID) != nullptr);
    // get sub-super admin policy of sub-super admin with userId = 101
    GetPolicySuccess(TEST_USER_ID, subSuperAdmin, plugin->GetPolicyName());
    // get sub-super admin policy of sub-super admin with userId = 100
    GetPolicySuccess(DEFAULT_USER_ID, subSuperAdmin, plugin->GetPolicyName());

    // remove sub-super admin under userId = 100
    want.SetParam(AppExecFwk::Constants::USER_ID, DEFAULT_USER_ID);
    data.SetWant(want);
    edmMgr_->OnCommonEventPackageRemoved(data);
    // get sub-super admin
    ASSERT_TRUE(edmMgr_->adminMgr_->GetAdminByPkgName(subSuperAdmin, DEFAULT_USER_ID) == nullptr);
    // get sub-super admin policy of sub-super admin with userId = 101
    GetPolicyFailed(TEST_USER_ID, subSuperAdmin, plugin->GetPolicyName());
    // get sub-super admin policy of sub-super admin with userId = 100
    GetPolicyFailed(DEFAULT_USER_ID, subSuperAdmin, plugin->GetPolicyName());
    // disable super admin
    DisableSuperAdminSuc(superAdmin.GetBundleName());
}

/**
 * @tc.name: TestOnCommonEventPackageRemovedEnt
 * @tc.desc: Test OnCommonEventPackageRemoved super admin func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestOnCommonEventPackageRemovedEnt, TestSize.Level1)
{
    // enable super admin
    AppExecFwk::ElementName superAdmin;
    superAdmin.SetBundleName(ADMIN_PACKAGENAME);
    superAdmin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EnableAdminSuc(superAdmin, AdminType::ENT, DEFAULT_USER_ID);
    // authorize sub-super admin
    std::string subSuperAdmin = ADMIN_PACKAGENAME_1;
    AuthorizeAdminSuc(superAdmin, subSuperAdmin);
    // set policy with userId = 100 and 101
    auto plugin = PLUGIN::StringTestPlugin::GetPlugin();
    edmMgr_->pluginMgr_->AddPlugin(plugin);
    SetPolicy(superAdmin.GetBundleName(), plugin->GetPolicyName());
    SetPolicy(subSuperAdmin, plugin->GetPolicyName());

    // remove super admin under userId = 101
    EventFwk::CommonEventData data;
    AAFwk::Want want;
    want.SetElementName(superAdmin.GetBundleName(), superAdmin.GetAbilityName());
    want.SetParam(AppExecFwk::Constants::USER_ID, TEST_USER_ID);
    data.SetWant(want);
    edmMgr_->OnCommonEventPackageRemoved(data);
    // get sub-super admin and super admin
    ASSERT_TRUE(edmMgr_->adminMgr_->GetAdminByPkgName(superAdmin.GetBundleName(), DEFAULT_USER_ID) != nullptr);
    ASSERT_TRUE(edmMgr_->adminMgr_->GetAdminByPkgName(subSuperAdmin, DEFAULT_USER_ID) != nullptr);
    // get policy of super and sub-super admin with userId = 101
    GetPolicySuccess(TEST_USER_ID, superAdmin.GetBundleName(), plugin->GetPolicyName());
    GetPolicySuccess(TEST_USER_ID, subSuperAdmin, plugin->GetPolicyName());
    // get policy of super and sub-super admin with userId = 100
    GetPolicySuccess(DEFAULT_USER_ID, superAdmin.GetBundleName(), plugin->GetPolicyName());
    GetPolicySuccess(DEFAULT_USER_ID, subSuperAdmin, plugin->GetPolicyName());

    // remove super under userId = 100
    want.SetParam(AppExecFwk::Constants::USER_ID, DEFAULT_USER_ID);
    data.SetWant(want);
    edmMgr_->OnCommonEventPackageRemoved(data);
    // get sub-super admin and super admin
    ASSERT_TRUE(edmMgr_->adminMgr_->GetAdminByPkgName(superAdmin.GetBundleName(), DEFAULT_USER_ID) == nullptr);
    ASSERT_TRUE(edmMgr_->adminMgr_->GetAdminByPkgName(subSuperAdmin, DEFAULT_USER_ID) == nullptr);
    // get policy of super and sub-super admin with userId = 100
    GetPolicyFailed(DEFAULT_USER_ID, superAdmin.GetBundleName(), plugin->GetPolicyName());
    GetPolicyFailed(DEFAULT_USER_ID, subSuperAdmin, plugin->GetPolicyName());
    // get policy of super and sub-super admin with userId = 101
    GetPolicyFailed(TEST_USER_ID, superAdmin.GetBundleName(), plugin->GetPolicyName());
    GetPolicyFailed(TEST_USER_ID, subSuperAdmin, plugin->GetPolicyName());
}

/**
 * @tc.name: TestdisableSuperAdminWithPolicy
 * @tc.desc: Test disableSuperAdmin super admin func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestdisableSuperAdminWithPolicy, TestSize.Level1)
{
    EXPECT_CALL(*accessTokenMgrMock_, IsDebug).WillRepeatedly(DoAll(Return(false)));
    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillRepeatedly(DoAll(Return(true)));
    // enable super admin
    AppExecFwk::ElementName superAdmin;
    superAdmin.SetBundleName(ADMIN_PACKAGENAME);
    superAdmin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EnableAdminSuc(superAdmin, AdminType::ENT, DEFAULT_USER_ID);
    // authorize sub-super admin
    std::string subSuperAdmin = ADMIN_PACKAGENAME_1;
    AuthorizeAdminSuc(superAdmin, subSuperAdmin);
    // set policy with userId = 100 and 101
    auto plugin = PLUGIN::StringTestPlugin::GetPlugin();
    edmMgr_->pluginMgr_->AddPlugin(plugin);
    SetPolicy(superAdmin.GetBundleName(), plugin->GetPolicyName());
    SetPolicy(subSuperAdmin, plugin->GetPolicyName());
    // disable super admin
    DisableSuperAdminSuc(superAdmin.GetBundleName());
    // get sub-super admin and super admin
    ASSERT_TRUE(edmMgr_->adminMgr_->GetAdminByPkgName(superAdmin.GetBundleName(), DEFAULT_USER_ID) == nullptr);
    ASSERT_TRUE(edmMgr_->adminMgr_->GetAdminByPkgName(subSuperAdmin, DEFAULT_USER_ID) == nullptr);
    // get policy of sub-super admin with userId = 101
    GetPolicyFailed(TEST_USER_ID, superAdmin.GetBundleName(), plugin->GetPolicyName());
    GetPolicyFailed(TEST_USER_ID, subSuperAdmin, plugin->GetPolicyName());
    // get policy of sub-super admin with userId = 100
    GetPolicyFailed(DEFAULT_USER_ID, superAdmin.GetBundleName(), plugin->GetPolicyName());
    GetPolicyFailed(DEFAULT_USER_ID, subSuperAdmin, plugin->GetPolicyName());
}

/**
 * @tc.name: TestAuthorizeAdminWithoutPermisson
 * @tc.desc: Test TestAuthorizeAdmin without permission func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestAuthorizeAdminWithoutPermisson, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);

    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillOnce(DoAll(Return(false)));
    ErrCode ret = edmMgr_->AuthorizeAdmin(admin, ADMIN_PACKAGENAME_1);
    
    ASSERT_TRUE(ret == EdmReturnErrCode::PERMISSION_DENIED);
}

/**
 * @tc.name: TestAuthorizeAdminWithoutAdmin
 * @tc.desc: Test TestAuthorizeAdmin without administrator.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestAuthorizeAdminWithoutAdmin, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);

    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillOnce(DoAll(Return(true)));
    ErrCode ret = edmMgr_->AuthorizeAdmin(admin, ADMIN_PACKAGENAME_1);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestAuthorizeAdminWithoutSDA
 * @tc.desc: Test TestAuthorizeAdmin without administrator.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestAuthorizeAdminWithoutSDA, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EnableAdminSuc(admin, AdminType::NORMAL, DEFAULT_USER_ID);

    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillOnce(DoAll(Return(true)));
    std::vector<int32_t> ids = {DEFAULT_USER_ID};
    EXPECT_CALL(*osAccountMgrMock_, QueryActiveOsAccountIds).WillRepeatedly(DoAll(SetArgReferee<0>(ids),
        Return(ERR_OK)));

    ErrCode ret = edmMgr_->AuthorizeAdmin(admin, ADMIN_PACKAGENAME_1);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED);

    DisableAdminSuc(admin, DEFAULT_USER_ID);
    std::shared_ptr<Admin> normalAdmin = edmMgr_->adminMgr_->GetAdminByPkgName(admin.GetBundleName(), DEFAULT_USER_ID);
    EXPECT_TRUE(normalAdmin == nullptr);
}

/**
 * @tc.name: TestAuthorizeAdminIpcFail
 * @tc.desc: Test AuthorizeAdmin ipc fail func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestAuthorizeAdminIpcFail, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EnableAdminSuc(admin, AdminType::ENT, DEFAULT_USER_ID);

    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillOnce(DoAll(Return(true)));
    std::vector<int32_t> ids = {DEFAULT_USER_ID};
    EXPECT_CALL(*osAccountMgrMock_, QueryActiveOsAccountIds).WillRepeatedly(DoAll(SetArgReferee<0>(ids),
        Return(ERR_OK)));
    EXPECT_CALL(*bundleMgrMock_, GetNameForUid).WillOnce(DoAll(Return(1)));
    ErrCode res = edmMgr_->AuthorizeAdmin(admin, ADMIN_PACKAGENAME_1);
    EXPECT_TRUE(res == EdmReturnErrCode::PERMISSION_DENIED);

    DisableSuperAdminSuc(admin.GetBundleName());
    std::shared_ptr<Admin> superAdmin;
    EXPECT_TRUE(FAILED(edmMgr_->adminMgr_->GetSubOrSuperAdminByPkgName(admin.GetBundleName(), superAdmin)));
}

/**
 * @tc.name: TestAuthorizeAdminWithoutReq
 * @tc.desc: Test AuthorizeAdmin without request permission.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestAuthorizeAdminWithoutReq, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EnableAdminSuc(admin, AdminType::ENT, DEFAULT_USER_ID);

    std::vector<int32_t> ids = {DEFAULT_USER_ID};
    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillOnce(DoAll(Return(true)));
    EXPECT_CALL(*osAccountMgrMock_, QueryActiveOsAccountIds).WillRepeatedly(DoAll(SetArgReferee<0>(ids),
        Return(ERR_OK)));
    EXPECT_CALL(*bundleMgrMock_, GetNameForUid).WillOnce(DoAll(SetArgReferee<1>(admin.GetBundleName()),
        Return(ERR_OK)));
    GetBundleInfoMock(false, "");
    ErrCode ret = edmMgr_->AuthorizeAdmin(admin, ADMIN_PACKAGENAME_1);
    EXPECT_TRUE(ret == EdmReturnErrCode::AUTHORIZE_PERMISSION_FAILED);

    DisableSuperAdminSuc(admin.GetBundleName());
    std::shared_ptr<Admin> superAdmin;
    EXPECT_TRUE(FAILED(edmMgr_->adminMgr_->GetSubOrSuperAdminByPkgName(admin.GetBundleName(), superAdmin)));
}

/**
 * @tc.name: TestAuthorizeAdminSuc
 * @tc.desc: Test AuthorizeAdmin success.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestAuthorizeAdminSuc, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EnableAdminSuc(admin, AdminType::ENT, DEFAULT_USER_ID);

    AuthorizeAdminSuc(admin, ADMIN_PACKAGENAME_1);

    DisableSuperAdminSuc(admin.GetBundleName());
    std::shared_ptr<Admin> subOrSuperAdmin;
    EXPECT_TRUE(FAILED(edmMgr_->adminMgr_->GetSubOrSuperAdminByPkgName(ADMIN_PACKAGENAME_1, subOrSuperAdmin)));
    EXPECT_TRUE(FAILED(edmMgr_->adminMgr_->GetSubOrSuperAdminByPkgName(admin.GetAbilityName(), subOrSuperAdmin)));
}

/**
 * @tc.name: TestRemoveAdminAndAdminPolicy
 * @tc.desc: Test RemoveAdminAndAdminPolicy success.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestRemoveAdminAndAdminPolicy, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EnableAdminSuc(admin, AdminType::ENT, DEFAULT_USER_ID);
    EXPECT_TRUE(SUCCEEDED(edmMgr_->RemoveAdminAndAdminPolicy(admin.GetBundleName(), DEFAULT_USER_ID)));
    std::shared_ptr<Admin> superAdmin;
    EXPECT_TRUE(FAILED(edmMgr_->adminMgr_->GetSubOrSuperAdminByPkgName(admin.GetBundleName(), superAdmin)));

    EnableAdminSuc(admin, AdminType::NORMAL, DEFAULT_USER_ID);
    EXPECT_TRUE(SUCCEEDED(edmMgr_->RemoveAdminAndAdminPolicy(admin.GetBundleName(), DEFAULT_USER_ID)));
    auto normalAdmin = edmMgr_->adminMgr_->GetAdminByPkgName(admin.GetBundleName(), DEFAULT_USER_ID);
    EXPECT_TRUE(normalAdmin == nullptr);
}

/**
 * @tc.name: TestRemoveAdminPolicy
 * @tc.desc: Test RemoveAdminPolicy success.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestRemoveAdminPolicy, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EnableAdminSuc(admin, AdminType::ENT, DEFAULT_USER_ID);

    // set policy with userId = 100 and 101
    auto plugin = PLUGIN::StringTestPlugin::GetPlugin();
    edmMgr_->pluginMgr_->AddPlugin(plugin);
    SetPolicy(admin.GetBundleName(), plugin->GetPolicyName());

    // remove policy with userId = 101
    EXPECT_TRUE(SUCCEEDED(edmMgr_->RemoveAdminPolicy(admin.GetBundleName(), TEST_USER_ID)));
    GetPolicyFailed(TEST_USER_ID, admin.GetBundleName(), plugin->GetPolicyName());
    GetPolicySuccess(DEFAULT_USER_ID, admin.GetBundleName(), plugin->GetPolicyName());
}

/**
 * @tc.name: TestRemoveSubSuperAdminAndAdminPolicy
 * @tc.desc: Test RemoveSubSuperAdminAndAdminPolicy success.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestRemoveSubSuperAdminAndAdminPolicy, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EnableAdminSuc(admin, AdminType::ENT, DEFAULT_USER_ID);

    string subSuperBundleName = ADMIN_PACKAGENAME_1;
    AuthorizeAdminSuc(admin, subSuperBundleName);
    // set policy with userId = 100 and 101
    auto plugin = PLUGIN::StringTestPlugin::GetPlugin();
    edmMgr_->pluginMgr_->AddPlugin(plugin);
    SetPolicy(subSuperBundleName, plugin->GetPolicyName());

    // remove policy with userId = 100
    EXPECT_TRUE(SUCCEEDED(edmMgr_->RemoveSubSuperAdminAndAdminPolicy(subSuperBundleName)));

    auto superAdmin = edmMgr_->adminMgr_->GetAdminByPkgName(subSuperBundleName, DEFAULT_USER_ID);
    EXPECT_TRUE(superAdmin == nullptr);
    superAdmin = edmMgr_->adminMgr_->GetAdminByPkgName(subSuperBundleName, TEST_USER_ID);
    EXPECT_TRUE(superAdmin == nullptr);
    EXPECT_FALSE(edmMgr_->adminMgr_->IsSuperOrSubSuperAdmin(subSuperBundleName));
}

/**
 * @tc.name: TestRemoveSuperAdminAndAdminPolicy
 * @tc.desc: Test RemoveSuperAdminAndAdminPolicy success.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestRemoveSuperAdminAndAdminPolicy, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EnableAdminSuc(admin, AdminType::ENT, DEFAULT_USER_ID);

    // set policy with userId = 100 and 101
    auto plugin = PLUGIN::StringTestPlugin::GetPlugin();
    edmMgr_->pluginMgr_->AddPlugin(plugin);
    SetPolicy(admin.GetBundleName(), plugin->GetPolicyName());

    // remove policy with userId = 100
    EXPECT_TRUE(SUCCEEDED(edmMgr_->RemoveSubSuperAdminAndAdminPolicy(admin.GetBundleName())));

    auto superAdmin = edmMgr_->adminMgr_->GetAdminByPkgName(admin.GetBundleName(), DEFAULT_USER_ID);
    EXPECT_TRUE(superAdmin == nullptr);
    superAdmin = edmMgr_->adminMgr_->GetAdminByPkgName(admin.GetBundleName(), TEST_USER_ID);
    EXPECT_TRUE(superAdmin == nullptr);
    EXPECT_FALSE(edmMgr_->adminMgr_->IsSuperAdmin(admin.GetBundleName()));
}

/**
 * @tc.name: TestRemoveSubOrSuperAdminAndAdminPolicy
 * @tc.desc: Test RemoveSubOrSuperAdminAndAdminPolicy success.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestRemoveSubOrSuperAdminAndAdminPolicy, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EnableAdminSuc(admin, AdminType::ENT, DEFAULT_USER_ID);

    // set policy with userId = 100 and 101
    auto plugin = PLUGIN::StringTestPlugin::GetPlugin();
    edmMgr_->pluginMgr_->AddPlugin(plugin);
    SetPolicy(admin.GetBundleName(), plugin->GetPolicyName());

    std::vector<int32_t> userIds{TEST_USER_ID};
    // remove policy with userId = 100
    EXPECT_TRUE(SUCCEEDED(edmMgr_->RemoveSubOrSuperAdminAndAdminPolicy(admin.GetBundleName(), userIds)));

    auto superAdmin = edmMgr_->adminMgr_->GetAdminByPkgName(admin.GetBundleName(), DEFAULT_USER_ID);
    EXPECT_TRUE(superAdmin == nullptr);
    superAdmin = edmMgr_->adminMgr_->GetAdminByPkgName(admin.GetBundleName(), TEST_USER_ID);
    EXPECT_TRUE(superAdmin == nullptr);
    EXPECT_FALSE(edmMgr_->adminMgr_->IsSuperAdmin(admin.GetBundleName()));
}

/**
 * @tc.name: TestEnableAmdinCallingPermissionFailed
 * @tc.desc: Test EnabldeAdmin func with verify calling permission failed.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestEnableAmdinCallingPermissionFailed, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EntInfo entInfo("test", "this is test");

    EXPECT_CALL(*accessTokenMgrMock_, IsDebug).WillOnce(DoAll(Return(false)));
    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillOnce(DoAll(Return(false)));

    ErrCode res = edmMgr_->EnableAdmin(admin, entInfo, AdminType::NORMAL, 0);
    EXPECT_TRUE(res == EdmReturnErrCode::PERMISSION_DENIED);
}

/**
 * @tc.name: TestEnabaleAdminQueryExtensionAbilityInfosFailed
 * @tc.desc: Test EnabledAdmin func with query extension abilityInfos failed.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestEnabaleAdminQueryExtensionAbilityInfosFailed, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EntInfo entInfo("test", "this is test");

    EXPECT_CALL(*accessTokenMgrMock_, IsDebug).WillOnce(DoAll(Return(false)));
    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillOnce(DoAll(Return(true)));
    QueryExtensionAbilityInfosMock(false, "");

    ErrCode res = edmMgr_->EnableAdmin(admin, entInfo, AdminType::NORMAL, 1);
    EXPECT_TRUE(res == EdmReturnErrCode::COMPONENT_INVALID);
}

/**
 * @tc.name: TestEnabaleAdminQueryExtensionAbilityInfosEmpty
 * @tc.desc: Test EnabledAdmin func with query extension abilityInfos empty.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestEnabaleAdminQueryExtensionAbilityInfosEmpty, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EntInfo entInfo("test", "this is test");

    EXPECT_CALL(*accessTokenMgrMock_, IsDebug).WillOnce(DoAll(Return(false)));
    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillOnce(DoAll(Return(true)));
    QueryExtensionAbilityInfosMock(true, "", true);

    ErrCode res = edmMgr_->EnableAdmin(admin, entInfo, AdminType::NORMAL, 1);
    EXPECT_TRUE(res == EdmReturnErrCode::COMPONENT_INVALID);
}

/**
 * @tc.name: TestEnabaleAdminVerifyConditionFailed
 * @tc.desc: Test EnabledAdmin func with invalid admin type.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestEnabaleAdminVerifyConditionFailed, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EntInfo entInfo("test", "this is test");

    EXPECT_CALL(*accessTokenMgrMock_, IsDebug).WillOnce(DoAll(Return(false)));
    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillOnce(DoAll(Return(true)));
    QueryExtensionAbilityInfosMock(true, admin.GetBundleName());

    ErrCode res = edmMgr_->EnableAdmin(admin, entInfo, AdminType::UNKNOWN, 1);
    EXPECT_TRUE(res == EdmReturnErrCode::ENABLE_ADMIN_FAILED);
}

/**
 * @tc.name: TestEnabaleSuperWithErrorUserId
 * @tc.desc: Test enabled super admin with userId = 101.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestEnabaleSuperWithErrorUserId, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EntInfo entInfo("test", "this is test");

    EXPECT_CALL(*accessTokenMgrMock_, IsDebug).WillOnce(DoAll(Return(false)));
    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillOnce(DoAll(Return(true)));
    QueryExtensionAbilityInfosMock(true, admin.GetBundleName());

    ErrCode res = edmMgr_->EnableAdmin(admin, entInfo, AdminType::ENT, TEST_USER_ID);
    EXPECT_TRUE(res == EdmReturnErrCode::ENABLE_ADMIN_FAILED);
}

/**
 * @tc.name: TestEnabaleSuperAdminToNormalAdmin
 * @tc.desc: Test enabled super admin to normal admin.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestEnabaleSuperAdminToNormalAdmin, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EntInfo entInfo("test", "this is test");
    EnableAdminSuc(admin, AdminType::ENT, DEFAULT_USER_ID);

    EXPECT_CALL(*accessTokenMgrMock_, IsDebug).WillOnce(DoAll(Return(false)));
    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillOnce(DoAll(Return(true)));
    QueryExtensionAbilityInfosMock(true, admin.GetBundleName());

    ErrCode res = edmMgr_->EnableAdmin(admin, entInfo, AdminType::NORMAL, DEFAULT_USER_ID);
    EXPECT_TRUE(res == EdmReturnErrCode::ENABLE_ADMIN_FAILED);

    DisableSuperAdminSuc(ADMIN_PACKAGENAME);
}

/**
 * @tc.name: TestEnabaleSuperAdminToOtherUserId
 * @tc.desc: Test enabled super admin to other user id.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestEnabaleSuperAdminToOtherUserId, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EntInfo entInfo("test", "this is test");
    EnableAdminSuc(admin, AdminType::ENT, DEFAULT_USER_ID);

    EXPECT_CALL(*accessTokenMgrMock_, IsDebug).WillOnce(DoAll(Return(false)));
    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillOnce(DoAll(Return(true)));
    QueryExtensionAbilityInfosMock(true, admin.GetBundleName());

    ErrCode res = edmMgr_->EnableAdmin(admin, entInfo, AdminType::ENT, TEST_USER_ID);
    EXPECT_TRUE(res == EdmReturnErrCode::ENABLE_ADMIN_FAILED);

    DisableSuperAdminSuc(ADMIN_PACKAGENAME);
}

/**
 * @tc.name: TestEnabaleSuperAdminWithOtherEntInfo
 * @tc.desc: Test enabled super admin with other entInfo.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestEnabaleSuperAdminWithOtherEntInfo, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EnableAdminSuc(admin, AdminType::ENT, DEFAULT_USER_ID);

    EXPECT_CALL(*accessTokenMgrMock_, IsDebug).WillOnce(DoAll(Return(false)));
    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillOnce(DoAll(Return(true)));
    QueryExtensionAbilityInfosMock(true, admin.GetBundleName());
    GetBundleInfoMock(true, "");

    EntInfo entInfo("test1", "this is test1");
    ErrCode res = edmMgr_->EnableAdmin(admin, entInfo, AdminType::ENT, DEFAULT_USER_ID);
    EXPECT_TRUE(res == ERR_OK);

    DisableSuperAdminSuc(ADMIN_PACKAGENAME);
}

/**
 * @tc.name: TestEnabaleMultipleSuperAdmin
 * @tc.desc: Test enabled two super admin.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestEnabaleMultipleSuperAdmin, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EnableAdminSuc(admin, AdminType::ENT, DEFAULT_USER_ID);

    EXPECT_CALL(*accessTokenMgrMock_, IsDebug).WillOnce(DoAll(Return(false)));
    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillOnce(DoAll(Return(true)));
    QueryExtensionAbilityInfosMock(true, admin.GetBundleName());

    admin.SetBundleName(ADMIN_PACKAGENAME_1);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY_1);
    EntInfo entInfo("test", "this is test");
    ErrCode res = edmMgr_->EnableAdmin(admin, entInfo, AdminType::ENT, DEFAULT_USER_ID);
    EXPECT_TRUE(res == EdmReturnErrCode::ENABLE_ADMIN_FAILED);

    DisableSuperAdminSuc(ADMIN_PACKAGENAME);
}

/**
 * @tc.name: TestEnabaleSuperAdminWithOtherAbility
 * @tc.desc: Test enabled super admin with other ability.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestEnabaleSuperAdminWithOtherAbility, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EnableAdminSuc(admin, AdminType::ENT, DEFAULT_USER_ID);

    EXPECT_CALL(*accessTokenMgrMock_, IsDebug).WillOnce(DoAll(Return(false)));
    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillOnce(DoAll(Return(true)));
    QueryExtensionAbilityInfosMock(true, admin.GetBundleName());
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY_1);
    EntInfo entInfo("test", "this is test");
    ErrCode res = edmMgr_->EnableAdmin(admin, entInfo, AdminType::ENT, DEFAULT_USER_ID);
    EXPECT_TRUE(res == EdmReturnErrCode::ENABLE_ADMIN_FAILED);

    DisableSuperAdminSuc(ADMIN_PACKAGENAME);
}

/**
 * @tc.name: TestGetAllPermissionsByAdminFail
 * @tc.desc: Test GetAllPermissionsByAdminFail func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestGetAllPermissionsByAdminFail, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EntInfo entInfo("test", "this is test");

    EXPECT_CALL(*accessTokenMgrMock_, IsDebug).WillOnce(DoAll(Return(false)));
    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillOnce(DoAll(Return(true)));
    QueryExtensionAbilityInfosMock(true, admin.GetBundleName());
    GetBundleInfoMock(false, "");

    ErrCode res = edmMgr_->EnableAdmin(admin, entInfo, AdminType::NORMAL, 0);
    EXPECT_TRUE(res == EdmReturnErrCode::COMPONENT_INVALID);
}

/**
 * @tc.name: TestEnableAdminWithQueryExtensionAdbilityInfosEmptyBundleName
 * @tc.desc: Test EnableAdmin with QueryExtensionAdbilityInfos return empty bundleName.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestEnableAdminWithQueryExtensionAdbilityInfosEmptyBundleName, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EntInfo entInfo("test", "this is test");

    EXPECT_CALL(*accessTokenMgrMock_, IsDebug).WillRepeatedly(DoAll(Return(false)));
    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillRepeatedly(DoAll(Return(true)));
    QueryExtensionAbilityInfosMock(true, "");
    GetBundleInfoMock(true, "");

    ErrCode res = edmMgr_->EnableAdmin(admin, entInfo, AdminType::NORMAL, DEFAULT_USER_ID);
    EXPECT_TRUE(res == ERR_OK);

    bool isEnable = edmMgr_->IsAdminEnabled(admin, DEFAULT_USER_ID);
    EXPECT_TRUE(!isEnable);

    res = edmMgr_->DisableAdmin(admin, DEFAULT_USER_ID);
    EXPECT_TRUE(res != ERR_OK);

    AppExecFwk::ElementName admin1;
    admin1.SetBundleName("");
    admin1.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    res = edmMgr_->DisableAdmin(admin1, DEFAULT_USER_ID);
    EXPECT_TRUE(res == ERR_OK);
}

/**
 * @tc.name: TestEnableNormalAdminWithDefaultUserId
 * @tc.desc: Test enable normal admin with userId = 100.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestEnableNormalAdminWithDefaultUserId, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EntInfo entInfo("test", "this is test");

    EXPECT_CALL(*accessTokenMgrMock_, IsDebug).WillRepeatedly(DoAll(Return(false)));
    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillRepeatedly(DoAll(Return(true)));
    QueryExtensionAbilityInfosMock(true, admin.GetBundleName());
    GetBundleInfoMock(true, EDM_TEST_PERMISSION);

    ErrCode res = edmMgr_->EnableAdmin(admin, entInfo, AdminType::NORMAL, DEFAULT_USER_ID);
    EXPECT_TRUE(res == ERR_OK);

    bool isEnable = edmMgr_->IsAdminEnabled(admin, DEFAULT_USER_ID);
    EXPECT_TRUE(isEnable);

    res = edmMgr_->DisableAdmin(admin, DEFAULT_USER_ID);
    EXPECT_TRUE(res == ERR_OK);
}

/**
 * @tc.name: TestEnableAdminWithPermissionEmpty
 * @tc.desc: Test EnableAdmin permission empty func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestEnableAdminWithPermissionEmpty, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EntInfo entInfo("test", "this is test");

    EXPECT_CALL(*accessTokenMgrMock_, IsDebug).WillRepeatedly(DoAll(Return(false)));
    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillRepeatedly(DoAll(Return(true)));
    QueryExtensionAbilityInfosMock(true, admin.GetBundleName());
    GetBundleInfoMock(true, "");
    std::vector<int32_t> ids = {DEFAULT_USER_ID};
    EXPECT_CALL(*osAccountMgrMock_, QueryActiveOsAccountIds).WillRepeatedly(DoAll(SetArgReferee<0>(ids),
        Return(ERR_OK)));

    ErrCode res = edmMgr_->EnableAdmin(admin, entInfo, AdminType::NORMAL, DEFAULT_USER_ID);
    EXPECT_TRUE(res == ERR_OK);

    std::vector<std::string> enabledAdminList;
    edmMgr_->GetEnabledAdmin(AdminType::NORMAL, enabledAdminList); // normal admin not empty
    EXPECT_FALSE(enabledAdminList.empty());

    bool isEnable = edmMgr_->IsAdminEnabled(admin, DEFAULT_USER_ID);
    EXPECT_TRUE(isEnable);

    isEnable = edmMgr_->IsSuperAdmin(admin.GetBundleName());
    EXPECT_TRUE(!isEnable);

    res = edmMgr_->DisableAdmin(admin, DEFAULT_USER_ID);
    EXPECT_TRUE(res == ERR_OK);

    res = edmMgr_->DisableSuperAdmin(admin.GetBundleName());
    EXPECT_TRUE(res != ERR_OK);
}

/**
 * @tc.name: TestDisableSuperAdminTwoAdmin
 * @tc.desc: Test DisableSuperAdmin Two Admin func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestDisableSuperAdminTwoAdmin, TestSize.Level1)
{
    EXPECT_CALL(*accessTokenMgrMock_, IsDebug).WillRepeatedly(DoAll(Return(false)));
    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillRepeatedly(DoAll(Return(true)));

    std::vector<std::u16string> args;
    ErrCode res = edmMgr_->Dump(-1, args);
    EXPECT_TRUE(res != ERR_OK);
    res = TestDump(); // empty
    EXPECT_TRUE(res == ERR_OK);

    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EnableAdminSuc(admin, AdminType::ENT, DEFAULT_USER_ID);
    EXPECT_TRUE(edmMgr_->IsSuperAdmin(admin.GetBundleName()));

    res = TestDump(); // not empty
    EXPECT_TRUE(res == ERR_OK);
    Utils::ExecCmdSync("rm -f /data/edmDumpTest.txt");

    // other admin
    AppExecFwk::ElementName admin1;
    admin1.SetBundleName(ADMIN_PACKAGENAME_1);
    admin1.SetAbilityName(ADMIN_PACKAGENAME_ABILITY_1);
    EnableAdminSuc(admin1, AdminType::NORMAL, DEFAULT_USER_ID);

    EXPECT_CALL(*accessTokenMgrMock_, IsDebug).WillOnce(DoAll(Return(false)));
    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillOnce(DoAll(Return(true)));
    res = edmMgr_->DisableSuperAdmin(admin1.GetBundleName());
    EXPECT_TRUE(res == EdmReturnErrCode::DISABLE_ADMIN_FAILED);

    DisableAdminSuc(admin1, DEFAULT_USER_ID);

    EXPECT_CALL(*accessTokenMgrMock_, IsDebug).WillOnce(DoAll(Return(false)));
    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillOnce(DoAll(Return(true)));
    res = edmMgr_->DisableAdmin(admin, DEFAULT_USER_ID); // admintype is super
    EXPECT_TRUE(res == ERR_OK);
}

/**
 * @tc.name: TestDisableSuperAdminIpcSuc
 * @tc.desc: Test DisableSuperAdmin Ipc Suc func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestDisableSuperAdminIpcSuc, TestSize.Level1)
{
    EXPECT_CALL(*accessTokenMgrMock_, IsDebug).WillRepeatedly(DoAll(Return(false)));
    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillRepeatedly(DoAll(Return(true)));

    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EnableAdminSuc(admin, AdminType::ENT, DEFAULT_USER_ID);
    EXPECT_TRUE(edmMgr_->IsSuperAdmin(admin.GetBundleName()));
    DisableSuperAdminSuc(admin.GetBundleName());
}

/**
 * @tc.name: TestEnableNormalAdminToDebug
 * @tc.desc: Test hdc enable normal admin to debug.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestEnableNormalAdminToDebug, TestSize.Level1)
{
    // enable normal admin
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EnableAdminSuc(admin, AdminType::NORMAL, DEFAULT_USER_ID);
    // shell enable debug admin
    EntInfo entInfo("test", "this is test");
    QueryExtensionAbilityInfosMock(true, admin.GetBundleName());
    EXPECT_CALL(*accessTokenMgrMock_, IsDebug).WillOnce(DoAll(Return(true)));
    ErrCode res = edmMgr_->EnableAdmin(admin, entInfo, AdminType::ENT, DEFAULT_USER_ID);
    EXPECT_TRUE(res == EdmReturnErrCode::ENABLE_ADMIN_FAILED);
    // disable normal admin
    DisableAdminSuc(admin, DEFAULT_USER_ID);
}

/**
 * @tc.name: TestEnableSuperAdminToDebug
 * @tc.desc: Test hdc enable super admin to debug.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestEnableSuperAdminToDebug, TestSize.Level1)
{
    // enable super admin
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EnableAdminSuc(admin, AdminType::ENT, DEFAULT_USER_ID);
    // shell enable debug admin
    EntInfo entInfo("test", "this is test");
    QueryExtensionAbilityInfosMock(true, admin.GetBundleName());
    EXPECT_CALL(*accessTokenMgrMock_, IsDebug).WillOnce(DoAll(Return(true)));
    ErrCode res = edmMgr_->EnableAdmin(admin, entInfo, AdminType::ENT, DEFAULT_USER_ID);
    EXPECT_TRUE(res == EdmReturnErrCode::ENABLE_ADMIN_FAILED);
    // disable normal admin
    DisableSuperAdminSuc(admin.GetBundleName());
}

/**
 * @tc.name: TestEnableDebugSuperAdmin
 * @tc.desc: Test enable debug super admin.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestEnableDebugSuperAdmin, TestSize.Level1)
{
    // enable super admin
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EnableAdminSuc(admin, AdminType::ENT, DEFAULT_USER_ID);
    // hdc enable debug super admin1
    AppExecFwk::ElementName admin1;
    admin1.SetBundleName(ADMIN_PACKAGENAME_1);
    admin1.SetAbilityName(ADMIN_PACKAGENAME_ABILITY_1);
    EnableAdminSuc(admin1, AdminType::ENT, DEFAULT_USER_ID, true);
    // disable super admin
    DisableSuperAdminSuc(admin.GetBundleName());
    // hdc disable debug super admin1
    EXPECT_CALL(*accessTokenMgrMock_, IsDebug).WillOnce(DoAll(Return(true)));
    ErrCode res = edmMgr_->DisableSuperAdmin(admin1.GetBundleName());
    EXPECT_TRUE(res == ERR_OK);
}

/**
 * @tc.name: TestHdcDisableNormalAdmin
 * @tc.desc: Test hdc disable normal admin.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestHdcDisableNormalAdmin, TestSize.Level1)
{
    // enable normal admin
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EnableAdminSuc(admin, AdminType::NORMAL, DEFAULT_USER_ID);
    // hdc disable normal admin
    EXPECT_CALL(*accessTokenMgrMock_, IsDebug).WillOnce(DoAll(Return(true)));
    ErrCode res = edmMgr_->DisableSuperAdmin(admin.GetBundleName());
    EXPECT_TRUE(res == EdmReturnErrCode::DISABLE_ADMIN_FAILED);
    // disable normal admin
    DisableAdminSuc(admin, DEFAULT_USER_ID);
}

/**
 * @tc.name: TestHdcDisableSuperAdmin
 * @tc.desc: Test hdc disable super admin.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestHdcDisableSuperAdmin, TestSize.Level1)
{
    // enable super admin
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EnableAdminSuc(admin, AdminType::ENT, DEFAULT_USER_ID);
    // hdc disable super admin
    EXPECT_CALL(*accessTokenMgrMock_, IsDebug).WillOnce(DoAll(Return(true)));
    ErrCode res = edmMgr_->DisableSuperAdmin(admin.GetBundleName());
    EXPECT_TRUE(res == EdmReturnErrCode::DISABLE_ADMIN_FAILED);
    // disable super admin
    DisableSuperAdminSuc(admin.GetBundleName());
}

/**
 * @tc.name: TestDisableDebugSuperAdmin
 * @tc.desc: Test disable debug super admin with debug = false.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestDisableDebugSuperAdmin, TestSize.Level1)
{
    // hdc enbale debug super admin
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EnableAdminSuc(admin, AdminType::ENT, DEFAULT_USER_ID, true);
    // disable debug super admin
    DisableSuperAdminSuc(admin.GetBundleName());
}

/**
 * @tc.name: TestSetEnterpriseInfoWithoutPermission
 * @tc.desc: Test SetEnterpriseInfo func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestSetEnterpriseInfoWithoutPermission, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);

    MessageParcel reply;
    ErrCode res = edmMgr_->GetEnterpriseInfo(admin, reply);
    EXPECT_TRUE(res == EdmReturnErrCode::ADMIN_INACTIVE);

    EntInfo entInfo("test", "this is test");
    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillOnce(DoAll(Return(false)));
    res = edmMgr_->SetEnterpriseInfo(admin, entInfo);
    EXPECT_TRUE(res == EdmReturnErrCode::PERMISSION_DENIED);
}

/**
 * @tc.name: TestSetEnterpriseInfoWithoutActiveAdmin
 * @tc.desc: Test SetEnterpriseInfo func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestSetEnterpriseInfoWithoutActiveAdmin, TestSize.Level1)
{
    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillOnce(DoAll(Return(true)));

    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);

    MessageParcel reply;
    ErrCode res = edmMgr_->GetEnterpriseInfo(admin, reply);
    EXPECT_TRUE(res == EdmReturnErrCode::ADMIN_INACTIVE);

    EntInfo entInfo("test", "this is test");
    res = edmMgr_->SetEnterpriseInfo(admin, entInfo);
    EXPECT_TRUE(res == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestSetEnterpriseInfoCheckCallingUidFailed
 * @tc.desc: Test SetEnterpriseInfo func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestSetEnterpriseInfoCheckCallingUidFailed, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);

    EnableAdminSuc(admin, AdminType::ENT, DEFAULT_USER_ID);

    MessageParcel reply;
    ErrCode res = edmMgr_->GetEnterpriseInfo(admin, reply);
    EXPECT_TRUE(res == ERR_OK);

    EntInfo entInfo("test", "this is test");
    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillOnce(DoAll(Return(true)));
    res = edmMgr_->SetEnterpriseInfo(admin, entInfo);
    EXPECT_TRUE(res == EdmReturnErrCode::PERMISSION_DENIED);

    DisableSuperAdminSuc(admin.GetBundleName());
}

/**
 * @tc.name: TestSetEnterpriseInfoSuc
 * @tc.desc: Test SetEnterpriseInfo func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestSetEnterpriseInfoSuc, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EnableAdminSuc(admin, AdminType::ENT, DEFAULT_USER_ID);

    EXPECT_CALL(*bundleMgrMock_, GetNameForUid).WillOnce(DoAll(SetArgReferee<1>(admin.GetBundleName()),
        Return(ERR_OK)));
    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillOnce(DoAll(Return(true)));

    EntInfo entInfo("test", "this is test");
    ErrCode res = edmMgr_->SetEnterpriseInfo(admin, entInfo);
    EXPECT_TRUE(res == ERR_OK);

    MessageParcel reply;
    res = edmMgr_->GetEnterpriseInfo(admin, reply);
    EXPECT_TRUE(res == ERR_OK);

    DisableSuperAdminSuc(admin.GetBundleName());
}

/**
 * @tc.name: TestOnReceiveEvent
 * @tc.desc: Test OnReceiveEvent func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestOnReceiveEvent, TestSize.Level1)
{
    EnterpriseDeviceMgrAbility listener;
    edmMgr_->CreateEnterpriseDeviceEventSubscriber(listener);
    EventFwk::MatchingSkills skill = EventFwk::MatchingSkills();
    EventFwk::CommonEventSubscribeInfo info(skill);
    std::shared_ptr<EnterpriseDeviceEventSubscriber> edmEventSubscriber =
        std::make_shared<EnterpriseDeviceEventSubscriber>(info, *edmMgr_);
    size_t mapSize = edmMgr_->commonEventFuncMap_.size();
    EXPECT_TRUE(mapSize == COMMON_EVENT_FUNC_MAP_SIZE);

    EventFwk::CommonEventData data;
    std::string action = "usual.event.ERROR_EVENT";
    AAFwk::Want want;
    want.SetAction(action);
    data.SetWant(want);
    edmEventSubscriber->OnReceiveEvent(data);
    auto func = edmMgr_->commonEventFuncMap_.find(action);
    EXPECT_TRUE(func == edmMgr_->commonEventFuncMap_.end());

    edmMgr_->commonEventFuncMap_[action] = nullptr;
    edmEventSubscriber->OnReceiveEvent(data);
    func = edmMgr_->commonEventFuncMap_.find(action);
    EXPECT_TRUE(func != edmMgr_->commonEventFuncMap_.end());
}

/**
 * @tc.name: TestOnCommonEventUserRemoved
 * @tc.desc: Test OnCommonEventUserRemoved func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestOnCommonEventUserRemoved, TestSize.Level1)
{
    EnterpriseDeviceMgrAbility listener;
    edmMgr_->CreateEnterpriseDeviceEventSubscriber(listener);
    EventFwk::MatchingSkills skill = EventFwk::MatchingSkills();
    EventFwk::CommonEventSubscribeInfo info(skill);
    std::shared_ptr<EnterpriseDeviceEventSubscriber> edmEventSubscriber =
        std::make_shared<EnterpriseDeviceEventSubscriber>(info, *edmMgr_);
    AppExecFwk::ExtensionAbilityInfo abilityInfo;
    abilityInfo.bundleName = ADMIN_PACKAGENAME;
    abilityInfo.name = ADMIN_PACKAGENAME_ABILITY;
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "technology company in wuhan";
    std::vector<std::string> permissions = {EDM_TEST_PERMISSION};
    Admin edmAdmin(abilityInfo, AdminType::NORMAL, entInfo, permissions, false);
    edmMgr_->adminMgr_->SetAdminValue(DEFAULT_USER_ID, edmAdmin);
    edmAdmin.adminInfo_.packageName_ = ADMIN_PACKAGENAME_1;
    edmAdmin.adminInfo_.className_ = ADMIN_PACKAGENAME_ABILITY_1;
    edmAdmin.adminInfo_.entInfo_.enterpriseName = "company1";
    edmAdmin.adminInfo_.entInfo_.description = "technology company in wuhan";
    edmMgr_->adminMgr_->SetAdminValue(ERROR_USER_ID_REMOVE, edmAdmin);

    EventFwk::CommonEventData data;
    std::string action = "usual.event.USER_REMOVED";
    AAFwk::Want want;
    want.SetAction(action);
    data.SetWant(want);
    data.SetCode(ERROR_USER_ID_REMOVE);
    edmEventSubscriber->OnReceiveEvent(data);
    std::vector<std::shared_ptr<Admin>> userAdmin;
    bool isExist = edmMgr_->adminMgr_->GetAdminByUserId(ERROR_USER_ID_REMOVE, userAdmin);
    EXPECT_TRUE(isExist);

    data.SetCode(DEFAULT_USER_ID);
    edmMgr_->OnCommonEventUserRemoved(data);
    isExist = edmMgr_->adminMgr_->GetAdminByUserId(DEFAULT_USER_ID, userAdmin);
    EXPECT_TRUE(!isExist);

    ErrCode ret = edmMgr_->adminMgr_->DeleteAdmin(edmAdmin.adminInfo_.packageName_, ERROR_USER_ID_REMOVE);
    EXPECT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnCommonEventPackageAdded
 * @tc.desc: Test OnCommonEventPackageAdded and OnCommonEventPackageRemoved func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestOnCommonEventPackageAdded, TestSize.Level1)
{
    EnterpriseDeviceMgrAbility listener;
    edmMgr_->CreateEnterpriseDeviceEventSubscriber(listener);
    EventFwk::MatchingSkills skill = EventFwk::MatchingSkills();
    EventFwk::CommonEventSubscribeInfo info(skill);
    std::shared_ptr<EnterpriseDeviceEventSubscriber> edmEventSubscriber =
        std::make_shared<EnterpriseDeviceEventSubscriber>(info, *edmMgr_);

    EventFwk::CommonEventData data;
    AAFwk::Want want;
    want.SetElementName(ADMIN_PACKAGENAME, ADMIN_PACKAGENAME_ABILITY);
    want.SetAction("usual.event.PACKAGE_ADDED");
    data.SetWant(want);
    edmEventSubscriber->OnReceiveEvent(data);

    want.SetAction("usual.event.PACKAGE_REMOVED");
    data.SetWant(want);
    edmEventSubscriber->OnReceiveEvent(data);
  
    AppExecFwk::ExtensionAbilityInfo abilityInfo;
    abilityInfo.bundleName = ADMIN_PACKAGENAME;
    abilityInfo.name = ADMIN_PACKAGENAME_ABILITY;
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "technology company in wuhan";
    std::vector<std::string> permissions = {EDM_TEST_PERMISSION};
    Admin edmAdmin(abilityInfo, AdminType::NORMAL, entInfo, permissions, false);
    edmMgr_->adminMgr_->SetAdminValue(DEFAULT_USER_ID, edmAdmin);

    edmAdmin.adminInfo_.packageName_ = ADMIN_PACKAGENAME_1;
    edmAdmin.adminInfo_.className_ = ADMIN_PACKAGENAME_ABILITY_1;
    edmAdmin.adminInfo_.entInfo_.enterpriseName = "company1";
    edmAdmin.adminInfo_.entInfo_.description = "technology company in wuhan1";
    edmMgr_->adminMgr_->SetAdminValue(DEFAULT_USER_ID, edmAdmin);
    const std::vector<uint32_t> events = {BUNDLE_ADDED_EVENT, BUNDLE_REMOVED_EVENT};
    edmMgr_->adminMgr_->SaveSubscribeEvents(events, abilityInfo.bundleName, DEFAULT_USER_ID);

    std::string action = "usual.event.PACKAGE_ADDED";
    want.SetAction(action);
    want.SetElementName("com.edm.test.added", "com.edm.test.demo.MainAbility");
    data.SetWant(want);
    edmEventSubscriber->OnReceiveEvent(data);
    auto func = edmMgr_->commonEventFuncMap_.find(action);
    EXPECT_TRUE(func != edmMgr_->commonEventFuncMap_.end());

    action = "usual.event.PACKAGE_REMOVED";
    want.SetAction(action);
    want.SetElementName("com.edm.test.removed", "com.edm.test.demo.MainAbility");
    data.SetWant(want);
    edmEventSubscriber->OnReceiveEvent(data);
    func = edmMgr_->commonEventFuncMap_.find(action);
    EXPECT_TRUE(func != edmMgr_->commonEventFuncMap_.end());

    EXPECT_EQ(edmMgr_->adminMgr_->DeleteAdmin(abilityInfo.bundleName, DEFAULT_USER_ID), ERR_OK);
    EXPECT_EQ(edmMgr_->adminMgr_->DeleteAdmin(ADMIN_PACKAGENAME_1, DEFAULT_USER_ID), ERR_OK);
}

/**
 * @tc.name: TestSubscribeManagedEventWithoutPermission
 * @tc.desc: Test SubscribeManagedEvent func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestSubscribeManagedEventWithoutPermission, TestSize.Level1)
{
    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillRepeatedly(DoAll(Return(false)));
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);

    std::vector<uint32_t> event;
    ErrCode res = edmMgr_->SubscribeManagedEvent(admin, event);
    EXPECT_TRUE(res == EdmReturnErrCode::PERMISSION_DENIED);

    res = edmMgr_->UnsubscribeManagedEvent(admin, event);
    EXPECT_TRUE(res == EdmReturnErrCode::PERMISSION_DENIED);
}

/**
 * @tc.name: TestSubscribeManagedEventWithoutActiveAdmin
 * @tc.desc: Test SubscribeManagedEvent func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestSubscribeManagedEventWithoutActiveAdmin, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    std::vector<uint32_t> event;

    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillRepeatedly(DoAll(Return(true)));
    ErrCode res = edmMgr_->SubscribeManagedEvent(admin, event);
    EXPECT_TRUE(res == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestSubscribeManagedEventCheckCallingUidFailed
 * @tc.desc: Test SubscribeManagedEvent func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestSubscribeManagedEventCheckCallingUidFailed, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EnableAdminSuc(admin, AdminType::NORMAL, DEFAULT_USER_ID);

    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillRepeatedly(DoAll(Return(true)));
    std::vector<int32_t> ids = {DEFAULT_USER_ID};
    EXPECT_CALL(*osAccountMgrMock_, QueryActiveOsAccountIds).WillRepeatedly(DoAll(SetArgReferee<0>(ids),
        Return(ERR_OK)));
    EXPECT_CALL(*bundleMgrMock_, GetNameForUid).WillRepeatedly(DoAll(Return(1)));
    std::vector<uint32_t> event;
    ErrCode res = edmMgr_->SubscribeManagedEvent(admin, event);
    EXPECT_TRUE(res == EdmReturnErrCode::PERMISSION_DENIED);

    DisableAdminSuc(admin, DEFAULT_USER_ID);
}

/**
 * @tc.name: TestSubscribeManagedEventWithEmptyEvents
 * @tc.desc: Test SubscribeManagedEvent func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestSubscribeManagedEventWithEmptyEvents, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EnableAdminSuc(admin, AdminType::ENT, DEFAULT_USER_ID);

    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillRepeatedly(DoAll(Return(true)));
    EXPECT_CALL(*bundleMgrMock_, GetNameForUid).WillRepeatedly(DoAll(SetArgReferee<1>(admin.GetBundleName()),
        Return(ERR_OK)));
    std::vector<uint32_t> event;
    ErrCode res = edmMgr_->SubscribeManagedEvent(admin, event);
    EXPECT_TRUE(res == EdmReturnErrCode::MANAGED_EVENTS_INVALID);

    DisableSuperAdminSuc(admin.GetBundleName());
}

/**
 * @tc.name: TestSubscribeManagedEventWithInvalidEvents
 * @tc.desc: Test SubscribeManagedEvent func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestSubscribeManagedEventWithInvalidEvents, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EnableAdminSuc(admin, AdminType::ENT, DEFAULT_USER_ID);

    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillRepeatedly(DoAll(Return(true)));
    EXPECT_CALL(*bundleMgrMock_, GetNameForUid).WillRepeatedly(DoAll(SetArgReferee<1>(admin.GetBundleName()),
        Return(ERR_OK)));
    std::vector<uint32_t> event = {INVALID_MANAGED_EVENT_TEST};
    ErrCode res = edmMgr_->SubscribeManagedEvent(admin, event);
    EXPECT_TRUE(res == EdmReturnErrCode::MANAGED_EVENTS_INVALID);

    DisableSuperAdminSuc(admin.GetBundleName());
}

/**
 * @tc.name: TestSubscribeManagedEvent
 * @tc.desc: Test TestSubscribeManagedEvent func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestSubscribeManagedEvent, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EntInfo entInfo("test", "this is test");
    EnableAdminSuc(admin, AdminType::ENT, DEFAULT_USER_ID);

    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillOnce(DoAll(Return(true)));
    EXPECT_CALL(*bundleMgrMock_, GetNameForUid).WillOnce(DoAll(SetArgReferee<1>(admin.GetBundleName()),
        Return(ERR_OK)));
    std::vector<uint32_t> events = {BUNDLE_ADDED_EVENT, BUNDLE_REMOVED_EVENT};
    ErrCode res = edmMgr_->SubscribeManagedEvent(admin, events);
    EXPECT_TRUE(res == ERR_OK);

    DisableSuperAdminSuc(admin.GetBundleName());
}

/**
 * @tc.name: SubscribeAppStartStopEvent
 * @tc.desc: Test SubscribeAppStartStopEvent func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, SubscribeAppStartStopEvent, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EntInfo entInfo("test", "this is test");
    EnableAdminSuc(admin, AdminType::NORMAL, DEFAULT_USER_ID);

    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillOnce(DoAll(Return(true)));
    std::vector<int32_t> ids = {DEFAULT_USER_ID};
    EXPECT_CALL(*osAccountMgrMock_, QueryActiveOsAccountIds).WillRepeatedly(DoAll(SetArgReferee<0>(ids),
        Return(ERR_OK)));
    EXPECT_CALL(*bundleMgrMock_, GetNameForUid).WillOnce(DoAll(SetArgReferee<1>(admin.GetBundleName()),
        Return(ERR_OK)));
    std::vector<uint32_t> events = {APP_START_EVENT, APP_STOP_EVENT};
    ErrCode res = edmMgr_->SubscribeManagedEvent(admin, events);
    EXPECT_TRUE(res == ERR_OK);
    DisableAdminSuc(admin, DEFAULT_USER_ID);
}

/**
 * @tc.name: TestUnsubscribeManagedEvent
 * @tc.desc: Test UnsubscribeManagedEvent func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestUnsubscribeManagedEvent, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EnableAdminSuc(admin, AdminType::ENT, DEFAULT_USER_ID);

    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillOnce(DoAll(Return(true)));
    EXPECT_CALL(*bundleMgrMock_, GetNameForUid).WillOnce(DoAll(SetArgReferee<1>(admin.GetBundleName()),
        Return(ERR_OK)));
    std::vector<uint32_t> events = {BUNDLE_ADDED_EVENT, BUNDLE_REMOVED_EVENT};
    ErrCode res = edmMgr_->UnsubscribeManagedEvent(admin, events);
    EXPECT_TRUE(res == ERR_OK);

    DisableSuperAdminSuc(admin.GetBundleName());
}

/**
 * @tc.name: UnsubscribeAppStartStopEvent
 * @tc.desc: Test UnsubscribeAppStartStopEvent func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, UnsubscribeAppStartStopEvent, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName(ADMIN_PACKAGENAME_ABILITY);
    EnableAdminSuc(admin, AdminType::NORMAL, DEFAULT_USER_ID);

    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillOnce(DoAll(Return(true)));
    std::vector<int32_t> ids = {DEFAULT_USER_ID};
    EXPECT_CALL(*osAccountMgrMock_, QueryActiveOsAccountIds).WillRepeatedly(DoAll(SetArgReferee<0>(ids),
        Return(ERR_OK)));
    EXPECT_CALL(*bundleMgrMock_, GetNameForUid).WillOnce(DoAll(SetArgReferee<1>(admin.GetBundleName()),
        Return(ERR_OK)));
    std::vector<uint32_t> events = {APP_START_EVENT, APP_STOP_EVENT};
    ErrCode res = edmMgr_->UnsubscribeManagedEvent(admin, events);
    EXPECT_TRUE(res == ERR_OK);

    DisableAdminSuc(admin, DEFAULT_USER_ID);
}

/**
 * @tc.name: TestGetSuperAdmin
 * @tc.desc: Test GetSuperAdmin func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestGetSuperAdmin, TestSize.Level1)
{
    MessageParcel reply;
    ErrCode res = edmMgr_->GetSuperAdmin(reply);
    EXPECT_TRUE(reply.ReadInt32() == ERR_OK);
    EXPECT_TRUE(reply.ReadString() == "");
    EXPECT_TRUE(reply.ReadString() == "");
    EXPECT_TRUE(res == ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS