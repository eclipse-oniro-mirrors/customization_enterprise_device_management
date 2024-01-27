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
#define protected public
#include "enterprise_device_mgr_ability.h"
#include "plugin_singleton.h"
#undef protected
#undef private
#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "bundle_manager_mock.h"
#include "enterprise_device_mgr_ability_test.h"
#include "iplugin_template_test.h"
#include "plugin_manager_test.h"
#include "system_ability_definition.h"
#include "utils.h"

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
const std::string ADMIN_PACKAGENAME = "com.edm.test.demo.ipc.suc";
const std::string ADMIN_PACKAGENAME_FAILED = "com.edm.test.demo.ipc.fail";
const std::string EDM_MANAGE_DATETIME_PERMISSION = "ohos.permission.SET_TIME";
const std::string EDM_TEST_PERMISSION = "ohos.permission.EDM_TEST_PERMISSION";
const std::string ARRAY_MAP_TESTPLG_POLICYNAME = "ArrayMapTestPlugin";
const std::string TEST_POLICY_VALUE = "test_policy_value";
const std::string PERMISSION_MANAGE_ENTERPRISE_DEVICE_ADMIN_TEST = "ohos.permission.MANAGE_ENTERPRISE_DEVICE_ADMIN";

void EnterpriseDeviceMgrAbilityTest::SetUp()
{
    edmSysManager_ = std::make_shared<EdmSysManager>();
    sptr<IRemoteObject> object = new (std::nothrow) AppExecFwk::BundleMgrService(ADMIN_PACKAGENAME);
    edmSysManager_->RegisterSystemAbilityOfRemoteObject(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID, object);
    plugin_ = PLUGIN::ArrayMapTestPlugin::GetPlugin();
    edmMgr_ = EnterpriseDeviceMgrAbility::GetInstance();
    edmMgr_->adminMgr_ = AdminManager::GetInstance();
    edmMgr_->pluginMgr_ = PluginManager::GetInstance();
    edmMgr_->policyMgr_ = std::make_shared<PolicyManager>();
}

void EnterpriseDeviceMgrAbilityTest::TearDown()
{
    edmMgr_->adminMgr_->instance_.reset();
    edmMgr_->pluginMgr_->instance_.reset();
    edmMgr_->policyMgr_.reset();
    edmMgr_->instance_.clear();
    edmMgr_.clear();
    edmSysManager_->UnregisterSystemAbilityOfRemoteObject(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
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
    plugin_->permission_ = EDM_MANAGE_DATETIME_PERMISSION;
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

/**
 * @tc.name: HandleDevicePolicyFuncTest000
 * @tc.desc: Test EnterpriseDeviceMgrAbility::HandleDevicePolicy function.(return ERR_OK)
 * @tc.desc: Test whether HandleDevicePolicy runs to the end
 * @tc.type: FUNC
 * @tc.require: issueI5PBT1
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, HandleDevicePolicyFuncTest000, TestSize.Level1)
{
    PrepareBeforeHandleDevicePolicy();
    const char* permissions[] = {EDM_MANAGE_DATETIME_PERMISSION.c_str()};
    Utils::SetNativeTokenTypeAndPermissions(permissions, sizeof(permissions) / sizeof(permissions[0]));
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, ARRAY_MAP_TESTPLUGIN_POLICYCODE);
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName(ADMIN_PACKAGENAME_FAILED);
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = edmMgr_->HandleDevicePolicy(code, elementName, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(res == EdmReturnErrCode::PERMISSION_DENIED);
    Utils::ResetTokenTypeAndUid();
}

/**
 * @tc.name: HandleDevicePolicyFuncTest001
 * @tc.desc: Test EnterpriseDeviceMgrAbility::HandleDevicePolicy function.(return ERR_OK)
 * @tc.desc: Test whether HandleDevicePolicy runs to the end
 * @tc.type: FUNC
 * @tc.require: issueI5PBT1
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, HandleDevicePolicyFuncTest001, TestSize.Level1)
{
    PrepareBeforeHandleDevicePolicy();
    const char* permissions[] = {EDM_MANAGE_DATETIME_PERMISSION.c_str()};
    Utils::SetNativeTokenTypeAndPermissions(permissions, sizeof(permissions) / sizeof(permissions[0]));
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, ARRAY_MAP_TESTPLUGIN_POLICYCODE);
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName(ADMIN_PACKAGENAME);
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = edmMgr_->HandleDevicePolicy(code, elementName, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);
    Utils::ResetTokenTypeAndUid();
}
/**
 * @tc.name: HandleDevicePolicyFuncTest002
 * @tc.desc: Test EnterpriseDeviceMgrAbility::HandleDevicePolicy function.(if (deviceAdmin == nullptr))
 * @tc.desc: Test if deviceAdmin is empty
 * @tc.type: FUNC
 * @tc.require: issueI5PBT1
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, HandleDevicePolicyFuncTest002, TestSize.Level1)
{
    PrepareBeforeHandleDevicePolicy();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, ARRAY_MAP_TESTPLUGIN_POLICYCODE);
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName("com.edm.test.demoFail");
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = edmMgr_->HandleDevicePolicy(code, elementName, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(res == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: HandleDevicePolicyFuncTest003
 * @tc.desc: Test EnterpriseDeviceMgrAbility::HandleDevicePolicy function.(if (plugin == nullptr))
 * @tc.desc: Test if plugin is empty
 * @tc.type: FUNC
 * @tc.require: issueI5PBT1
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, HandleDevicePolicyFuncTest003, TestSize.Level1)
{
    PrepareBeforeHandleDevicePolicy();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, INVALID_POLICYCODE);
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName(ADMIN_PACKAGENAME);
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = edmMgr_->HandleDevicePolicy(code, elementName, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(res == EdmReturnErrCode::INTERFACE_UNSUPPORTED);
}

/**
 * @tc.name: HandleDevicePolicyFuncTest004
 * @tc.desc: Test EnterpriseDeviceMgrAbility::HandleDevicePolicy function.
 * @tc.desc: if (!deviceAdmin->CheckPermission(plugin->GetPermission()))
 * @tc.type: FUNC
 * @tc.require: issueI5PBT1
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, HandleDevicePolicyFuncTest004, TestSize.Level1)
{
    PrepareBeforeHandleDevicePolicy();
    Admin testAdmin;
    testAdmin.adminInfo_.packageName_ = ADMIN_PACKAGENAME;
    std::vector<std::shared_ptr<Admin>> adminVec = {std::make_shared<Admin>(testAdmin)};
    edmMgr_->adminMgr_->admins_.clear();
    edmMgr_->adminMgr_->admins_.insert(
        std::pair<int32_t, std::vector<std::shared_ptr<Admin>>>(DEFAULT_USER_ID, adminVec));
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, ARRAY_MAP_TESTPLUGIN_POLICYCODE);
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName(ADMIN_PACKAGENAME);
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = edmMgr_->HandleDevicePolicy(code, elementName, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(res == EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED);
}

/**
 * @tc.name: HandleDevicePolicyFuncTest005
 * @tc.desc: Test EnterpriseDeviceMgrAbility::HandleDevicePolicy function.
 * @tc.desc: if (!VerifyCallingPermission(plugin->GetPermission()))
 * @tc.type: FUNC
 * @tc.require: issueI5PBT1
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, HandleDevicePolicyFuncTest005, TestSize.Level1)
{
    PrepareBeforeHandleDevicePolicy();
    Admin testAdmin;
    testAdmin.adminInfo_.packageName_ = ADMIN_PACKAGENAME;
    testAdmin.adminInfo_.permission_ = {EDM_TEST_PERMISSION};
    std::vector<std::shared_ptr<Admin>> adminVec = {std::make_shared<Admin>(testAdmin)};
    edmMgr_->adminMgr_->admins_.clear();
    edmMgr_->adminMgr_->admins_.insert(
        std::pair<int32_t, std::vector<std::shared_ptr<Admin>>>(DEFAULT_USER_ID, adminVec));
    plugin_->permission_ = EDM_TEST_PERMISSION;
    edmMgr_->pluginMgr_->pluginsCode_.clear();
    edmMgr_->pluginMgr_->pluginsName_.clear();
    edmMgr_->pluginMgr_->AddPlugin(plugin_);
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, ARRAY_MAP_TESTPLUGIN_POLICYCODE);
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName(ADMIN_PACKAGENAME);
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = edmMgr_->HandleDevicePolicy(code, elementName, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(res == EdmReturnErrCode::PERMISSION_DENIED);
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
    const char* permissions[] = {EDM_MANAGE_DATETIME_PERMISSION.c_str()};
    Utils::SetNativeTokenTypeAndPermissions(permissions, sizeof(permissions) / sizeof(permissions[0]));
    plugin_ = PLUGIN::HandlePolicyBiFunctionPlg::GetPlugin();
    plugin_->permission_ = EDM_MANAGE_DATETIME_PERMISSION;
    edmMgr_->pluginMgr_->pluginsCode_.clear();
    edmMgr_->pluginMgr_->pluginsName_.clear();
    edmMgr_->pluginMgr_->AddPlugin(plugin_);
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, HANDLE_POLICY_BIFUNCTIONPLG_POLICYCODE);
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName(ADMIN_PACKAGENAME);
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("ErrorData");
    ErrCode res = edmMgr_->HandleDevicePolicy(code, elementName, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_EDM_OPERATE_JSON);
    Utils::ResetTokenTypeAndUid();
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
    const char* permissions[] = {EDM_MANAGE_DATETIME_PERMISSION.c_str()};
    Utils::SetNativeTokenTypeAndPermissions(permissions, sizeof(permissions) / sizeof(permissions[0]));
    plugin_ = PLUGIN::HandlePolicyBiFunctionPlg::GetPlugin();
    plugin_->permission_ = EDM_MANAGE_DATETIME_PERMISSION;
    edmMgr_->pluginMgr_->pluginsCode_.clear();
    edmMgr_->pluginMgr_->pluginsName_.clear();
    edmMgr_->pluginMgr_->AddPlugin(plugin_);
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, HANDLE_POLICY_BIFUNCTIONPLG_POLICYCODE);
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName(ADMIN_PACKAGENAME);
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("testValue");
    ErrCode res = edmMgr_->HandleDevicePolicy(code, elementName, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);
    res = edmMgr_->policyMgr_->SetPolicy(ADMIN_PACKAGENAME, plugin_->GetPolicyName(), "", "");
    ASSERT_TRUE(res == ERR_OK);

    plugin_ = PLUGIN::HandlePolicyBiFunctionUnsavePlg::GetPlugin();
    plugin_->permission_ = EDM_MANAGE_DATETIME_PERMISSION;
    edmMgr_->pluginMgr_->pluginsCode_.clear();
    edmMgr_->pluginMgr_->pluginsName_.clear();
    edmMgr_->pluginMgr_->AddPlugin(plugin_);
    code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, HANDLE_POLICY_BIFUNCTION_UNSAVE_PLG_POLICYCODE);
    data.WriteString("{\"name\" : \"testValue\"}");
    res = edmMgr_->HandleDevicePolicy(code, elementName, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);
    Utils::ResetTokenTypeAndUid();
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
    const char* permissions[] = {EDM_MANAGE_DATETIME_PERMISSION.c_str()};
    Utils::SetNativeTokenTypeAndPermissions(permissions, sizeof(permissions) / sizeof(permissions[0]));
    plugin_ = PLUGIN::HandlePolicyJsonBiFunctionPlg::GetPlugin();
    plugin_->permission_ = EDM_MANAGE_DATETIME_PERMISSION;
    edmMgr_->pluginMgr_->pluginsCode_.clear();
    edmMgr_->pluginMgr_->pluginsName_.clear();
    edmMgr_->pluginMgr_->AddPlugin(plugin_);
    AdminValueItemsMap map;
    std::string errJsonStr = "v1,v2v3??v4"; // Enter a string that cannot be parsed by JSON
    map.insert(std::pair<std::string, std::string>(ADMIN_PACKAGENAME, errJsonStr));
    map.insert(std::pair<std::string, std::string>("com.edm.test.demo2", errJsonStr));
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, HANDLE_POLICY_JSON_BIFUNCTIONPLG_POLICYCODE);
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName(ADMIN_PACKAGENAME);
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("{\"name\" : \"testValue\"}");
    ErrCode res = edmMgr_->HandleDevicePolicy(code, elementName, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);
    res = edmMgr_->policyMgr_->SetPolicy(ADMIN_PACKAGENAME, plugin_->GetPolicyName(), "", "", DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);
    Utils::ResetTokenTypeAndUid();
}

/**
 * @tc.name: GetDevicePolicyFuncTest001
 * @tc.desc: Test EnterpriseDeviceMgrAbility::GetDevicePolicy function.
 * @tc.desc: Test if (plugin == nullptr)
 * @tc.type: FUNC
 * @tc.require: issueI5PBT1
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, GetDevicePolicyFuncTest001, TestSize.Level1)
{
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, INVALID_POLICYCODE);
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(1);
    ErrCode res = edmMgr_->GetDevicePolicy(code, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(res == EdmReturnErrCode::INTERFACE_UNSUPPORTED);
}

/**
 * @tc.name: GetDevicePolicyFuncTest002
 * @tc.desc: Test EnterpriseDeviceMgrAbility::GetDevicePolicy function.
 * @tc.desc: Test if admin == nullptr
 * @tc.type: FUNC
 * @tc.require: issueI5PBT1
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, GetDevicePolicyFuncTest002, TestSize.Level1)
{
    const char* permissions[] = {EDM_MANAGE_DATETIME_PERMISSION.c_str()};
    Utils::SetNativeTokenTypeAndPermissions(permissions, sizeof(permissions) / sizeof(permissions[0]));
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, ARRAY_MAP_TESTPLUGIN_POLICYCODE);
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(1);
    plugin_->permission_ = EDM_MANAGE_DATETIME_PERMISSION;
    edmMgr_->pluginMgr_->AddPlugin(plugin_);
    ErrCode res = edmMgr_->GetDevicePolicy(code, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);
    Utils::ResetTokenTypeAndUid();
}

/**
 * @tc.name: GetDevicePolicyFuncTest003
 * @tc.desc: Test EnterpriseDeviceMgrAbility::GetDevicePolicy function.
 * @tc.desc: Test if admin != nullptr && deviceAdmin == nullptr
 * @tc.type: FUNC
 * @tc.require: issueI5PBT1
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, GetDevicePolicyFuncTest003, TestSize.Level1)
{
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, ARRAY_MAP_TESTPLUGIN_POLICYCODE);
    plugin_->permission_ = EDM_MANAGE_DATETIME_PERMISSION;
    edmMgr_->pluginMgr_->AddPlugin(plugin_);
    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.test.demoFail");
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(0);
    data.WriteParcelable(&admin);
    ErrCode res = edmMgr_->GetDevicePolicy(code, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(res == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: GetDevicePolicyFuncTest004
 * @tc.desc: Test EnterpriseDeviceMgrAbility::GetDevicePolicy function.
 * @tc.desc: Test if admin != nullptr && (deviceAdmin->CheckPermission fail)
 * @tc.type: FUNC
 * @tc.require: issueI5PBT1
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, GetDevicePolicyFuncTest004, TestSize.Level1)
{
    PrepareBeforeHandleDevicePolicy();
    plugin_->permission_ = EDM_TEST_PERMISSION;
    edmMgr_->pluginMgr_->AddPlugin(plugin_);
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, ARRAY_MAP_TESTPLUGIN_POLICYCODE);
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(0);
    data.WriteParcelable(&admin);
    ErrCode res = edmMgr_->GetDevicePolicy(code, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(res == EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED);
}

/**
 * @tc.name: GetDevicePolicyFuncTest005
 * @tc.desc: Test EnterpriseDeviceMgrAbility::GetDevicePolicy function.
 * @tc.desc: Test if admin != nullptr && (if (!VerifyCallingPermission(plugin->GetPermission())))
 * @tc.type: FUNC
 * @tc.require: issueI5PBT1
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, GetDevicePolicyFuncTest005, TestSize.Level1)
{
    Admin testAdmin;
    testAdmin.adminInfo_.packageName_ = ADMIN_PACKAGENAME;
    testAdmin.adminInfo_.permission_ = {EDM_TEST_PERMISSION};
    std::vector<std::shared_ptr<Admin>> adminVec = {std::make_shared<Admin>(testAdmin)};
    edmMgr_->adminMgr_->admins_.insert(
        std::pair<int32_t, std::vector<std::shared_ptr<Admin>>>(DEFAULT_USER_ID, adminVec));
    plugin_->permission_ = EDM_TEST_PERMISSION;
    edmMgr_->pluginMgr_->AddPlugin(plugin_);
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, ARRAY_MAP_TESTPLUGIN_POLICYCODE);
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(0);
    data.WriteParcelable(&admin);
    ErrCode res = edmMgr_->GetDevicePolicy(code, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(res != EdmReturnErrCode::PERMISSION_DENIED);
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
    const char* permissions[] = {EDM_MANAGE_DATETIME_PERMISSION.c_str()};
    Utils::SetNativeTokenTypeAndPermissions(permissions, sizeof(permissions) / sizeof(permissions[0]));
    PrepareBeforeHandleDevicePolicy();
    plugin_ = PLUGIN::HandlePolicyBiFunctionUnsavePlg::GetPlugin();
    plugin_->permission_ = EDM_MANAGE_DATETIME_PERMISSION;
    edmMgr_->pluginMgr_->pluginsCode_.clear();
    edmMgr_->pluginMgr_->pluginsName_.clear();
    edmMgr_->pluginMgr_->AddPlugin(plugin_);
    uint32_t code =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, HANDLE_POLICY_BIFUNCTION_UNSAVE_PLG_POLICYCODE);
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(0);
    data.WriteParcelable(&admin);
    ErrCode res = edmMgr_->GetDevicePolicy(code, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);
    Utils::ResetTokenTypeAndUid();
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
    plugin_->permission_ = EDM_TEST_PERMISSION;
    edmMgr_->pluginMgr_->AddPlugin(plugin_);
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, ARRAY_MAP_TESTPLUGIN_POLICYCODE);
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME_FAILED);
    MessageParcel data;
    MessageParcel reply;
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
    const char* permissions[] = {PERMISSION_MANAGE_ENTERPRISE_DEVICE_ADMIN_TEST.c_str()};
    Utils::SetNativeTokenTypeAndPermissions(permissions, sizeof(permissions) / sizeof(permissions[0]));
    // enable super admin
    AppExecFwk::ElementName superAdmin;
    superAdmin.SetBundleName("com.edm.test.demo.ipc.suc");
    superAdmin.SetAbilityName("com.edm.test.demo.ipc.suc.MainAbility");
    EntInfo entInfo("test", "this is test");
    EXPECT_TRUE(SUCCEEDED(edmMgr_->EnableAdmin(superAdmin, entInfo, AdminType::ENT, DEFAULT_USER_ID)));
    // authorize sub-super admin
    std::string subSuperAdmin = "com.edm.test.demo1";
    EXPECT_TRUE(SUCCEEDED(edmMgr_->AuthorizeAdmin(superAdmin, subSuperAdmin)));
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
    EXPECT_TRUE(SUCCEEDED(edmMgr_->DisableSuperAdmin(superAdmin.GetBundleName())));
    Utils::ResetTokenTypeAndUid();
}

/**
 * @tc.name: TestOnCommonEventPackageRemovedNormal
 * @tc.desc: Test OnCommonEventPackageRemoved noraml admin func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestOnCommonEventPackageRemovedNormal, TestSize.Level1)
{
    const char* permissions[] = {PERMISSION_MANAGE_ENTERPRISE_DEVICE_ADMIN_TEST.c_str()};
    Utils::SetNativeTokenTypeAndPermissions(permissions, sizeof(permissions) / sizeof(permissions[0]));
    // enable normal admin with userId = 100 and 101
    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo.ipc.suc");
    admin.SetAbilityName("com.edm.test.demo.ipc.suc.MainAbility");
    EntInfo entInfo("test", "this is test");
    EXPECT_TRUE(SUCCEEDED(edmMgr_->EnableAdmin(admin, entInfo, AdminType::NORMAL, DEFAULT_USER_ID)));
    EXPECT_TRUE(SUCCEEDED(edmMgr_->EnableAdmin(admin, entInfo, AdminType::NORMAL, TEST_USER_ID)));
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
    Utils::ResetTokenTypeAndUid();
}

/**
 * @tc.name: TestOnCommonEventPackageRemovedSub
 * @tc.desc: Test OnCommonEventPackageRemoved sub super admin func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestOnCommonEventPackageRemovedSub, TestSize.Level1)
{
    const char* permissions[] = {PERMISSION_MANAGE_ENTERPRISE_DEVICE_ADMIN_TEST.c_str()};
    Utils::SetNativeTokenTypeAndPermissions(permissions, sizeof(permissions) / sizeof(permissions[0]));
    // enable super admin
    AppExecFwk::ElementName superAdmin;
    superAdmin.SetBundleName("com.edm.test.demo.ipc.suc");
    superAdmin.SetAbilityName("com.edm.test.demo.ipc.suc.MainAbility");
    EntInfo entInfo("test", "this is test");
    EXPECT_TRUE(SUCCEEDED(edmMgr_->EnableAdmin(superAdmin, entInfo, AdminType::ENT, DEFAULT_USER_ID)));
    // authorize sub-super admin
    std::string subSuperAdmin = "com.edm.test.demo1";
    EXPECT_TRUE(SUCCEEDED(edmMgr_->AuthorizeAdmin(superAdmin, subSuperAdmin)));
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
    EXPECT_TRUE(SUCCEEDED(edmMgr_->DisableSuperAdmin(superAdmin.GetBundleName())));
    Utils::ResetTokenTypeAndUid();
}

/**
 * @tc.name: TestOnCommonEventPackageRemovedEnt
 * @tc.desc: Test OnCommonEventPackageRemoved super admin func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestOnCommonEventPackageRemovedEnt, TestSize.Level1)
{
    const char* permissions[] = {PERMISSION_MANAGE_ENTERPRISE_DEVICE_ADMIN_TEST.c_str()};
    Utils::SetNativeTokenTypeAndPermissions(permissions, sizeof(permissions) / sizeof(permissions[0]));
    // enable super admin
    AppExecFwk::ElementName superAdmin;
    superAdmin.SetBundleName("com.edm.test.demo.ipc.suc");
    superAdmin.SetAbilityName("com.edm.test.demo.ipc.suc.MainAbility");
    EntInfo entInfo("test", "this is test");
    EXPECT_TRUE(SUCCEEDED(edmMgr_->EnableAdmin(superAdmin, entInfo, AdminType::ENT, DEFAULT_USER_ID)));
    // authorize sub-super admin
    std::string subSuperAdmin = "com.edm.test.demo1";
    EXPECT_TRUE(SUCCEEDED(edmMgr_->AuthorizeAdmin(superAdmin, subSuperAdmin)));
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
    Utils::ResetTokenTypeAndUid();
}

/**
 * @tc.name: TestdisableSuperAdminWithPolicy
 * @tc.desc: Test disableSuperAdmin super admin func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestdisableSuperAdminWithPolicy, TestSize.Level1)
{
    const char* permissions[] = {PERMISSION_MANAGE_ENTERPRISE_DEVICE_ADMIN_TEST.c_str()};
    Utils::SetNativeTokenTypeAndPermissions(permissions, sizeof(permissions) / sizeof(permissions[0]));
    // enable super admin
    AppExecFwk::ElementName superAdmin;
    superAdmin.SetBundleName("com.edm.test.demo.ipc.suc");
    superAdmin.SetAbilityName("com.edm.test.demo.ipc.suc.MainAbility");
    EntInfo entInfo("test", "this is test");
    EXPECT_TRUE(SUCCEEDED(edmMgr_->EnableAdmin(superAdmin, entInfo, AdminType::ENT, DEFAULT_USER_ID)));
    // authorize sub-super admin
    std::string subSuperAdmin = "com.edm.test.demo1";
    EXPECT_TRUE(SUCCEEDED(edmMgr_->AuthorizeAdmin(superAdmin, subSuperAdmin)));
    // set policy with userId = 100 and 101
    auto plugin = PLUGIN::StringTestPlugin::GetPlugin();
    edmMgr_->pluginMgr_->AddPlugin(plugin);
    SetPolicy(superAdmin.GetBundleName(), plugin->GetPolicyName());
    SetPolicy(subSuperAdmin, plugin->GetPolicyName());
    // disable super admin
    EXPECT_TRUE(SUCCEEDED(edmMgr_->DisableSuperAdmin(superAdmin.GetBundleName())));
    // get sub-super admin and super admin
    ASSERT_TRUE(edmMgr_->adminMgr_->GetAdminByPkgName(superAdmin.GetBundleName(), DEFAULT_USER_ID) == nullptr);
    ASSERT_TRUE(edmMgr_->adminMgr_->GetAdminByPkgName(subSuperAdmin, DEFAULT_USER_ID) == nullptr);
    // get policy of sub-super admin with userId = 101
    GetPolicyFailed(TEST_USER_ID, superAdmin.GetBundleName(), plugin->GetPolicyName());
    GetPolicyFailed(TEST_USER_ID, subSuperAdmin, plugin->GetPolicyName());
    // get policy of sub-super admin with userId = 100
    GetPolicyFailed(DEFAULT_USER_ID, superAdmin.GetBundleName(), plugin->GetPolicyName());
    GetPolicyFailed(DEFAULT_USER_ID, subSuperAdmin, plugin->GetPolicyName());
    Utils::ResetTokenTypeAndUid();
}

/**
 * @tc.name: TestAuthorizeAdminWithoutPermisson
 * @tc.desc: Test TestAuthorizeAdmin without permission func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestAuthorizeAdminWithoutPermisson, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo");
    admin.SetAbilityName("com.edm.test.demo");
    ErrCode ret = edmMgr_->AuthorizeAdmin(admin, "com.edm.test.demo1");
    ASSERT_TRUE(ret == EdmReturnErrCode::PERMISSION_DENIED);
}

/**
 * @tc.name: TestAuthorizeAdminWithoutAdmin
 * @tc.desc: Test TestAuthorizeAdmin without administrator.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestAuthorizeAdminWithoutAdmin, TestSize.Level1)
{
    const char* permissions[] = {PERMISSION_MANAGE_ENTERPRISE_DEVICE_ADMIN_TEST.c_str()};
    Utils::SetNativeTokenTypeAndPermissions(permissions, sizeof(permissions) / sizeof(permissions[0]));

    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo");
    admin.SetAbilityName("com.edm.test.demo");
    ErrCode ret = edmMgr_->AuthorizeAdmin(admin, "com.edm.test.demo1");
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
    Utils::ResetTokenTypeAndUid();
}

/**
 * @tc.name: TestAuthorizeAdminWithoutSDA
 * @tc.desc: Test TestAuthorizeAdmin without administrator.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestAuthorizeAdminWithoutSDA, TestSize.Level1)
{
    const char* permissions[] = {PERMISSION_MANAGE_ENTERPRISE_DEVICE_ADMIN_TEST.c_str()};
    Utils::SetNativeTokenTypeAndPermissions(permissions, sizeof(permissions) / sizeof(permissions[0]));

    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo");
    admin.SetAbilityName("com.edm.test.demo");
    EntInfo entInfo("test", "this is test");
    ASSERT_TRUE(SUCCEEDED(edmMgr_->EnableAdmin(admin, entInfo, AdminType::NORMAL, DEFAULT_USER_ID)));

    ErrCode ret = edmMgr_->AuthorizeAdmin(admin, "com.edm.test.demo1");
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED);

    ASSERT_TRUE(SUCCEEDED(edmMgr_->DisableAdmin(admin, DEFAULT_USER_ID)));
    std::shared_ptr<Admin> normalAdmin = edmMgr_->adminMgr_->GetAdminByPkgName(admin.GetBundleName(), DEFAULT_USER_ID);
    EXPECT_TRUE(normalAdmin == nullptr);
    Utils::ResetTokenTypeAndUid();
}

/**
 * @tc.name: TestAuthorizeAdminIpcFail
 * @tc.desc: Test AuthorizeAdmin ipc fail func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestAuthorizeAdminIpcFail, TestSize.Level1)
{
    const char* permissions[] = {PERMISSION_MANAGE_ENTERPRISE_DEVICE_ADMIN_TEST.c_str()};
    Utils::SetNativeTokenTypeAndPermissions(permissions, sizeof(permissions) / sizeof(permissions[0]));

    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo.ipc.fail");
    admin.SetAbilityName("com.edm.test.demo.ipc.fail.MainAbility");
    EntInfo entInfo("test", "this is test");
    EXPECT_TRUE(SUCCEEDED(edmMgr_->EnableAdmin(admin, entInfo, AdminType::ENT, DEFAULT_USER_ID)));

    ErrCode res = edmMgr_->AuthorizeAdmin(admin, "com.edm.test.demo1");
    EXPECT_TRUE(res == EdmReturnErrCode::PERMISSION_DENIED);

    EXPECT_TRUE(SUCCEEDED(edmMgr_->DisableSuperAdmin(admin.GetBundleName())));
    std::shared_ptr<Admin> superAdmin;
    EXPECT_TRUE(FAILED(edmMgr_->adminMgr_->GetSubOrSuperAdminByPkgName(admin.GetBundleName(), superAdmin)));
    Utils::ResetTokenTypeAndUid();
}

/**
 * @tc.name: TestAuthorizeAdminWithoutReq
 * @tc.desc: Test AuthorizeAdmin without request permission.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestAuthorizeAdminWithoutReq, TestSize.Level1)
{
    const char* permissions[] = {PERMISSION_MANAGE_ENTERPRISE_DEVICE_ADMIN_TEST.c_str()};
    Utils::SetNativeTokenTypeAndPermissions(permissions, sizeof(permissions) / sizeof(permissions[0]));

    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo.ipc.suc");
    admin.SetAbilityName("com.edm.test.demo.ipc.suc.MainAbility");
    EntInfo entInfo("test", "this is test");
    EXPECT_TRUE(SUCCEEDED(edmMgr_->EnableAdmin(admin, entInfo, AdminType::ENT, DEFAULT_USER_ID)));

    ErrCode ret = edmMgr_->AuthorizeAdmin(admin, "com.edm.get.permission.fail");
    EXPECT_TRUE(ret == EdmReturnErrCode::AUTHORIZE_PERMISSION_FAILED);

    EXPECT_TRUE(SUCCEEDED(edmMgr_->DisableSuperAdmin(admin.GetBundleName())));
    std::shared_ptr<Admin> superAdmin;
    EXPECT_TRUE(FAILED(edmMgr_->adminMgr_->GetSubOrSuperAdminByPkgName(admin.GetBundleName(), superAdmin)));
    Utils::ResetTokenTypeAndUid();
}

/**
 * @tc.name: TestAuthorizeAdminSuc
 * @tc.desc: Test AuthorizeAdmin success.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestAuthorizeAdminSuc, TestSize.Level1)
{
    const char* permissions[] = {PERMISSION_MANAGE_ENTERPRISE_DEVICE_ADMIN_TEST.c_str()};
    Utils::SetNativeTokenTypeAndPermissions(permissions, sizeof(permissions) / sizeof(permissions[0]));

    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo.ipc.suc");
    admin.SetAbilityName("com.edm.test.demo.ipc.suc.MainAbility");
    EntInfo entInfo("test", "this is test");
    EXPECT_TRUE(SUCCEEDED(edmMgr_->EnableAdmin(admin, entInfo, AdminType::ENT, DEFAULT_USER_ID)));

    EXPECT_TRUE(SUCCEEDED(edmMgr_->AuthorizeAdmin(admin, "com.edm.test.demo1")));

    EXPECT_TRUE(SUCCEEDED(edmMgr_->DisableSuperAdmin(admin.GetBundleName())));
    std::shared_ptr<Admin> subOrSuperAdmin;
    EXPECT_TRUE(FAILED(edmMgr_->adminMgr_->GetSubOrSuperAdminByPkgName("com.edm.test.demo1", subOrSuperAdmin)));
    EXPECT_TRUE(FAILED(edmMgr_->adminMgr_->GetSubOrSuperAdminByPkgName(admin.GetAbilityName(), subOrSuperAdmin)));
    Utils::ResetTokenTypeAndUid();
}

/**
 * @tc.name: TestRemoveAdminAndAdminPolicy
 * @tc.desc: Test RemoveAdminAndAdminPolicy success.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestRemoveAdminAndAdminPolicy, TestSize.Level1)
{
    const char* permissions[] = {PERMISSION_MANAGE_ENTERPRISE_DEVICE_ADMIN_TEST.c_str()};
    Utils::SetNativeTokenTypeAndPermissions(permissions, sizeof(permissions) / sizeof(permissions[0]));

    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo.ipc.suc");
    admin.SetAbilityName("com.edm.test.demo.ipc.suc.MainAbility");
    EntInfo entInfo("test", "this is test");
    EXPECT_TRUE(SUCCEEDED(edmMgr_->EnableAdmin(admin, entInfo, AdminType::ENT, DEFAULT_USER_ID)));
    EXPECT_TRUE(SUCCEEDED(edmMgr_->RemoveAdminAndAdminPolicy(admin.GetBundleName(), DEFAULT_USER_ID)));
    std::shared_ptr<Admin> superAdmin;
    EXPECT_TRUE(FAILED(edmMgr_->adminMgr_->GetSubOrSuperAdminByPkgName("com.edm.test.demo.ipc.suc", superAdmin)));

    EXPECT_TRUE(SUCCEEDED(edmMgr_->EnableAdmin(admin, entInfo, AdminType::NORMAL, DEFAULT_USER_ID)));
    EXPECT_TRUE(SUCCEEDED(edmMgr_->RemoveAdminAndAdminPolicy(admin.GetBundleName(), DEFAULT_USER_ID)));
    auto normalAdmin = edmMgr_->adminMgr_->GetAdminByPkgName("com.edm.test.demo.ipc.suc", DEFAULT_USER_ID);
    EXPECT_TRUE(normalAdmin == nullptr);
    Utils::ResetTokenTypeAndUid();
}

/**
 * @tc.name: TestRemoveAdminPolicy
 * @tc.desc: Test RemoveAdminPolicy success.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestRemoveAdminPolicy, TestSize.Level1)
{
    const char* permissions[] = {PERMISSION_MANAGE_ENTERPRISE_DEVICE_ADMIN_TEST.c_str()};
    Utils::SetNativeTokenTypeAndPermissions(permissions, sizeof(permissions) / sizeof(permissions[0]));

    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo.ipc.suc");
    admin.SetAbilityName("com.edm.test.demo.ipc.suc.MainAbility");
    EntInfo entInfo("test", "this is test");
    EXPECT_TRUE(SUCCEEDED(edmMgr_->EnableAdmin(admin, entInfo, AdminType::ENT, DEFAULT_USER_ID)));

    // set policy with userId = 100 and 101
    auto plugin = PLUGIN::StringTestPlugin::GetPlugin();
    edmMgr_->pluginMgr_->AddPlugin(plugin);
    SetPolicy(admin.GetBundleName(), plugin->GetPolicyName());

    // remove policy with userId = 101
    EXPECT_TRUE(SUCCEEDED(edmMgr_->RemoveAdminPolicy(admin.GetBundleName(), TEST_USER_ID)));
    GetPolicyFailed(TEST_USER_ID, admin.GetBundleName(), plugin->GetPolicyName());
    GetPolicySuccess(DEFAULT_USER_ID, admin.GetBundleName(), plugin->GetPolicyName());

    Utils::ResetTokenTypeAndUid();
}

/**
 * @tc.name: TestRemoveSubSuperAdminAndAdminPolicy
 * @tc.desc: Test RemoveSubSuperAdminAndAdminPolicy success.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestRemoveSubSuperAdminAndAdminPolicy, TestSize.Level1)
{
    const char* permissions[] = {PERMISSION_MANAGE_ENTERPRISE_DEVICE_ADMIN_TEST.c_str()};
    Utils::SetNativeTokenTypeAndPermissions(permissions, sizeof(permissions) / sizeof(permissions[0]));

    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo.ipc.suc");
    admin.SetAbilityName("com.edm.test.demo.ipc.suc.MainAbility");
    EntInfo entInfo("test", "this is test");
    EXPECT_TRUE(SUCCEEDED(edmMgr_->EnableAdmin(admin, entInfo, AdminType::ENT, DEFAULT_USER_ID)));

    string subSuperBundleName = "com.edm.test.demo1";
    EXPECT_TRUE(SUCCEEDED(edmMgr_->AuthorizeAdmin(admin, subSuperBundleName)));
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
    Utils::ResetTokenTypeAndUid();
}

/**
 * @tc.name: TestRemoveSuperAdminAndAdminPolicy
 * @tc.desc: Test RemoveSuperAdminAndAdminPolicy success.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestRemoveSuperAdminAndAdminPolicy, TestSize.Level1)
{
    const char* permissions[] = {PERMISSION_MANAGE_ENTERPRISE_DEVICE_ADMIN_TEST.c_str()};
    Utils::SetNativeTokenTypeAndPermissions(permissions, sizeof(permissions) / sizeof(permissions[0]));

    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo.ipc.suc");
    admin.SetAbilityName("com.edm.test.demo.ipc.suc.MainAbility");
    EntInfo entInfo("test", "this is test");
    EXPECT_TRUE(SUCCEEDED(edmMgr_->EnableAdmin(admin, entInfo, AdminType::ENT, DEFAULT_USER_ID)));

    // set policy with userId = 100 and 101
    auto plugin = PLUGIN::StringTestPlugin::GetPlugin();
    edmMgr_->pluginMgr_->AddPlugin(plugin);
    SetPolicy(admin.GetBundleName(), plugin->GetPolicyName());

    // remove policy with userId = 100
    EXPECT_TRUE(SUCCEEDED(edmMgr_->RemoveSubSuperAdminAndAdminPolicy(admin.GetBundleName())));

    auto superAdmin = edmMgr_->adminMgr_->GetAdminByPkgName("com.edm.test.demo.ipc.suc", DEFAULT_USER_ID);
    EXPECT_TRUE(superAdmin == nullptr);
    superAdmin = edmMgr_->adminMgr_->GetAdminByPkgName("com.edm.test.demo.ipc.suc", TEST_USER_ID);
    EXPECT_TRUE(superAdmin == nullptr);
    EXPECT_FALSE(edmMgr_->adminMgr_->IsSuperAdmin("com.edm.test.demo.ipc.suc"));
    Utils::ResetTokenTypeAndUid();
}

/**
 * @tc.name: TestRemoveSubOrSuperAdminAndAdminPolicy
 * @tc.desc: Test RemoveSubOrSuperAdminAndAdminPolicy success.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestRemoveSubOrSuperAdminAndAdminPolicy, TestSize.Level1)
{
    const char* permissions[] = {PERMISSION_MANAGE_ENTERPRISE_DEVICE_ADMIN_TEST.c_str()};
    Utils::SetNativeTokenTypeAndPermissions(permissions, sizeof(permissions) / sizeof(permissions[0]));

    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo.ipc.suc");
    admin.SetAbilityName("com.edm.test.demo.ipc.suc.MainAbility");
    EntInfo entInfo("test", "this is test");
    EXPECT_TRUE(SUCCEEDED(edmMgr_->EnableAdmin(admin, entInfo, AdminType::ENT, DEFAULT_USER_ID)));

    // set policy with userId = 100 and 101
    auto plugin = PLUGIN::StringTestPlugin::GetPlugin();
    edmMgr_->pluginMgr_->AddPlugin(plugin);
    SetPolicy(admin.GetBundleName(), plugin->GetPolicyName());

    std::vector<int32_t> userIds{TEST_USER_ID};
    // remove policy with userId = 100
    EXPECT_TRUE(SUCCEEDED(edmMgr_->RemoveSubOrSuperAdminAndAdminPolicy(admin.GetBundleName(), userIds)));

    auto superAdmin = edmMgr_->adminMgr_->GetAdminByPkgName("com.edm.test.demo.ipc.suc", DEFAULT_USER_ID);
    EXPECT_TRUE(superAdmin == nullptr);
    superAdmin = edmMgr_->adminMgr_->GetAdminByPkgName("com.edm.test.demo.ipc.suc", TEST_USER_ID);
    EXPECT_TRUE(superAdmin == nullptr);
    EXPECT_FALSE(edmMgr_->adminMgr_->IsSuperAdmin("com.edm.test.demo.ipc.suc"));
    Utils::ResetTokenTypeAndUid();
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS