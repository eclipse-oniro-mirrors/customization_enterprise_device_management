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

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#define private public
#define protected public
#include "iplugin_manager.h"
#include "publish_form_to_desktop_plugin.h"
#undef protected
#undef private

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_os_account_manager_impl_mock.h"
#include "external_manager_factory_mock.h"
#include "iedm_form_manager.h"
#include "publish_form_to_desktop_param.h"
#include "utils.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {

// form_mgr_errors.h 中定义的错误码常量，测试中需要使用
constexpr int32_t ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED = 2293766;
constexpr int32_t ERR_APPEXECFWK_FORM_INVALID_PARAM = 2293767;
constexpr int32_t ERR_APPEXECFWK_FORM_PUBLISH_NO_SPACE = 2293856;
constexpr int32_t ERR_APPEXECFWK_FORM_MAX_SYSTEM_FORMS = 2293783;
constexpr int32_t ERR_APPEXECFWK_FORM_MAX_FORMS_PER_CLIENT = 2293787;
constexpr int32_t ERR_APPEXECFWK_FORM_MAX_FORMS_PER_USER = 2293851;
constexpr int32_t ERR_APPEXECFWK_FORM_PUBLISH_NOT_SUPPORT = 2293858;

// form_constants.h 中定义的卡片尺寸常量，测试中需要使用
constexpr int32_t DIMENSION_1_2 = 1;  // 最小有效卡片尺寸
constexpr int32_t DIMENSION_3_3 = 9;  // 最大有效卡片尺寸

// IEdmFormManager 的 Mock 类，使用 gmock + iInstance_ 指针替换模式
class EdmFormManagerMock : public IEdmFormManager {
public:
    ~EdmFormManagerMock() override = default;
    MOCK_METHOD(ErrCode, RequestPublishFormCrossUser,
        (AAFwk::Want &want, int32_t userId, int64_t &formId), (override));
};

class PublishFormToDesktopPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);

    void SetUp() override;

    void TearDown() override;

    std::shared_ptr<EdmFormManagerMock> formManagerMock_ = std::make_shared<EdmFormManagerMock>();
    std::shared_ptr<ExternalManagerFactoryMock> externalManagerFactoryMock_ = nullptr;
    std::shared_ptr<EdmOsAccountManagerImplMock> osAccountManagerMock_ = nullptr;
};

void PublishFormToDesktopPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void PublishFormToDesktopPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is original ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

void PublishFormToDesktopPluginTest::SetUp()
{
    IEdmFormManager::iInstance_ = formManagerMock_.get();
    externalManagerFactoryMock_ = std::make_shared<ExternalManagerFactoryMock>();
    osAccountManagerMock_ = std::make_shared<EdmOsAccountManagerImplMock>();
}

void PublishFormToDesktopPluginTest::TearDown()
{
    formManagerMock_.reset();
    IEdmFormManager::iInstance_ = nullptr;
    externalManagerFactoryMock_.reset();
    osAccountManagerMock_.reset();
}

/**
 * @tc.name: TestConstructor
 * @tc.desc: Test PublishFormToDesktopPlugin constructor initializes member variables correctly.
 * @tc.type: FUNC
 */
HWTEST_F(PublishFormToDesktopPluginTest, TestConstructor, TestSize.Level1)
{
    PublishFormToDesktopPlugin plugin;
    EXPECT_EQ(plugin.policyCode_, EdmInterfaceCode::PUBLISH_FORM_TO_DESKTOP);
    EXPECT_EQ(plugin.policyName_, PolicyName::POLICY_PUBLISH_FORM_TO_DESKTOP);
    EXPECT_EQ(plugin.permissionConfig_.typePermissions.size(), 1u);
    EXPECT_EQ(plugin.permissionConfig_.typePermissions.at(IPlugin::PermissionType::SUPER_DEVICE_ADMIN),
        EdmPermission::PERMISSION_ENTERPRISE_REQUEST_PUBLISH_FORM);
    EXPECT_EQ(plugin.permissionConfig_.apiType, IPlugin::ApiType::PUBLIC);
    EXPECT_FALSE(plugin.needSave_);
}

/**
 * @tc.name: OnHandlePolicy_CurrentUserIdInvalid_ReturnAddFormFailed
 * @tc.desc: Test OnHandlePolicy when currentUserId is negative, should return ADD_FORM_FAILED.
 * @tc.type: FUNC
 */
HWTEST_F(PublishFormToDesktopPluginTest, OnHandlePolicy_CurrentUserIdInvalid_ReturnAddFormFailed, TestSize.Level1)
{
    PublishFormToDesktopPlugin plugin;
    plugin.externalManagerFactory_ = externalManagerFactoryMock_;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"", "", false};
    uint32_t funcCode = POLICY_FUNC_CODE(static_cast<uint32_t>(FuncOperateType::SET),
        EdmInterfaceCode::PUBLISH_FORM_TO_DESKTOP);

    EXPECT_CALL(*externalManagerFactoryMock_, CreateOsAccountManager)
        .WillOnce(Return(osAccountManagerMock_));
    EXPECT_CALL(*osAccountManagerMock_, GetCurrentUserId)
        .WillOnce(Return(-1));

    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::ADD_FORM_FAILED);
}

/**
 * @tc.name: OnHandlePolicy_UnMarshallingFailed_ReturnParameterVerificationFailed
 * @tc.desc: Test OnHandlePolicy when UnMarshalling fails (empty data), should return PARAMETER_VERIFICATION_FAILED.
 * @tc.type: FUNC
 */
HWTEST_F(PublishFormToDesktopPluginTest, OnHandlePolicy_UnMarshallingFailed_ReturnParameterVerificationFailed,
    TestSize.Level1)
{
    PublishFormToDesktopPlugin plugin;
    plugin.externalManagerFactory_ = externalManagerFactoryMock_;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"", "", false};
    uint32_t funcCode = POLICY_FUNC_CODE(static_cast<uint32_t>(FuncOperateType::SET),
        EdmInterfaceCode::PUBLISH_FORM_TO_DESKTOP);

    EXPECT_CALL(*externalManagerFactoryMock_, CreateOsAccountManager)
        .WillOnce(Return(osAccountManagerMock_));
    EXPECT_CALL(*osAccountManagerMock_, GetCurrentUserId)
        .WillOnce(Return(DEFAULT_USER_ID));

    // 空 MessageParcel，UnMarshalling 会失败
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: OnHandlePolicy_EmptyBundleName_ReturnParameterVerificationFailed
 * @tc.desc: Test OnHandlePolicy when bundleName is empty, should return PARAMETER_VERIFICATION_FAILED.
 * @tc.type: FUNC
 */
HWTEST_F(PublishFormToDesktopPluginTest, OnHandlePolicy_EmptyBundleName_ReturnParameterVerificationFailed,
    TestSize.Level1)
{
    PublishFormToDesktopPlugin plugin;
    plugin.externalManagerFactory_ = externalManagerFactoryMock_;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"", "", false};
    uint32_t funcCode = POLICY_FUNC_CODE(static_cast<uint32_t>(FuncOperateType::SET),
        EdmInterfaceCode::PUBLISH_FORM_TO_DESKTOP);

    PublishFormToDesktopParam param;
    param.bundleName = "";
    param.moduleName = "module_test";
    param.abilityName = "ability_test";
    param.name = "form_test";
    param.dimension = 2;
    param.Marshalling(data);

    EXPECT_CALL(*externalManagerFactoryMock_, CreateOsAccountManager)
        .WillOnce(Return(osAccountManagerMock_));
    EXPECT_CALL(*osAccountManagerMock_, GetCurrentUserId)
        .WillOnce(Return(DEFAULT_USER_ID));

    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: OnHandlePolicy_EmptyAbilityName_ReturnParameterVerificationFailed
 * @tc.desc: Test OnHandlePolicy when abilityName is empty, should return PARAMETER_VERIFICATION_FAILED.
 * @tc.type: FUNC
 */
HWTEST_F(PublishFormToDesktopPluginTest, OnHandlePolicy_EmptyAbilityName_ReturnParameterVerificationFailed,
    TestSize.Level1)
{
    PublishFormToDesktopPlugin plugin;
    plugin.externalManagerFactory_ = externalManagerFactoryMock_;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"", "", false};
    uint32_t funcCode = POLICY_FUNC_CODE(static_cast<uint32_t>(FuncOperateType::SET),
        EdmInterfaceCode::PUBLISH_FORM_TO_DESKTOP);

    PublishFormToDesktopParam param;
    param.bundleName = "bundle_test";
    param.moduleName = "module_test";
    param.abilityName = "";
    param.name = "form_test";
    param.dimension = 2;
    param.Marshalling(data);

    EXPECT_CALL(*externalManagerFactoryMock_, CreateOsAccountManager)
        .WillOnce(Return(osAccountManagerMock_));
    EXPECT_CALL(*osAccountManagerMock_, GetCurrentUserId)
        .WillOnce(Return(DEFAULT_USER_ID));

    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: OnHandlePolicy_EmptyModuleName_ReturnParameterVerificationFailed
 * @tc.desc: Test OnHandlePolicy when moduleName is empty, should return PARAMETER_VERIFICATION_FAILED.
 * @tc.type: FUNC
 */
HWTEST_F(PublishFormToDesktopPluginTest, OnHandlePolicy_EmptyModuleName_ReturnParameterVerificationFailed,
    TestSize.Level1)
{
    PublishFormToDesktopPlugin plugin;
    plugin.externalManagerFactory_ = externalManagerFactoryMock_;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"", "", false};
    uint32_t funcCode = POLICY_FUNC_CODE(static_cast<uint32_t>(FuncOperateType::SET),
        EdmInterfaceCode::PUBLISH_FORM_TO_DESKTOP);

    PublishFormToDesktopParam param;
    param.bundleName = "bundle_test";
    param.moduleName = "";
    param.abilityName = "ability_test";
    param.name = "form_test";
    param.dimension = 2;
    param.Marshalling(data);

    EXPECT_CALL(*externalManagerFactoryMock_, CreateOsAccountManager)
        .WillOnce(Return(osAccountManagerMock_));
    EXPECT_CALL(*osAccountManagerMock_, GetCurrentUserId)
        .WillOnce(Return(DEFAULT_USER_ID));

    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: OnHandlePolicy_EmptyName_ReturnParameterVerificationFailed
 * @tc.desc: Test OnHandlePolicy when name is empty, should return PARAMETER_VERIFICATION_FAILED.
 * @tc.type: FUNC
 */
HWTEST_F(PublishFormToDesktopPluginTest, OnHandlePolicy_EmptyName_ReturnParameterVerificationFailed,
    TestSize.Level1)
{
    PublishFormToDesktopPlugin plugin;
    plugin.externalManagerFactory_ = externalManagerFactoryMock_;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"", "", false};
    uint32_t funcCode = POLICY_FUNC_CODE(static_cast<uint32_t>(FuncOperateType::SET),
        EdmInterfaceCode::PUBLISH_FORM_TO_DESKTOP);

    PublishFormToDesktopParam param;
    param.bundleName = "bundle_test";
    param.moduleName = "module_test";
    param.abilityName = "ability_test";
    param.name = "";
    param.dimension = 2;
    param.Marshalling(data);

    EXPECT_CALL(*externalManagerFactoryMock_, CreateOsAccountManager)
        .WillOnce(Return(osAccountManagerMock_));
    EXPECT_CALL(*osAccountManagerMock_, GetCurrentUserId)
        .WillOnce(Return(DEFAULT_USER_ID));

    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: OnHandlePolicy_RequestPublishFormSuccess_ReturnOk
 * @tc.desc: Test OnHandlePolicy when RequestPublishFormCrossUser succeeds, should return ERR_OK with formId.
 * @tc.type: FUNC
 */
HWTEST_F(PublishFormToDesktopPluginTest, OnHandlePolicy_RequestPublishFormSuccess_ReturnOk, TestSize.Level1)
{
    PublishFormToDesktopPlugin plugin;
    plugin.externalManagerFactory_ = externalManagerFactoryMock_;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"", "", false};
    uint32_t funcCode = POLICY_FUNC_CODE(static_cast<uint32_t>(FuncOperateType::SET),
        EdmInterfaceCode::PUBLISH_FORM_TO_DESKTOP);

    PublishFormToDesktopParam param;
    param.bundleName = "com.test.bundle";
    param.moduleName = "entry";
    param.abilityName = "MainAbility";
    param.name = "widget";
    param.dimension = 2;
    param.Marshalling(data);

    EXPECT_CALL(*externalManagerFactoryMock_, CreateOsAccountManager)
        .WillOnce(Return(osAccountManagerMock_));
    EXPECT_CALL(*osAccountManagerMock_, GetCurrentUserId)
        .WillOnce(Return(DEFAULT_USER_ID));
    EXPECT_CALL(*formManagerMock_, RequestPublishFormCrossUser(_, _, _))
        .WillOnce(DoAll(SetArgReferee<2>(12345), Return(ERR_OK)));

    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    // 验证 reply 中写入了 ERR_OK 和 formId
    int32_t replyCode = 0;
    reply.RewindRead(0);
    reply.ReadInt32(replyCode);
    EXPECT_EQ(replyCode, ERR_OK);
    std::string formIdStr;
    reply.ReadString(formIdStr);
    EXPECT_EQ(formIdStr, "12345");
}

/**
 * @tc.name: OnHandlePolicy_FormGetBundleFailed_ReturnFormNotExist
 * @tc.desc: Test OnHandlePolicy when RequestPublishFormCrossUser returns ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED,
 *           should return FORM_NOT_EXIST.
 * @tc.type: FUNC
 */
HWTEST_F(PublishFormToDesktopPluginTest, OnHandlePolicy_FormGetBundleFailed_ReturnFormNotExist, TestSize.Level1)
{
    PublishFormToDesktopPlugin plugin;
    plugin.externalManagerFactory_ = externalManagerFactoryMock_;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"", "", false};
    uint32_t funcCode = POLICY_FUNC_CODE(static_cast<uint32_t>(FuncOperateType::SET),
        EdmInterfaceCode::PUBLISH_FORM_TO_DESKTOP);

    PublishFormToDesktopParam param;
    param.bundleName = "com.test.bundle";
    param.moduleName = "entry";
    param.abilityName = "MainAbility";
    param.name = "widget";
    param.dimension = 2;
    param.Marshalling(data);

    EXPECT_CALL(*externalManagerFactoryMock_, CreateOsAccountManager)
        .WillOnce(Return(osAccountManagerMock_));
    EXPECT_CALL(*osAccountManagerMock_, GetCurrentUserId)
        .WillOnce(Return(DEFAULT_USER_ID));
    EXPECT_CALL(*formManagerMock_, RequestPublishFormCrossUser(_, _, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED));

    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::FORM_NOT_EXIST);
}

/**
 * @tc.name: OnHandlePolicy_FormInvalidParam_ReturnFormNotExist
 * @tc.desc: Test OnHandlePolicy when RequestPublishFormCrossUser returns ERR_APPEXECFWK_FORM_INVALID_PARAM,
 *           should return FORM_NOT_EXIST.
 * @tc.type: FUNC
 */
HWTEST_F(PublishFormToDesktopPluginTest, OnHandlePolicy_FormInvalidParam_ReturnFormNotExist, TestSize.Level1)
{
    PublishFormToDesktopPlugin plugin;
    plugin.externalManagerFactory_ = externalManagerFactoryMock_;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"", "", false};
    uint32_t funcCode = POLICY_FUNC_CODE(static_cast<uint32_t>(FuncOperateType::SET),
        EdmInterfaceCode::PUBLISH_FORM_TO_DESKTOP);

    PublishFormToDesktopParam param;
    param.bundleName = "com.test.bundle";
    param.moduleName = "entry";
    param.abilityName = "MainAbility";
    param.name = "widget";
    param.dimension = 2;
    param.Marshalling(data);

    EXPECT_CALL(*externalManagerFactoryMock_, CreateOsAccountManager)
        .WillOnce(Return(osAccountManagerMock_));
    EXPECT_CALL(*osAccountManagerMock_, GetCurrentUserId)
        .WillOnce(Return(DEFAULT_USER_ID));
    EXPECT_CALL(*formManagerMock_, RequestPublishFormCrossUser(_, _, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_INVALID_PARAM));

    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::FORM_NOT_EXIST);
}

/**
 * @tc.name: OnHandlePolicy_FormPublishNoSpace_ReturnFormNumberUpperLimit
 * @tc.desc: Test OnHandlePolicy when RequestPublishFormCrossUser returns ERR_APPEXECFWK_FORM_PUBLISH_NO_SPACE,
 *           should return FORM_LIMIT_REACHED.
 * @tc.type: FUNC
 */
HWTEST_F(PublishFormToDesktopPluginTest, OnHandlePolicy_FormPublishNoSpace_ReturnFormNumberUpperLimit,
    TestSize.Level1)
{
    PublishFormToDesktopPlugin plugin;
    plugin.externalManagerFactory_ = externalManagerFactoryMock_;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"", "", false};
    uint32_t funcCode = POLICY_FUNC_CODE(static_cast<uint32_t>(FuncOperateType::SET),
        EdmInterfaceCode::PUBLISH_FORM_TO_DESKTOP);

    PublishFormToDesktopParam param;
    param.bundleName = "com.test.bundle";
    param.moduleName = "entry";
    param.abilityName = "MainAbility";
    param.name = "widget";
    param.dimension = 2;
    param.Marshalling(data);

    EXPECT_CALL(*externalManagerFactoryMock_, CreateOsAccountManager)
        .WillOnce(Return(osAccountManagerMock_));
    EXPECT_CALL(*osAccountManagerMock_, GetCurrentUserId)
        .WillOnce(Return(DEFAULT_USER_ID));
    EXPECT_CALL(*formManagerMock_, RequestPublishFormCrossUser(_, _, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_PUBLISH_NO_SPACE));

    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::FORM_LIMIT_REACHED);
}

/**
 * @tc.name: OnHandlePolicy_FormMaxSystemForms_ReturnFormNumberUpperLimit
 * @tc.desc: Test OnHandlePolicy when RequestPublishFormCrossUser returns ERR_APPEXECFWK_FORM_MAX_SYSTEM_FORMS,
 *           should return FORM_LIMIT_REACHED.
 * @tc.type: FUNC
 */
HWTEST_F(PublishFormToDesktopPluginTest, OnHandlePolicy_FormMaxSystemForms_ReturnFormNumberUpperLimit,
    TestSize.Level1)
{
    PublishFormToDesktopPlugin plugin;
    plugin.externalManagerFactory_ = externalManagerFactoryMock_;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"", "", false};
    uint32_t funcCode = POLICY_FUNC_CODE(static_cast<uint32_t>(FuncOperateType::SET),
        EdmInterfaceCode::PUBLISH_FORM_TO_DESKTOP);

    PublishFormToDesktopParam param;
    param.bundleName = "com.test.bundle";
    param.moduleName = "entry";
    param.abilityName = "MainAbility";
    param.name = "widget";
    param.dimension = 2;
    param.Marshalling(data);

    EXPECT_CALL(*externalManagerFactoryMock_, CreateOsAccountManager)
        .WillOnce(Return(osAccountManagerMock_));
    EXPECT_CALL(*osAccountManagerMock_, GetCurrentUserId)
        .WillOnce(Return(DEFAULT_USER_ID));
    EXPECT_CALL(*formManagerMock_, RequestPublishFormCrossUser(_, _, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_MAX_SYSTEM_FORMS));

    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::FORM_LIMIT_REACHED);
}

/**
 * @tc.name: OnHandlePolicy_FormMaxFormsPerClient_ReturnFormNumberUpperLimit
 * @tc.desc: Test OnHandlePolicy when RequestPublishFormCrossUser returns ERR_APPEXECFWK_FORM_MAX_FORMS_PER_CLIENT,
 *           should return FORM_LIMIT_REACHED.
 * @tc.type: FUNC
 */
HWTEST_F(PublishFormToDesktopPluginTest, OnHandlePolicy_FormMaxFormsPerClient_ReturnFormNumberUpperLimit,
    TestSize.Level1)
{
    PublishFormToDesktopPlugin plugin;
    plugin.externalManagerFactory_ = externalManagerFactoryMock_;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"", "", false};
    uint32_t funcCode = POLICY_FUNC_CODE(static_cast<uint32_t>(FuncOperateType::SET),
        EdmInterfaceCode::PUBLISH_FORM_TO_DESKTOP);

    PublishFormToDesktopParam param;
    param.bundleName = "com.test.bundle";
    param.moduleName = "entry";
    param.abilityName = "MainAbility";
    param.name = "widget";
    param.dimension = 2;
    param.Marshalling(data);

    EXPECT_CALL(*externalManagerFactoryMock_, CreateOsAccountManager)
        .WillOnce(Return(osAccountManagerMock_));
    EXPECT_CALL(*osAccountManagerMock_, GetCurrentUserId)
        .WillOnce(Return(DEFAULT_USER_ID));
    EXPECT_CALL(*formManagerMock_, RequestPublishFormCrossUser(_, _, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_MAX_FORMS_PER_CLIENT));

    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::FORM_LIMIT_REACHED);
}

/**
 * @tc.name: OnHandlePolicy_FormMaxFormsPerUser_ReturnFormNumberUpperLimit
 * @tc.desc: Test OnHandlePolicy when RequestPublishFormCrossUser returns ERR_APPEXECFWK_FORM_MAX_FORMS_PER_USER,
 *           should return FORM_LIMIT_REACHED.
 * @tc.type: FUNC
 */
HWTEST_F(PublishFormToDesktopPluginTest, OnHandlePolicy_FormMaxFormsPerUser_ReturnFormNumberUpperLimit,
    TestSize.Level1)
{
    PublishFormToDesktopPlugin plugin;
    plugin.externalManagerFactory_ = externalManagerFactoryMock_;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"", "", false};
    uint32_t funcCode = POLICY_FUNC_CODE(static_cast<uint32_t>(FuncOperateType::SET),
        EdmInterfaceCode::PUBLISH_FORM_TO_DESKTOP);

    PublishFormToDesktopParam param;
    param.bundleName = "com.test.bundle";
    param.moduleName = "entry";
    param.abilityName = "MainAbility";
    param.name = "widget";
    param.dimension = 2;
    param.Marshalling(data);

    EXPECT_CALL(*externalManagerFactoryMock_, CreateOsAccountManager)
        .WillOnce(Return(osAccountManagerMock_));
    EXPECT_CALL(*osAccountManagerMock_, GetCurrentUserId)
        .WillOnce(Return(DEFAULT_USER_ID));
    EXPECT_CALL(*formManagerMock_, RequestPublishFormCrossUser(_, _, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_MAX_FORMS_PER_USER));

    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::FORM_LIMIT_REACHED);
}

/**
 * @tc.name: OnHandlePolicy_FormPublishNotSupport_ReturnFormTypeNotSupport
 * @tc.desc: Test OnHandlePolicy when RequestPublishFormCrossUser returns ERR_APPEXECFWK_FORM_PUBLISH_NOT_SUPPORT,
 *           should return FORM_TYPE_NOT_SUPPORT.
 * @tc.type: FUNC
 */
HWTEST_F(PublishFormToDesktopPluginTest, OnHandlePolicy_FormPublishNotSupport_ReturnFormTypeNotSupport,
    TestSize.Level1)
{
    PublishFormToDesktopPlugin plugin;
    plugin.externalManagerFactory_ = externalManagerFactoryMock_;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"", "", false};
    uint32_t funcCode = POLICY_FUNC_CODE(static_cast<uint32_t>(FuncOperateType::SET),
        EdmInterfaceCode::PUBLISH_FORM_TO_DESKTOP);

    PublishFormToDesktopParam param;
    param.bundleName = "com.test.bundle";
    param.moduleName = "entry";
    param.abilityName = "MainAbility";
    param.name = "widget";
    param.dimension = 2;
    param.Marshalling(data);

    EXPECT_CALL(*externalManagerFactoryMock_, CreateOsAccountManager)
        .WillOnce(Return(osAccountManagerMock_));
    EXPECT_CALL(*osAccountManagerMock_, GetCurrentUserId)
        .WillOnce(Return(DEFAULT_USER_ID));
    EXPECT_CALL(*formManagerMock_, RequestPublishFormCrossUser(_, _, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_PUBLISH_NOT_SUPPORT));

    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::FORM_TYPE_NOT_SUPPORT);
}

/**
 * @tc.name: OnHandlePolicy_OtherFormError_ReturnAddFormFailed
 * @tc.desc: Test OnHandlePolicy when RequestPublishFormCrossUser returns an unknown error code,
 *           should return ADD_FORM_FAILED.
 * @tc.type: FUNC
 */
HWTEST_F(PublishFormToDesktopPluginTest, OnHandlePolicy_OtherFormError_ReturnAddFormFailed, TestSize.Level1)
{
    PublishFormToDesktopPlugin plugin;
    plugin.externalManagerFactory_ = externalManagerFactoryMock_;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"", "", false};
    uint32_t funcCode = POLICY_FUNC_CODE(static_cast<uint32_t>(FuncOperateType::SET),
        EdmInterfaceCode::PUBLISH_FORM_TO_DESKTOP);

    PublishFormToDesktopParam param;
    param.bundleName = "com.test.bundle";
    param.moduleName = "entry";
    param.abilityName = "MainAbility";
    param.name = "widget";
    param.dimension = 2;
    param.Marshalling(data);

    EXPECT_CALL(*externalManagerFactoryMock_, CreateOsAccountManager)
        .WillOnce(Return(osAccountManagerMock_));
    EXPECT_CALL(*osAccountManagerMock_, GetCurrentUserId)
        .WillOnce(Return(DEFAULT_USER_ID));
    // 使用一个不在已知错误码映射中的错误码
    EXPECT_CALL(*formManagerMock_, RequestPublishFormCrossUser(_, _, _))
        .WillOnce(Return(-999));

    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::ADD_FORM_FAILED);
}

// ==================== PublishFormToDesktopParam 序列化测试 ====================

/**
 * @tc.name: Marshalling_NormalData_ReturnTrue
 * @tc.desc: Test PublishFormToDesktopParam::Marshalling with normal data.
 * @tc.type: FUNC
 */
HWTEST_F(PublishFormToDesktopPluginTest, Marshalling_NormalData_ReturnTrue, TestSize.Level1)
{
    PublishFormToDesktopParam param;
    param.bundleName = "com.test.bundle";
    param.moduleName = "entry";
    param.abilityName = "MainAbility";
    param.name = "widget";
    param.dimension = 2;

    MessageParcel data;
    bool ret = param.Marshalling(data);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: UnMarshalling_NormalData_ReturnTrue
 * @tc.desc: Test PublishFormToDesktopParam::UnMarshalling with normal data.
 * @tc.type: FUNC
 */
HWTEST_F(PublishFormToDesktopPluginTest, UnMarshalling_NormalData_ReturnTrue, TestSize.Level1)
{
    PublishFormToDesktopParam srcParam;
    srcParam.bundleName = "com.test.bundle";
    srcParam.moduleName = "entry";
    srcParam.abilityName = "MainAbility";
    srcParam.name = "widget";
    srcParam.dimension = 2;

    MessageParcel data;
    ASSERT_TRUE(srcParam.Marshalling(data));

    PublishFormToDesktopParam destParam;
    data.RewindRead(0);
    bool ret = PublishFormToDesktopParam::UnMarshalling(data, destParam);
    EXPECT_TRUE(ret);
    EXPECT_EQ(destParam.bundleName, "com.test.bundle");
    EXPECT_EQ(destParam.moduleName, "entry");
    EXPECT_EQ(destParam.abilityName, "MainAbility");
    EXPECT_EQ(destParam.name, "widget");
    EXPECT_EQ(destParam.dimension, 2);
}

/**
 * @tc.name: UnMarshalling_EmptyData_ReturnFalse
 * @tc.desc: Test PublishFormToDesktopParam::UnMarshalling with empty MessageParcel, should return false.
 * @tc.type: FUNC
 */
HWTEST_F(PublishFormToDesktopPluginTest, UnMarshalling_EmptyData_ReturnFalse, TestSize.Level1)
{
    MessageParcel data;
    PublishFormToDesktopParam param;
    bool ret = PublishFormToDesktopParam::UnMarshalling(data, param);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: Marshalling_UnMarshalling_RoundTrip_Success
 * @tc.desc: Test PublishFormToDesktopParam round-trip serialization and deserialization.
 * @tc.type: FUNC
 */
HWTEST_F(PublishFormToDesktopPluginTest, Marshalling_UnMarshalling_RoundTrip_Success, TestSize.Level1)
{
    PublishFormToDesktopParam srcParam;
    srcParam.bundleName = "com.example.app";
    srcParam.moduleName = "feature_module";
    srcParam.abilityName = "FormAbility";
    srcParam.name = "CardForm";
    srcParam.dimension = 4;

    MessageParcel data;
    ASSERT_TRUE(srcParam.Marshalling(data));

    PublishFormToDesktopParam destParam;
    data.RewindRead(0);
    ASSERT_TRUE(PublishFormToDesktopParam::UnMarshalling(data, destParam));

    EXPECT_EQ(destParam.bundleName, srcParam.bundleName);
    EXPECT_EQ(destParam.moduleName, srcParam.moduleName);
    EXPECT_EQ(destParam.abilityName, srcParam.abilityName);
    EXPECT_EQ(destParam.name, srcParam.name);
    EXPECT_EQ(destParam.dimension, srcParam.dimension);
}

/**
 * @tc.name: Marshalling_DefaultDimension_Success
 * @tc.desc: Test PublishFormToDesktopParam::Marshalling with default dimension value.
 * @tc.type: FUNC
 */
HWTEST_F(PublishFormToDesktopPluginTest, Marshalling_DefaultDimension_Success, TestSize.Level1)
{
    PublishFormToDesktopParam param;
    param.bundleName = "com.test.bundle";
    param.moduleName = "entry";
    param.abilityName = "MainAbility";
    param.name = "widget";
    // dimension 使用默认值 0

    MessageParcel data;
    bool ret = param.Marshalling(data);
    EXPECT_TRUE(ret);

    PublishFormToDesktopParam destParam;
    data.RewindRead(0);
    ASSERT_TRUE(PublishFormToDesktopParam::UnMarshalling(data, destParam));
    EXPECT_EQ(destParam.dimension, 0);
}

/**
 * @tc.name: OnHandlePolicy_DimensionBelowMin_ReturnParameterVerificationFailed
 * @tc.desc: Test OnHandlePolicy when dimension is below DIMENSION_1_2, should return PARAMETER_VERIFICATION_FAILED.
 * @tc.type: FUNC
 */
HWTEST_F(PublishFormToDesktopPluginTest, OnHandlePolicy_DimensionBelowMin_ReturnParameterVerificationFailed,
    TestSize.Level1)
{
    PublishFormToDesktopPlugin plugin;
    plugin.externalManagerFactory_ = externalManagerFactoryMock_;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"", "", false};
    uint32_t funcCode = POLICY_FUNC_CODE(static_cast<uint32_t>(FuncOperateType::SET),
        EdmInterfaceCode::PUBLISH_FORM_TO_DESKTOP);

    PublishFormToDesktopParam param;
    param.bundleName = "com.test.bundle";
    param.moduleName = "entry";
    param.abilityName = "MainAbility";
    param.name = "widget";
    param.dimension = DIMENSION_1_2 - 1; // 低于 DIMENSION_1_2(1)
    param.Marshalling(data);

    EXPECT_CALL(*externalManagerFactoryMock_, CreateOsAccountManager)
        .WillOnce(Return(osAccountManagerMock_));
    EXPECT_CALL(*osAccountManagerMock_, GetCurrentUserId)
        .WillOnce(Return(DEFAULT_USER_ID));

    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: OnHandlePolicy_DimensionAboveMax_ReturnParameterVerificationFailed
 * @tc.desc: Test OnHandlePolicy when dimension is above DIMENSION_3_3, should return PARAMETER_VERIFICATION_FAILED.
 * @tc.type: FUNC
 */
HWTEST_F(PublishFormToDesktopPluginTest, OnHandlePolicy_DimensionAboveMax_ReturnParameterVerificationFailed,
    TestSize.Level1)
{
    PublishFormToDesktopPlugin plugin;
    plugin.externalManagerFactory_ = externalManagerFactoryMock_;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"", "", false};
    uint32_t funcCode = POLICY_FUNC_CODE(static_cast<uint32_t>(FuncOperateType::SET),
        EdmInterfaceCode::PUBLISH_FORM_TO_DESKTOP);

    PublishFormToDesktopParam param;
    param.bundleName = "com.test.bundle";
    param.moduleName = "entry";
    param.abilityName = "MainAbility";
    param.name = "widget";
    param.dimension = DIMENSION_3_3 + 1; // 高于 DIMENSION_3_3
    param.Marshalling(data);

    EXPECT_CALL(*externalManagerFactoryMock_, CreateOsAccountManager)
        .WillOnce(Return(osAccountManagerMock_));
    EXPECT_CALL(*osAccountManagerMock_, GetCurrentUserId)
        .WillOnce(Return(DEFAULT_USER_ID));

    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: OnHandlePolicy_DimensionAtMinBoundary_ReturnOk
 * @tc.desc: Test OnHandlePolicy when dimension equals DIMENSION_1_2 (min boundary), should return ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(PublishFormToDesktopPluginTest, OnHandlePolicy_DimensionAtMinBoundary_ReturnOk, TestSize.Level1)
{
    PublishFormToDesktopPlugin plugin;
    plugin.externalManagerFactory_ = externalManagerFactoryMock_;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"", "", false};
    uint32_t funcCode = POLICY_FUNC_CODE(static_cast<uint32_t>(FuncOperateType::SET),
        EdmInterfaceCode::PUBLISH_FORM_TO_DESKTOP);

    PublishFormToDesktopParam param;
    param.bundleName = "com.test.bundle";
    param.moduleName = "entry";
    param.abilityName = "MainAbility";
    param.name = "widget";
    param.dimension = DIMENSION_1_2; // 最小边界值
    param.Marshalling(data);

    EXPECT_CALL(*externalManagerFactoryMock_, CreateOsAccountManager)
        .WillOnce(Return(osAccountManagerMock_));
    EXPECT_CALL(*osAccountManagerMock_, GetCurrentUserId)
        .WillOnce(Return(DEFAULT_USER_ID));
    EXPECT_CALL(*formManagerMock_, RequestPublishFormCrossUser(_, _, _))
        .WillOnce(DoAll(SetArgReferee<2>(100), Return(ERR_OK)));

    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    int32_t replyCode = 0;
    reply.RewindRead(0);
    reply.ReadInt32(replyCode);
    EXPECT_EQ(replyCode, ERR_OK);
    std::string formIdStr;
    reply.ReadString(formIdStr);
    EXPECT_EQ(formIdStr, "100");
}

/**
 * @tc.name: OnHandlePolicy_DimensionAtMaxBoundary_ReturnOk
 * @tc.desc: Test OnHandlePolicy when dimension equals DIMENSION_3_3 (max boundary), should return ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(PublishFormToDesktopPluginTest, OnHandlePolicy_DimensionAtMaxBoundary_ReturnOk, TestSize.Level1)
{
    PublishFormToDesktopPlugin plugin;
    plugin.externalManagerFactory_ = externalManagerFactoryMock_;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"", "", false};
    uint32_t funcCode = POLICY_FUNC_CODE(static_cast<uint32_t>(FuncOperateType::SET),
        EdmInterfaceCode::PUBLISH_FORM_TO_DESKTOP);

    PublishFormToDesktopParam param;
    param.bundleName = "com.test.bundle";
    param.moduleName = "entry";
    param.abilityName = "MainAbility";
    param.name = "widget";
    param.dimension = DIMENSION_3_3; // 最大边界值
    param.Marshalling(data);

    EXPECT_CALL(*externalManagerFactoryMock_, CreateOsAccountManager)
        .WillOnce(Return(osAccountManagerMock_));
    EXPECT_CALL(*osAccountManagerMock_, GetCurrentUserId)
        .WillOnce(Return(DEFAULT_USER_ID));
    EXPECT_CALL(*formManagerMock_, RequestPublishFormCrossUser(_, _, _))
        .WillOnce(DoAll(SetArgReferee<2>(200), Return(ERR_OK)));

    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    int32_t replyCode = 0;
    reply.RewindRead(0);
    reply.ReadInt32(replyCode);
    EXPECT_EQ(replyCode, ERR_OK);
    std::string formIdStr;
    reply.ReadString(formIdStr);
    EXPECT_EQ(formIdStr, "200");
}

// ==================== currentUserId 边界值测试 ====================

/**
 * @tc.name: OnHandlePolicy_CurrentUserIdZero_ReturnOk
 * @tc.desc: Test OnHandlePolicy when currentUserId is 0 (boundary value, 0 >= 0 is valid), should return ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(PublishFormToDesktopPluginTest, OnHandlePolicy_CurrentUserIdZero_ReturnOk, TestSize.Level1)
{
    PublishFormToDesktopPlugin plugin;
    plugin.externalManagerFactory_ = externalManagerFactoryMock_;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"", "", false};
    uint32_t funcCode = POLICY_FUNC_CODE(static_cast<uint32_t>(FuncOperateType::SET),
        EdmInterfaceCode::PUBLISH_FORM_TO_DESKTOP);

    PublishFormToDesktopParam param;
    param.bundleName = "com.test.bundle";
    param.moduleName = "entry";
    param.abilityName = "MainAbility";
    param.name = "widget";
    param.dimension = 2;
    param.Marshalling(data);

    EXPECT_CALL(*externalManagerFactoryMock_, CreateOsAccountManager)
        .WillOnce(Return(osAccountManagerMock_));
    EXPECT_CALL(*osAccountManagerMock_, GetCurrentUserId)
        .WillOnce(Return(0)); // currentUserId = 0，边界值
    EXPECT_CALL(*formManagerMock_, RequestPublishFormCrossUser(_, _, _))
        .WillOnce(DoAll(SetArgReferee<2>(99999), Return(ERR_OK)));

    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    int32_t replyCode = 0;
    reply.RewindRead(0);
    reply.ReadInt32(replyCode);
    EXPECT_EQ(replyCode, ERR_OK);
    std::string formIdStr;
    reply.ReadString(formIdStr);
    EXPECT_EQ(formIdStr, "99999");
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
