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
#define protected public
#define private public
#include "disallow_install_device_certificate_plugin.h"
#undef protected
#undef private
#include <string>
#include <utility>
#include <vector>

#include "basic_bool_plugin.h"
#include "cert_manager_sdk_stub.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
constexpr int32_t INVALID_USER_ID = -1;
constexpr int32_t VALID_USER_ID = 100;

constexpr char KEY_DEFAULT_CONFIG[] = "installGlobalUserCA_defaultConfig";
constexpr char KEY_ENABLE_USER_LIST[] = "enableInstallGlobalUserCA_userList";
constexpr char KEY_DISABLE_USER_LIST[] = "disableInstallGlobalUserCA_userList";
constexpr char VALUE_ENABLE[] = "enable";
constexpr char VALUE_DISABLE[] = "disable";

constexpr int32_t CM_GET_FAILED_RET = -6;
constexpr int32_t CM_SET_FAILED_RET = -6;

class DisallowInstallDeviceCertificatePluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);

    void SetUp() override;

    void TearDown() override;

    static std::string GetSavedValue(const std::string &key);

    static std::vector<std::pair<std::string, std::string>> DefaultConfigItems();

    static std::uint32_t SetFuncCode();
};

void DisallowInstallDeviceCertificatePluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DisallowInstallDeviceCertificatePluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

void DisallowInstallDeviceCertificatePluginTest::SetUp(void)
{
    CertManagerSdkStub::Reset();
}

void DisallowInstallDeviceCertificatePluginTest::TearDown(void)
{
    CertManagerSdkStub::Reset();
}

std::string DisallowInstallDeviceCertificatePluginTest::GetSavedValue(const std::string &key)
{
    auto items = CertManagerSdkStub::GetSavedConfigItems();
    for (const auto &item : items) {
        if (item.first == key) {
            return item.second;
        }
    }
    return "";
}

std::vector<std::pair<std::string, std::string>> DisallowInstallDeviceCertificatePluginTest::DefaultConfigItems()
{
    return {
        {KEY_DEFAULT_CONFIG, VALUE_ENABLE},
        {KEY_ENABLE_USER_LIST, ""},
        {KEY_DISABLE_USER_LIST, ""},
    };
}

std::uint32_t DisallowInstallDeviceCertificatePluginTest::SetFuncCode()
{
    return POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::INSTALL_DEVICE_CERTIFICATE);
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_001
 * @tc.desc: Test the plugin attributes are initialized correctly.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_001, TestSize.Level1)
{
    DisallowInstallDeviceCertificatePlugin plugin;
    ASSERT_EQ(plugin.GetCode(), EdmInterfaceCode::INSTALL_DEVICE_CERTIFICATE);
    ASSERT_EQ(plugin.GetPolicyName(), PolicyName::POLICY_DISALLOW_INSTALL_DEVICE_CERTIFICATE);
    ASSERT_TRUE(plugin.NeedSavePolicy());
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_002
 * @tc.desc: Test the plugin declares the manage-restrictions permission for super device admin.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_002, TestSize.Level1)
{
    DisallowInstallDeviceCertificatePlugin plugin;
    ASSERT_EQ(plugin.GetPermission(FuncOperateType::SET, IPlugin::PermissionType::SUPER_DEVICE_ADMIN),
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    ASSERT_EQ(plugin.GetApiType(FuncOperateType::SET), IPlugin::ApiType::PUBLIC);
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_003
 * @tc.desc: Test SetOtherModulePolicy with an invalid user id.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_003, TestSize.Level1)
{
    DisallowInstallDeviceCertificatePlugin plugin;
    ErrCode ret = plugin.SetOtherModulePolicy(true, INVALID_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAM_ERROR);
    // The certificate manager must not be touched when the user id is rejected.
    ASSERT_EQ(CertManagerSdkStub::GetGetConfigCallCount(), 0U);
    ASSERT_EQ(CertManagerSdkStub::GetSetConfigCallCount(), 0U);
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_004
 * @tc.desc: Test SetOtherModulePolicy with a negative user id for the enable path.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_004, TestSize.Level1)
{
    DisallowInstallDeviceCertificatePlugin plugin;
    ErrCode ret = plugin.SetOtherModulePolicy(false, INVALID_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAM_ERROR);
    ASSERT_EQ(CertManagerSdkStub::GetSetConfigCallCount(), 0U);
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_005
 * @tc.desc: Test SetOtherModulePolicy returns EXECUTE_TIME_OUT when reading the cert manager config fails.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_005, TestSize.Level1)
{
    CertManagerSdkStub::SetGetConfigRet(CM_GET_FAILED_RET);
    DisallowInstallDeviceCertificatePlugin plugin;
    ErrCode ret = plugin.SetOtherModulePolicy(true, VALID_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
    ASSERT_EQ(CertManagerSdkStub::GetGetConfigCallCount(), 1U);
    ASSERT_EQ(CertManagerSdkStub::GetSetConfigCallCount(), 0U);
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_006
 * @tc.desc: Test SetOtherModulePolicy returns EXECUTE_TIME_OUT when writing the cert manager config fails.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_006, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems(DefaultConfigItems());
    CertManagerSdkStub::SetSetConfigRet(CM_SET_FAILED_RET);
    DisallowInstallDeviceCertificatePlugin plugin;
    ErrCode ret = plugin.SetOtherModulePolicy(true, VALID_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
    ASSERT_EQ(CertManagerSdkStub::GetSetConfigCallCount(), 1U);
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_007
 * @tc.desc: Test disabling certificate installation adds the user to the disable list.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_007, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems(DefaultConfigItems());
    DisallowInstallDeviceCertificatePlugin plugin;
    ErrCode ret = plugin.SetOtherModulePolicy(true, VALID_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(CertManagerSdkStub::GetSetConfigCallCount(), 1U);
    ASSERT_EQ(GetSavedValue(KEY_DISABLE_USER_LIST), "100");
    // The enable list is not operated by the plugin, so it is not written.
    ASSERT_EQ(GetSavedValue(KEY_ENABLE_USER_LIST), "");
    // The default config is always written as "enable".
    ASSERT_EQ(GetSavedValue(KEY_DEFAULT_CONFIG), VALUE_ENABLE);
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_008
 * @tc.desc: Test disabling certificate installation does not modify the enable list.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_008, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems({
        {KEY_DEFAULT_CONFIG, VALUE_ENABLE},
        {KEY_ENABLE_USER_LIST, "100|101"},
        {KEY_DISABLE_USER_LIST, ""},
    });
    DisallowInstallDeviceCertificatePlugin plugin;
    ErrCode ret = plugin.SetOtherModulePolicy(true, VALID_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    // The enable list is not operated by the plugin, so it is not written.
    ASSERT_EQ(GetSavedValue(KEY_ENABLE_USER_LIST), "");
    ASSERT_EQ(GetSavedValue(KEY_DISABLE_USER_LIST), "100");
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_009
 * @tc.desc: Test disabling certificate installation is idempotent when the user is already disabled.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_009, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems({
        {KEY_DEFAULT_CONFIG, VALUE_ENABLE},
        {KEY_ENABLE_USER_LIST, ""},
        {KEY_DISABLE_USER_LIST, "100"},
    });
    DisallowInstallDeviceCertificatePlugin plugin;
    ErrCode ret = plugin.SetOtherModulePolicy(true, VALID_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(GetSavedValue(KEY_DISABLE_USER_LIST), "100");
    ASSERT_EQ(CertManagerSdkStub::GetSetConfigCallCount(), 1U);
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_010
 * @tc.desc: Test disabling certificate installation appends the user to an existing disable list.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_010, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems({
        {KEY_DEFAULT_CONFIG, VALUE_ENABLE},
        {KEY_ENABLE_USER_LIST, ""},
        {KEY_DISABLE_USER_LIST, "101"},
    });
    DisallowInstallDeviceCertificatePlugin plugin;
    ErrCode ret = plugin.SetOtherModulePolicy(true, VALID_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(GetSavedValue(KEY_DISABLE_USER_LIST), "101|100");
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_011
 * @tc.desc: Test enabling certificate installation removes the user from the disable list.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_011, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems({
        {KEY_DEFAULT_CONFIG, VALUE_ENABLE},
        {KEY_ENABLE_USER_LIST, ""},
        {KEY_DISABLE_USER_LIST, "100|101"},
    });
    DisallowInstallDeviceCertificatePlugin plugin;
    ErrCode ret = plugin.SetOtherModulePolicy(false, VALID_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(GetSavedValue(KEY_DISABLE_USER_LIST), "101");
    // The enable list is not operated by the plugin, so it is not written.
    ASSERT_EQ(GetSavedValue(KEY_ENABLE_USER_LIST), "");
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_012
 * @tc.desc: Test enabling certificate installation resets the default config to enable and does not
 *           write the enable list, even when the stored default config is disable.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_012, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems({
        {KEY_DEFAULT_CONFIG, VALUE_DISABLE},
        {KEY_ENABLE_USER_LIST, ""},
        {KEY_DISABLE_USER_LIST, ""},
    });
    DisallowInstallDeviceCertificatePlugin plugin;
    ErrCode ret = plugin.SetOtherModulePolicy(false, VALID_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    // The enable list is not operated by the plugin, so it is not written.
    ASSERT_EQ(GetSavedValue(KEY_ENABLE_USER_LIST), "");
    ASSERT_EQ(GetSavedValue(KEY_DISABLE_USER_LIST), "");
    // The default config is always written as "enable".
    ASSERT_EQ(GetSavedValue(KEY_DEFAULT_CONFIG), VALUE_ENABLE);
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_013
 * @tc.desc: Test enabling certificate installation does not write the enable list, even when the
 *           stored enable list already holds the user.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_013, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems({
        {KEY_DEFAULT_CONFIG, VALUE_DISABLE},
        {KEY_ENABLE_USER_LIST, "100"},
        {KEY_DISABLE_USER_LIST, ""},
    });
    DisallowInstallDeviceCertificatePlugin plugin;
    ErrCode ret = plugin.SetOtherModulePolicy(false, VALID_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(GetSavedValue(KEY_ENABLE_USER_LIST), "");
    ASSERT_EQ(GetSavedValue(KEY_DEFAULT_CONFIG), VALUE_ENABLE);
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_014
 * @tc.desc: Test enabling certificate installation does not write the enable list when the default is enable.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_014, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems({
        {KEY_DEFAULT_CONFIG, VALUE_ENABLE},
        {KEY_ENABLE_USER_LIST, ""},
        {KEY_DISABLE_USER_LIST, "100"},
    });
    DisallowInstallDeviceCertificatePlugin plugin;
    ErrCode ret = plugin.SetOtherModulePolicy(false, VALID_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(GetSavedValue(KEY_DISABLE_USER_LIST), "");
    // The enable list is not operated by the plugin, so it is not written.
    ASSERT_EQ(GetSavedValue(KEY_ENABLE_USER_LIST), "");
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_015
 * @tc.desc: Test SetOtherModulePolicy works when the cert manager config is empty and the default is used.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_015, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems({});
    DisallowInstallDeviceCertificatePlugin plugin;
    ErrCode ret = plugin.SetOtherModulePolicy(true, VALID_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    // The default config falls back to "enable" when the config does not carry the key.
    ASSERT_EQ(GetSavedValue(KEY_DEFAULT_CONFIG), VALUE_ENABLE);
    ASSERT_EQ(GetSavedValue(KEY_DISABLE_USER_LIST), "100");
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_016
 * @tc.desc: Test SetOtherModulePolicy ignores unrelated config items.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_016, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems({
        {"someOtherKey", "someOtherValue"},
        {KEY_DISABLE_USER_LIST, ""},
    });
    DisallowInstallDeviceCertificatePlugin plugin;
    ErrCode ret = plugin.SetOtherModulePolicy(true, VALID_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(GetSavedValue(KEY_DEFAULT_CONFIG), VALUE_ENABLE);
    ASSERT_EQ(GetSavedValue(KEY_DISABLE_USER_LIST), "100");
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_017
 * @tc.desc: Test the user id match is exact and does not match a longer or shorter numeric token.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_017, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems({
        {KEY_DEFAULT_CONFIG, VALUE_ENABLE},
        {KEY_ENABLE_USER_LIST, ""},
        {KEY_DISABLE_USER_LIST, "1000"},
    });
    DisallowInstallDeviceCertificatePlugin plugin;
    ErrCode ret = plugin.SetOtherModulePolicy(true, VALID_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    // "1000" is a different user, so the disable list keeps it and appends 100.
    ASSERT_EQ(GetSavedValue(KEY_DISABLE_USER_LIST), "1000|100");
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_024
 * @tc.desc: Test OnHandlePolicy with an invalid user id.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_024, TestSize.Level1)
{
    DisallowInstallDeviceCertificatePlugin plugin;
    MessageParcel data;
    data.WriteBool(true);
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"", "", false};
    ErrCode ret = plugin.OnHandlePolicy(SetFuncCode(), data, reply, handlePolicyData, INVALID_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAM_ERROR);
    // The policy data must not be modified when the request is rejected.
    ASSERT_EQ(handlePolicyData.policyData, "");
    ASSERT_FALSE(handlePolicyData.isChanged);
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_025
 * @tc.desc: Test OnHandlePolicy disables the certificate installation and updates the policy data.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_025, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems(DefaultConfigItems());
    DisallowInstallDeviceCertificatePlugin plugin;
    MessageParcel data;
    data.WriteBool(true);
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"", "", false};
    ErrCode ret = plugin.OnHandlePolicy(SetFuncCode(), data, reply, handlePolicyData, VALID_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_TRUE(handlePolicyData.isChanged);
    ASSERT_EQ(handlePolicyData.policyData, "true");
    ASSERT_EQ(handlePolicyData.mergePolicyData, "true");
    ASSERT_EQ(GetSavedValue(KEY_DISABLE_USER_LIST), "100");
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_026
 * @tc.desc: Test OnHandlePolicy enables the certificate installation and clears the policy data.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_026, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems({
        {KEY_DEFAULT_CONFIG, VALUE_ENABLE},
        {KEY_ENABLE_USER_LIST, ""},
        {KEY_DISABLE_USER_LIST, "100"},
    });
    DisallowInstallDeviceCertificatePlugin plugin;
    MessageParcel data;
    data.WriteBool(false);
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"true", "true", false};
    ErrCode ret = plugin.OnHandlePolicy(SetFuncCode(), data, reply, handlePolicyData, VALID_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_TRUE(handlePolicyData.isChanged);
    ASSERT_EQ(handlePolicyData.policyData, "");
    // The merge data stays enabled because another admin still requires the restriction.
    ASSERT_EQ(handlePolicyData.mergePolicyData, "true");
    // The merged path does not apply the module policy, so the certificate manager is not written.
    ASSERT_EQ(CertManagerSdkStub::GetGetConfigCallCount(), 0U);
    ASSERT_EQ(CertManagerSdkStub::GetSetConfigCallCount(), 0U);
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_027
 * @tc.desc: Test OnHandlePolicy keeps the policy data untouched when the value does not change.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_027, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems({
        {KEY_DEFAULT_CONFIG, VALUE_ENABLE},
        {KEY_ENABLE_USER_LIST, ""},
        {KEY_DISABLE_USER_LIST, "100"},
    });
    DisallowInstallDeviceCertificatePlugin plugin;
    MessageParcel data;
    data.WriteBool(true);
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"true", "true", false};
    ErrCode ret = plugin.OnHandlePolicy(SetFuncCode(), data, reply, handlePolicyData, VALID_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    // The value was already "true", so the stored policy is not marked as changed.
    ASSERT_FALSE(handlePolicyData.isChanged);
    ASSERT_EQ(handlePolicyData.policyData, "true");
    // The merged path does not apply the module policy, so the certificate manager is not written.
    ASSERT_EQ(CertManagerSdkStub::GetSetConfigCallCount(), 0U);
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_028
 * @tc.desc: Test OnHandlePolicy reports the failure when the cert manager config cannot be written.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_028, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems(DefaultConfigItems());
    CertManagerSdkStub::SetSetConfigRet(CM_SET_FAILED_RET);
    DisallowInstallDeviceCertificatePlugin plugin;
    MessageParcel data;
    data.WriteBool(true);
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"", "", false};
    ErrCode ret = plugin.OnHandlePolicy(SetFuncCode(), data, reply, handlePolicyData, VALID_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
    ASSERT_FALSE(handlePolicyData.isChanged);
    ASSERT_EQ(handlePolicyData.policyData, "");
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_029
 * @tc.desc: Test OnAdminRemove re-enables the certificate installation when the admin held a non-merged policy.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_029, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems({
        {KEY_DEFAULT_CONFIG, VALUE_ENABLE},
        {KEY_ENABLE_USER_LIST, ""},
        {KEY_DISABLE_USER_LIST, "100"},
    });
    DisallowInstallDeviceCertificatePlugin plugin;
    // The merge data is empty, so this admin was the only one that enabled the restriction.
    ErrCode ret = plugin.OnAdminRemove("com.edm.test.admin", "true", "", VALID_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(CertManagerSdkStub::GetSetConfigCallCount(), 1U);
    ASSERT_EQ(GetSavedValue(KEY_DISABLE_USER_LIST), "");
    // The enable list is not operated by the plugin, so it is not written.
    ASSERT_EQ(GetSavedValue(KEY_ENABLE_USER_LIST), "");
    ASSERT_EQ(GetSavedValue(KEY_DEFAULT_CONFIG), VALUE_ENABLE);
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_030
 * @tc.desc: Test OnAdminRemove does not touch the cert manager when the policy was not enabled.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_030, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems(DefaultConfigItems());
    DisallowInstallDeviceCertificatePlugin plugin;
    ErrCode ret = plugin.OnAdminRemove("com.edm.test.admin", "", "", VALID_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(CertManagerSdkStub::GetSetConfigCallCount(), 0U);
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_031
 * @tc.desc: Test OnAdminRemove keeps the cert manager untouched when the policy is merged with other admins.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_031, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems({
        {KEY_DEFAULT_CONFIG, VALUE_ENABLE},
        {KEY_ENABLE_USER_LIST, ""},
        {KEY_DISABLE_USER_LIST, "100"},
    });
    DisallowInstallDeviceCertificatePlugin plugin;
    // The merge data is set, so another admin still requires the restriction and it must be kept.
    ErrCode ret = plugin.OnAdminRemove("com.edm.test.admin", "true", "true", VALID_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(CertManagerSdkStub::GetSetConfigCallCount(), 0U);
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_034
 * @tc.desc: Test OnAdminRemove reports the failure when the cert manager config cannot be written.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_034, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems({
        {KEY_DEFAULT_CONFIG, VALUE_ENABLE},
        {KEY_ENABLE_USER_LIST, ""},
        {KEY_DISABLE_USER_LIST, "100"},
    });
    CertManagerSdkStub::SetSetConfigRet(CM_SET_FAILED_RET);
    DisallowInstallDeviceCertificatePlugin plugin;
    ErrCode ret = plugin.OnAdminRemove("com.edm.test.admin", "true", "", VALID_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_035
 * @tc.desc: Test the disable and enable flows are symmetric, so the user list returns to its original value.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_035, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems({
        {KEY_DEFAULT_CONFIG, VALUE_ENABLE},
        {KEY_ENABLE_USER_LIST, ""},
        {KEY_DISABLE_USER_LIST, "101"},
    });
    DisallowInstallDeviceCertificatePlugin plugin;
    ASSERT_EQ(plugin.SetOtherModulePolicy(true, VALID_USER_ID), ERR_OK);
    ASSERT_EQ(GetSavedValue(KEY_DISABLE_USER_LIST), "101|100");

    // Feed the result back as the current config, then re-enable the installation.
    CertManagerSdkStub::SetConfigItems({
        {KEY_DEFAULT_CONFIG, VALUE_ENABLE},
        {KEY_ENABLE_USER_LIST, ""},
        {KEY_DISABLE_USER_LIST, GetSavedValue(KEY_DISABLE_USER_LIST)},
    });
    ASSERT_EQ(plugin.SetOtherModulePolicy(false, VALID_USER_ID), ERR_OK);
    ASSERT_EQ(GetSavedValue(KEY_DISABLE_USER_LIST), "101");
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_036
 * @tc.desc: Test the certificate manager config is released after being read.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_036, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems(DefaultConfigItems());
    DisallowInstallDeviceCertificatePlugin plugin;
    ASSERT_EQ(plugin.SetOtherModulePolicy(true, VALID_USER_ID), ERR_OK);
    ASSERT_EQ(CertManagerSdkStub::GetGetConfigCallCount(), 1U);
    ASSERT_EQ(CertManagerSdkStub::GetFreeConfigCallCount(), 1U);
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_037
 * @tc.desc: Test the user id 0 is a valid user and is handled like any other user id.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_037, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems(DefaultConfigItems());
    DisallowInstallDeviceCertificatePlugin plugin;
    ErrCode ret = plugin.SetOtherModulePolicy(true, 0);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(GetSavedValue(KEY_DISABLE_USER_LIST), "0");
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_038
 * @tc.desc: Test enabling certificate installation does not write the enable list, even when the
 *           stored enable list already holds other users.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_038, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems({
        {KEY_DEFAULT_CONFIG, VALUE_DISABLE},
        {KEY_ENABLE_USER_LIST, "101"},
        {KEY_DISABLE_USER_LIST, ""},
    });
    DisallowInstallDeviceCertificatePlugin plugin;
    ErrCode ret = plugin.SetOtherModulePolicy(false, VALID_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    // The enable list is not operated by the plugin, so it is not written.
    ASSERT_EQ(GetSavedValue(KEY_ENABLE_USER_LIST), "");
    ASSERT_EQ(GetSavedValue(KEY_DISABLE_USER_LIST), "");
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_039
 * @tc.desc: Test enabling certificate installation does not write the enable list, even when the
 *           stored enable list already holds the user together with other users.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_039, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems({
        {KEY_DEFAULT_CONFIG, VALUE_DISABLE},
        {KEY_ENABLE_USER_LIST, "101|100"},
        {KEY_DISABLE_USER_LIST, ""},
    });
    DisallowInstallDeviceCertificatePlugin plugin;
    ErrCode ret = plugin.SetOtherModulePolicy(false, VALID_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    // The enable list is not operated by the plugin, so it is not written.
    ASSERT_EQ(GetSavedValue(KEY_ENABLE_USER_LIST), "");
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_040
 * @tc.desc: Test disabling certificate installation does not write the enable list, even when the
 *           stored enable list holds empty tokens.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_040, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems({
        {KEY_DEFAULT_CONFIG, VALUE_ENABLE},
        {KEY_ENABLE_USER_LIST, "100||101"},
        {KEY_DISABLE_USER_LIST, ""},
    });
    DisallowInstallDeviceCertificatePlugin plugin;
    ErrCode ret = plugin.SetOtherModulePolicy(true, VALID_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    // The enable list is not operated by the plugin, so it is not written.
    ASSERT_EQ(GetSavedValue(KEY_ENABLE_USER_LIST), "");
    ASSERT_EQ(GetSavedValue(KEY_DISABLE_USER_LIST), "100");
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_041
 * @tc.desc: Test disabling certificate installation does not write the enable list, even when the
 *           stored enable list holds leading and trailing empty tokens.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_041, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems({
        {KEY_DEFAULT_CONFIG, VALUE_ENABLE},
        {KEY_ENABLE_USER_LIST, "|101|"},
        {KEY_DISABLE_USER_LIST, "|100|"},
    });
    DisallowInstallDeviceCertificatePlugin plugin;
    ErrCode ret = plugin.SetOtherModulePolicy(true, VALID_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    // The enable list is not operated by the plugin, so it is not written.
    ASSERT_EQ(GetSavedValue(KEY_ENABLE_USER_LIST), "");
    // The user is already in the disable list, so the list is left untouched with its separator tokens.
    ASSERT_EQ(GetSavedValue(KEY_DISABLE_USER_LIST), "|100|");
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_042
 * @tc.desc: Test a list that only holds separators is treated as an empty list.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_042, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems({
        {KEY_DEFAULT_CONFIG, VALUE_ENABLE},
        {KEY_ENABLE_USER_LIST, "||"},
        {KEY_DISABLE_USER_LIST, "|"},
    });
    DisallowInstallDeviceCertificatePlugin plugin;
    ErrCode ret = plugin.SetOtherModulePolicy(true, VALID_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    // The enable list is not operated by the plugin, so it is not written.
    ASSERT_EQ(GetSavedValue(KEY_ENABLE_USER_LIST), "");
    // The disable list only holds an empty token, so the user is appended behind the separator.
    ASSERT_EQ(GetSavedValue(KEY_DISABLE_USER_LIST), "||100");
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_046
 * @tc.desc: Test the plugin writes exactly the two expected config items to the certificate manager.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_046, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems(DefaultConfigItems());
    DisallowInstallDeviceCertificatePlugin plugin;
    ErrCode ret = plugin.SetOtherModulePolicy(true, VALID_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    auto saved = CertManagerSdkStub::GetSavedConfigItems();
    // The enable list is not operated by the plugin, so it is not written at all.
    ASSERT_EQ(saved.size(), 2U);
    ASSERT_EQ(saved[0].first, KEY_DEFAULT_CONFIG);
    ASSERT_EQ(saved[0].second, VALUE_ENABLE);
    ASSERT_EQ(saved[1].first, KEY_DISABLE_USER_LIST);
    ASSERT_EQ(saved[1].second, "100");
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_047
 * @tc.desc: Test the default config is always written as "enable", even when the certificate manager
 *           reports an unknown default value.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_047, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems({
        {KEY_DEFAULT_CONFIG, "unknown"},
        {KEY_ENABLE_USER_LIST, ""},
        {KEY_DISABLE_USER_LIST, ""},
    });
    DisallowInstallDeviceCertificatePlugin plugin;
    ErrCode ret = plugin.SetOtherModulePolicy(true, VALID_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    // The default config is always written as "enable".
    ASSERT_EQ(GetSavedValue(KEY_DEFAULT_CONFIG), VALUE_ENABLE);
    // The enable list is not operated by the plugin, so it is not written.
    ASSERT_EQ(GetSavedValue(KEY_ENABLE_USER_LIST), "");
    ASSERT_EQ(GetSavedValue(KEY_DISABLE_USER_LIST), "100");
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_049
 * @tc.desc: Test OnHandlePolicy does not touch the certificate manager when another admin already merged the policy.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_049, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems(DefaultConfigItems());
    DisallowInstallDeviceCertificatePlugin plugin;
    MessageParcel data;
    data.WriteBool(true);
    MessageParcel reply;
    // The merge data is set, so another admin already required the restriction.
    HandlePolicyData handlePolicyData{"", "true", false};
    ErrCode ret = plugin.OnHandlePolicy(SetFuncCode(), data, reply, handlePolicyData, VALID_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_TRUE(handlePolicyData.isChanged);
    ASSERT_EQ(handlePolicyData.policyData, "true");
    ASSERT_EQ(handlePolicyData.mergePolicyData, "true");
    // The merged path must not write the certificate manager config again.
    ASSERT_EQ(CertManagerSdkStub::GetGetConfigCallCount(), 0U);
    ASSERT_EQ(CertManagerSdkStub::GetSetConfigCallCount(), 0U);
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_050
 * @tc.desc: Test OnAdminRemove reports the failure when the certificate manager config cannot be written.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_050, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems({
        {KEY_DEFAULT_CONFIG, VALUE_ENABLE},
        {KEY_ENABLE_USER_LIST, ""},
        {KEY_DISABLE_USER_LIST, "100"},
    });
    CertManagerSdkStub::SetSetConfigRet(CM_SET_FAILED_RET);
    DisallowInstallDeviceCertificatePlugin plugin;
    ErrCode ret = plugin.OnAdminRemove("com.edm.test.admin", "true", "", VALID_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
    ASSERT_EQ(CertManagerSdkStub::GetSetConfigCallCount(), 1U);
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_051
 * @tc.desc: Test OnAdminRemove rejects an invalid user id.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_051, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems({
        {KEY_DEFAULT_CONFIG, VALUE_ENABLE},
        {KEY_ENABLE_USER_LIST, ""},
        {KEY_DISABLE_USER_LIST, "100"},
    });
    DisallowInstallDeviceCertificatePlugin plugin;
    ErrCode ret = plugin.OnAdminRemove("com.edm.test.admin", "true", "", INVALID_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAM_ERROR);
    // The certificate manager must not be touched when the user id is rejected.
    ASSERT_EQ(CertManagerSdkStub::GetGetConfigCallCount(), 0U);
    ASSERT_EQ(CertManagerSdkStub::GetSetConfigCallCount(), 0U);
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_052
 * @tc.desc: Test OnAdminRemove resets the default config to enable and does not write the enable
 *           list, even when the stored default config is disable.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_052, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems({
        {KEY_DEFAULT_CONFIG, VALUE_DISABLE},
        {KEY_ENABLE_USER_LIST, ""},
        {KEY_DISABLE_USER_LIST, "100"},
    });
    DisallowInstallDeviceCertificatePlugin plugin;
    // The merge data is empty, so this admin was the only one that enabled the restriction.
    ErrCode ret = plugin.OnAdminRemove("com.edm.test.admin", "true", "", VALID_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(CertManagerSdkStub::GetSetConfigCallCount(), 1U);
    ASSERT_EQ(GetSavedValue(KEY_DISABLE_USER_LIST), "");
    // The enable list is not operated by the plugin, so it is not written.
    ASSERT_EQ(GetSavedValue(KEY_ENABLE_USER_LIST), "");
    // The default config is always written as "enable".
    ASSERT_EQ(GetSavedValue(KEY_DEFAULT_CONFIG), VALUE_ENABLE);
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_053
 * @tc.desc: Test OnAdminRemove does not add the user to the enable list when the default config is enable.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_053, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems({
        {KEY_DEFAULT_CONFIG, VALUE_ENABLE},
        {KEY_ENABLE_USER_LIST, ""},
        {KEY_DISABLE_USER_LIST, "100"},
    });
    DisallowInstallDeviceCertificatePlugin plugin;
    ErrCode ret = plugin.OnAdminRemove("com.edm.test.admin", "true", "", VALID_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(CertManagerSdkStub::GetSetConfigCallCount(), 1U);
    ASSERT_EQ(GetSavedValue(KEY_DISABLE_USER_LIST), "");
    // The enable list is not operated by the plugin, so it is not written.
    ASSERT_EQ(GetSavedValue(KEY_ENABLE_USER_LIST), "");
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_054
 * @tc.desc: Test OnAdminRemove keeps the other users of the disable list.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_054, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems({
        {KEY_DEFAULT_CONFIG, VALUE_ENABLE},
        {KEY_ENABLE_USER_LIST, ""},
        {KEY_DISABLE_USER_LIST, "100|101"},
    });
    DisallowInstallDeviceCertificatePlugin plugin;
    ErrCode ret = plugin.OnAdminRemove("com.edm.test.admin", "true", "", VALID_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    // Only the removed admin's user is dropped, the other user is kept.
    ASSERT_EQ(GetSavedValue(KEY_DISABLE_USER_LIST), "101");
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_055
 * @tc.desc: Test OnAdminRemove with an empty policy value does not touch the certificate manager.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_055, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems({
        {KEY_DEFAULT_CONFIG, VALUE_ENABLE},
        {KEY_ENABLE_USER_LIST, ""},
        {KEY_DISABLE_USER_LIST, "100"},
    });
    DisallowInstallDeviceCertificatePlugin plugin;
    // The policy value is empty, so the restriction was never enabled by this admin.
    ErrCode ret = plugin.OnAdminRemove("com.edm.test.admin", "", "", VALID_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(CertManagerSdkStub::GetGetConfigCallCount(), 0U);
    ASSERT_EQ(CertManagerSdkStub::GetSetConfigCallCount(), 0U);
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_056
 * @tc.desc: Test the plugin reports the public api type for the set operation.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_056, TestSize.Level1)
{
    DisallowInstallDeviceCertificatePlugin plugin;
    // The feature is part of the public api surface.
    ASSERT_EQ(plugin.GetApiType(FuncOperateType::SET), IPlugin::ApiType::PUBLIC);
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_057
 * @tc.desc: Test the plugin declares exactly one permission that is resolved for every admin type.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_057, TestSize.Level1)
{
    DisallowInstallDeviceCertificatePlugin plugin;
    ASSERT_EQ(plugin.GetPermission(FuncOperateType::SET, IPlugin::PermissionType::SUPER_DEVICE_ADMIN),
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    // The plugin declares a single permission, so every admin type resolves to the same one.
    ASSERT_EQ(plugin.GetPermission(FuncOperateType::SET, IPlugin::PermissionType::NORMAL_DEVICE_ADMIN),
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_058
 * @tc.desc: Test the plugin policy is stored so it survives a service restart.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_058, TestSize.Level1)
{
    DisallowInstallDeviceCertificatePlugin plugin;
    ASSERT_TRUE(plugin.NeedSavePolicy());
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_059
 * @tc.desc: Test the disable user list keeps its order when a user is removed and added again.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_059, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems({
        {KEY_DEFAULT_CONFIG, VALUE_ENABLE},
        {KEY_ENABLE_USER_LIST, ""},
        {KEY_DISABLE_USER_LIST, "101|102"},
    });
    DisallowInstallDeviceCertificatePlugin plugin;
    ASSERT_EQ(plugin.SetOtherModulePolicy(true, VALID_USER_ID), ERR_OK);
    ASSERT_EQ(GetSavedValue(KEY_DISABLE_USER_LIST), "101|102|100");
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_060
 * @tc.desc: Test a large user list is rewritten without losing any other user.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_060, TestSize.Level1)
{
    std::string disableList;
    for (int32_t i = 0; i < 50; i++) {
        if (!disableList.empty()) {
            disableList.push_back('|');
        }
        disableList.append(std::to_string(i + 200));
    }
    CertManagerSdkStub::SetConfigItems({
        {KEY_DEFAULT_CONFIG, VALUE_ENABLE},
        {KEY_ENABLE_USER_LIST, ""},
        {KEY_DISABLE_USER_LIST, disableList},
    });
    DisallowInstallDeviceCertificatePlugin plugin;
    ErrCode ret = plugin.SetOtherModulePolicy(true, VALID_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    // The 50 existing users are preserved and the new user is appended at the end.
    ASSERT_EQ(GetSavedValue(KEY_DISABLE_USER_LIST), disableList + "|100");
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_061
 * @tc.desc: Test the enable list is left untouched while the disable list is updated.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_061, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems({
        {KEY_DEFAULT_CONFIG, VALUE_ENABLE},
        {KEY_ENABLE_USER_LIST, "101"},
        {KEY_DISABLE_USER_LIST, "102"},
    });
    DisallowInstallDeviceCertificatePlugin plugin;
    ErrCode ret = plugin.SetOtherModulePolicy(true, VALID_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    // The enable list is not operated by the plugin, so it is not written.
    ASSERT_EQ(GetSavedValue(KEY_ENABLE_USER_LIST), "");
    ASSERT_EQ(GetSavedValue(KEY_DISABLE_USER_LIST), "102|100");
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_063
 * @tc.desc: Test the plugin no longer overrides OnGetPolicy, so the query result is taken from the
 *           saved policy value and the certificate manager config is not read.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_063, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems(DefaultConfigItems());
    DisallowInstallDeviceCertificatePlugin plugin;
    std::string policyData = "true";
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, VALID_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    int32_t replyCode = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(replyCode));
    ASSERT_EQ(replyCode, ERR_OK);
    bool disallow = false;
    ASSERT_TRUE(reply.ReadBool(disallow));
    // The saved policy value carries the restriction, so the query reports it as disallowed.
    ASSERT_TRUE(disallow);
    // The query is served from the saved policy, so the certificate manager must not be touched.
    ASSERT_EQ(CertManagerSdkStub::GetGetConfigCallCount(), 0U);
    ASSERT_EQ(CertManagerSdkStub::GetSetConfigCallCount(), 0U);
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_064
 * @tc.desc: Test an empty saved policy value is reported as not disallowed and the certificate
 *           manager config is not read.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_064, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems(DefaultConfigItems());
    DisallowInstallDeviceCertificatePlugin plugin;
    std::string policyData = "";
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, VALID_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    int32_t replyCode = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(replyCode));
    ASSERT_EQ(replyCode, ERR_OK);
    bool disallow = true;
    ASSERT_TRUE(reply.ReadBool(disallow));
    // No policy has been saved, so the certificate installation stays allowed.
    ASSERT_FALSE(disallow);
    ASSERT_EQ(CertManagerSdkStub::GetGetConfigCallCount(), 0U);
    ASSERT_EQ(CertManagerSdkStub::GetSetConfigCallCount(), 0U);
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_065
 * @tc.desc: Test IsUserIdInList finds the user id in the list and reports the exact match only.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_065, TestSize.Level1)
{
    DisallowInstallDeviceCertificatePlugin plugin;
    // The user id is the first token of the list.
    ASSERT_TRUE(plugin.IsUserIdInList("100|101", VALID_USER_ID));
    // The user id is the last token of the list.
    ASSERT_TRUE(plugin.IsUserIdInList("101|100", VALID_USER_ID));
    // The user id is the only token of the list.
    ASSERT_TRUE(plugin.IsUserIdInList("100", VALID_USER_ID));
    // A longer token must not match the shorter user id.
    ASSERT_FALSE(plugin.IsUserIdInList("1000|101", VALID_USER_ID));
    // A shorter token must not match the longer user id.
    ASSERT_FALSE(plugin.IsUserIdInList("10|101", VALID_USER_ID));
    // Another user id is not reported as a member of the list.
    ASSERT_FALSE(plugin.IsUserIdInList("101|102", VALID_USER_ID));
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_066
 * @tc.desc: Test IsUserIdInList handles an empty list and a list that only holds separators.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_066, TestSize.Level1)
{
    DisallowInstallDeviceCertificatePlugin plugin;
    // An empty list holds no user id.
    ASSERT_FALSE(plugin.IsUserIdInList("", VALID_USER_ID));
    // A list that only holds separators holds no user id.
    ASSERT_FALSE(plugin.IsUserIdInList("||", VALID_USER_ID));
    // A list with leading and trailing separators still reports the user id.
    ASSERT_TRUE(plugin.IsUserIdInList("|100|", VALID_USER_ID));
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_067
 * @tc.desc: Test AppendUserListToken appends the token, skips the empty token and skips the excluded user id.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_067, TestSize.Level1)
{
    DisallowInstallDeviceCertificatePlugin plugin;
    std::string result;
    // The token is appended to an empty result without a leading separator.
    plugin.AppendUserListToken("100", "101", result);
    ASSERT_EQ(result, "100");
    // The token is appended behind the separator when the result is not empty.
    plugin.AppendUserListToken("101", "102", result);
    ASSERT_EQ(result, "100|101");
    // The empty token is skipped.
    plugin.AppendUserListToken("", "102", result);
    ASSERT_EQ(result, "100|101");
    // The excluded user id is skipped.
    plugin.AppendUserListToken("102", "102", result);
    ASSERT_EQ(result, "100|101");
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_068
 * @tc.desc: Test RemoveUserIdFromList removes the user id and keeps the other users.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_068, TestSize.Level1)
{
    DisallowInstallDeviceCertificatePlugin plugin;
    std::string result;
    // The user id is removed from the middle of the list.
    plugin.RemoveUserIdFromList("101|100|102", VALID_USER_ID, result);
    ASSERT_EQ(result, "101|102");
    // The user id is removed from the head of the list.
    plugin.RemoveUserIdFromList("100|101", VALID_USER_ID, result);
    ASSERT_EQ(result, "101");
    // The user id is removed from the tail of the list.
    plugin.RemoveUserIdFromList("101|100", VALID_USER_ID, result);
    ASSERT_EQ(result, "101");
    // A user id that is not in the list does not change the list.
    plugin.RemoveUserIdFromList("101|102", VALID_USER_ID, result);
    ASSERT_EQ(result, "101|102");
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_069
 * @tc.desc: Test RemoveUserIdFromList clears the previous result and drops the empty tokens.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_069, TestSize.Level1)
{
    DisallowInstallDeviceCertificatePlugin plugin;
    std::string result = "old";
    // The previous result is cleared before the list is rebuilt.
    plugin.RemoveUserIdFromList("101|102", VALID_USER_ID, result);
    ASSERT_EQ(result, "101|102");
    // The empty token between two separators is dropped.
    plugin.RemoveUserIdFromList("101||102", VALID_USER_ID, result);
    ASSERT_EQ(result, "101|102");
    // The leading and trailing empty tokens are dropped.
    plugin.RemoveUserIdFromList("|101|", VALID_USER_ID, result);
    ASSERT_EQ(result, "101");
    // A list that only holds separators rebuilds to an empty list.
    plugin.RemoveUserIdFromList("||", VALID_USER_ID, result);
    ASSERT_EQ(result, "");
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_070
 * @tc.desc: Test disabling certificate installation forces the default config to enable and never
 *           writes the enable list key to the certificate manager.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_070, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems({
        {KEY_DEFAULT_CONFIG, VALUE_DISABLE},
        {KEY_ENABLE_USER_LIST, "101"},
        {KEY_DISABLE_USER_LIST, ""},
    });
    DisallowInstallDeviceCertificatePlugin plugin;
    ErrCode ret = plugin.SetOtherModulePolicy(true, VALID_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(CertManagerSdkStub::GetSetConfigCallCount(), 1U);
    // The default config is forced to "enable" even though the stored value was "disable".
    ASSERT_EQ(GetSavedValue(KEY_DEFAULT_CONFIG), VALUE_ENABLE);
    // The disable list carries the user that is not allowed to install the device level certificate.
    ASSERT_EQ(GetSavedValue(KEY_DISABLE_USER_LIST), "100");
    // The enable list key is not part of the written config at all.
    auto saved = CertManagerSdkStub::GetSavedConfigItems();
    for (const auto &item : saved) {
        ASSERT_NE(item.first, KEY_ENABLE_USER_LIST);
    }
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_071
 * @tc.desc: Test enabling certificate installation forces the default config to enable and never
 *           writes the enable list key to the certificate manager.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_071, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems({
        {KEY_DEFAULT_CONFIG, VALUE_DISABLE},
        {KEY_ENABLE_USER_LIST, "101"},
        {KEY_DISABLE_USER_LIST, "100"},
    });
    DisallowInstallDeviceCertificatePlugin plugin;
    ErrCode ret = plugin.SetOtherModulePolicy(false, VALID_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(CertManagerSdkStub::GetSetConfigCallCount(), 1U);
    // The default config is forced to "enable" even though the stored value was "disable".
    ASSERT_EQ(GetSavedValue(KEY_DEFAULT_CONFIG), VALUE_ENABLE);
    // The user is removed from the disable list.
    ASSERT_EQ(GetSavedValue(KEY_DISABLE_USER_LIST), "");
    // The enable list key is not part of the written config at all.
    auto saved = CertManagerSdkStub::GetSavedConfigItems();
    for (const auto &item : saved) {
        ASSERT_NE(item.first, KEY_ENABLE_USER_LIST);
    }
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_072
 * @tc.desc: Test enabling certificate installation removes the user from the disable list and keeps
 *           the other users, and the default config is forced to enable.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_072, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems({
        {KEY_DEFAULT_CONFIG, VALUE_ENABLE},
        {KEY_ENABLE_USER_LIST, ""},
        {KEY_DISABLE_USER_LIST, "100|101"},
    });
    DisallowInstallDeviceCertificatePlugin plugin;
    ErrCode ret = plugin.SetOtherModulePolicy(false, VALID_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    // Only the target user is removed, the other user is kept.
    ASSERT_EQ(GetSavedValue(KEY_DISABLE_USER_LIST), "101");
    ASSERT_EQ(GetSavedValue(KEY_DEFAULT_CONFIG), VALUE_ENABLE);
}

/**
 * @tc.name: DisallowInstallDeviceCertificatePluginTest_073
 * @tc.desc: Test the disable and enable flow is symmetric, so the disable list returns to its
 *           original value and the default config stays enable.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowInstallDeviceCertificatePluginTest, DisallowInstallDeviceCertificatePluginTest_073, TestSize.Level1)
{
    CertManagerSdkStub::SetConfigItems({
        {KEY_DEFAULT_CONFIG, VALUE_ENABLE},
        {KEY_ENABLE_USER_LIST, ""},
        {KEY_DISABLE_USER_LIST, "101"},
    });
    DisallowInstallDeviceCertificatePlugin plugin;
    ASSERT_EQ(plugin.SetOtherModulePolicy(true, VALID_USER_ID), ERR_OK);
    ASSERT_EQ(GetSavedValue(KEY_DISABLE_USER_LIST), "101|100");
    ASSERT_EQ(GetSavedValue(KEY_DEFAULT_CONFIG), VALUE_ENABLE);

    // Feed the result back as the current config, then re-enable the installation.
    CertManagerSdkStub::SetConfigItems({
        {KEY_DEFAULT_CONFIG, VALUE_ENABLE},
        {KEY_ENABLE_USER_LIST, ""},
        {KEY_DISABLE_USER_LIST, GetSavedValue(KEY_DISABLE_USER_LIST)},
    });
    ASSERT_EQ(plugin.SetOtherModulePolicy(false, VALID_USER_ID), ERR_OK);
    ASSERT_EQ(GetSavedValue(KEY_DISABLE_USER_LIST), "101");
    ASSERT_EQ(GetSavedValue(KEY_DEFAULT_CONFIG), VALUE_ENABLE);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
