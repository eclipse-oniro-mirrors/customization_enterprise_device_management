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

#include "install_existed_plugin.h"

#include <gtest/gtest.h>
#include <iostream>
#include <memory>
#include <string>

#include <message_parcel.h>

#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "func_code.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
constexpr int32_t INVALID_USER_ID = -1;
const std::string TEST_BUNDLE_NAME = "com.example.myapplication";
const std::string NOT_INSTALLED_BUNDLE_NAME = "com.ohos.edm.ut.not.installed.bundle";

class InstallExistedPluginTest : public testing::Test {
public:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);

    static std::uint32_t MakeFuncCode(void)
    {
        return POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::INSTALL_EXISTED);
    }
};

void InstallExistedPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void InstallExistedPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestPluginAttributes
 * @tc.desc: Test InstallExistedPlugin policy code, policy name, save flag, api type and permission.
 * @tc.type: FUNC
 */
HWTEST_F(InstallExistedPluginTest, TestPluginAttributes, TestSize.Level1)
{
    InstallExistedPlugin plugin;
    EXPECT_EQ(plugin.GetCode(), EdmInterfaceCode::INSTALL_EXISTED);
    EXPECT_EQ(plugin.GetPolicyName(), PolicyName::POLICY_INSTALL_EXISTED);
    EXPECT_FALSE(plugin.NeedSavePolicy());
    EXPECT_EQ(plugin.GetApiType(FuncOperateType::SET), IPlugin::ApiType::PUBLIC);
    EXPECT_EQ(plugin.GetPermission(FuncOperateType::SET, IPlugin::PermissionType::SUPER_DEVICE_ADMIN),
        EdmPermission::PERMISSION_ENTERPRISE_INSTALL_BUNDLE);
}

/**
 * @tc.name: TestOnHandlePolicyEmptyBundleName
 * @tc.desc: Test InstallExistedPlugin::OnHandlePolicy with an empty bundleName.
 * @tc.type: FUNC
 */
HWTEST_F(InstallExistedPluginTest, TestOnHandlePolicyEmptyBundleName, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("");
    auto plugin = std::make_shared<InstallExistedPlugin>();
    HandlePolicyData handlePolicyData{"false", "", false};
    ErrCode ret = plugin->OnHandlePolicy(MakeFuncCode(), data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnHandlePolicyEmptyData
 * @tc.desc: Test InstallExistedPlugin::OnHandlePolicy when no bundleName is written into the parcel.
 * @tc.type: FUNC
 */
HWTEST_F(InstallExistedPluginTest, TestOnHandlePolicyEmptyData, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    auto plugin = std::make_shared<InstallExistedPlugin>();
    HandlePolicyData handlePolicyData{"false", "", false};
    ErrCode ret = plugin->OnHandlePolicy(MakeFuncCode(), data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnHandlePolicyNegativeUserId
 * @tc.desc: Test InstallExistedPlugin::OnHandlePolicy with a negative userId.
 * @tc.type: FUNC
 */
HWTEST_F(InstallExistedPluginTest, TestOnHandlePolicyNegativeUserId, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteString(TEST_BUNDLE_NAME);
    auto plugin = std::make_shared<InstallExistedPlugin>();
    HandlePolicyData handlePolicyData{"false", "", false};
    ErrCode ret = plugin->OnHandlePolicy(MakeFuncCode(), data, reply, handlePolicyData, INVALID_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnHandlePolicyInvalidParam
 * @tc.desc: Test InstallExistedPlugin::OnHandlePolicy when both bundleName and userId are invalid.
 * @tc.type: FUNC
 */
HWTEST_F(InstallExistedPluginTest, TestOnHandlePolicyInvalidParam, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("");
    auto plugin = std::make_shared<InstallExistedPlugin>();
    HandlePolicyData handlePolicyData{"false", "", false};
    ErrCode ret = plugin->OnHandlePolicy(MakeFuncCode(), data, reply, handlePolicyData, INVALID_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnHandlePolicyBundleNotInstalled
 * @tc.desc: Test InstallExistedPlugin::OnHandlePolicy for a bundle that is not installed. When the bundle
 *           manager is reachable the not-exist error is mapped to DOCK_APP_NOT_INSTALLED; if the test
 *           environment has no bundle manager the call is expected to time out instead.
 * @tc.type: FUNC
 */
HWTEST_F(InstallExistedPluginTest, TestOnHandlePolicyBundleNotInstalled, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteString(NOT_INSTALLED_BUNDLE_NAME);
    auto plugin = std::make_shared<InstallExistedPlugin>();
    HandlePolicyData handlePolicyData{"false", "", false};
    ErrCode ret = plugin->OnHandlePolicy(MakeFuncCode(), data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_NE(ret, ERR_OK);
    EXPECT_NE(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    EXPECT_TRUE(ret == EdmReturnErrCode::DOCK_APP_NOT_INSTALLED ||
        ret == EdmReturnErrCode::APPLICATION_INSTALL_FAILED ||
        ret == EdmReturnErrCode::EXECUTE_TIME_OUT) << "unexpected error code: " << ret;
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS