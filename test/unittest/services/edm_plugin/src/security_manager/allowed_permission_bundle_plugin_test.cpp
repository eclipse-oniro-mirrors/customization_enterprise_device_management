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
#include "allowed_permission_bundle_plugin.h"
#undef private
#undef protected

#include "allowed_permission_bundle_serializer.h"
#include "array_string_serializer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "ipolicy_manager.h"
#include "func_code_utils.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {

class AllowedPermissionBundlePluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void)
    {
        Utils::SetEdmInitialEnv();
    }

    static void TearDownTestSuite(void)
    {
        Utils::ResetTokenTypeAndUid();
        ASSERT_TRUE(Utils::IsOriginalUTEnv());
        std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
    }

    void SetUp() override
    {
        plugin_ = std::make_shared<AllowedPermissionBundlePlugin>();
    }

    void TearDown() override
    {
        plugin_ = nullptr;
    }

    std::shared_ptr<AllowedPermissionBundlePlugin> plugin_;
};

HWTEST_F(AllowedPermissionBundlePluginTest, TestReadParametersInvalidPermission_FAIL, TestSize.Level1)
{
    MessageParcel data;
    data.WriteString("");
    data.WriteString("");
    data.WriteString("com.test.app1");
    data.WriteInt32(100);
    data.WriteInt32(0);

    PolicyOperationParams params;
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::ALLOWED_PERMISSION_BUNDLE);
    ErrCode ret = plugin_->ReadParameters(data, params, funcCode);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

HWTEST_F(AllowedPermissionBundlePluginTest, TestReadParametersInvalidAppIdentifier_FAIL, TestSize.Level1)
{
    MessageParcel data;
    data.WriteString("");
    data.WriteString("ohos.permission.CAMERA");
    data.WriteString("");
    data.WriteInt32(100);
    data.WriteInt32(0);

    PolicyOperationParams params;
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::ALLOWED_PERMISSION_BUNDLE);
    ErrCode ret = plugin_->ReadParameters(data, params, funcCode);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

HWTEST_F(AllowedPermissionBundlePluginTest, TestReadParametersAppUninstallScene_SUC, TestSize.Level1)
{
    MessageParcel data;
    data.WriteString(EdmConstants::SCENE_APP_UNINSTALL);
    data.WriteString("ohos.permission.CAMERA");
    data.WriteString("123456");
    data.WriteString("com.test.app1");
    data.WriteInt32(100);
    data.WriteInt32(0);

    PolicyOperationParams params;
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE,
        EdmInterfaceCode::ALLOWED_PERMISSION_BUNDLE);
    ErrCode ret = plugin_->ReadParameters(data, params, funcCode);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(params.scene, PolicyScene::APP_UNINSTALL);
}

HWTEST_F(AllowedPermissionBundlePluginTest, TestReadParametersRemoveScene_SUC, TestSize.Level1)
{
    MessageParcel data;
    data.WriteString("");
    data.WriteString("ohos.permission.CAMERA");
    data.WriteString("123345");
    data.WriteString("com.test.app1");
    data.WriteInt32(100);
    data.WriteInt32(0);

    PolicyOperationParams params;
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE,
        EdmInterfaceCode::ALLOWED_PERMISSION_BUNDLE);
    ErrCode ret = plugin_->ReadParameters(data, params, funcCode);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(params.type, FuncOperateType::REMOVE);
    EXPECT_EQ(params.scene, PolicyScene::POLICY_REMOVE);
}

HWTEST_F(AllowedPermissionBundlePluginTest, TestOnGetPolicy_SUC, TestSize.Level1)
{
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin_->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS