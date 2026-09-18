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

#define protected public
#define private public
#include "external_storage_device_mount_policy_plugin.h"
#undef private
#undef protected

#include <gtest/gtest.h>

#include "edm_ipc_interface_code.h"
#include "mount_policy.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class ExternalStorageDeviceMountPolicyPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void ExternalStorageDeviceMountPolicyPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void ExternalStorageDeviceMountPolicyPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnGetPolicy
 * @tc.desc: Test ExternalStorageDeviceMountPolicyPlugin::OnGetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(ExternalStorageDeviceMountPolicyPluginTest, TestOnGetPolicy, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    std::shared_ptr<IPlugin> plugin = std::make_shared<ExternalStorageDeviceMountPolicyPlugin>();
    std::string policyData;
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
}

/**
 * @tc.name: TestOnHandlePolicyInvalidPolicy
 * @tc.desc: Test OnHandlePolicy with invalid mount policy.
 * @tc.type: FUNC
 */
HWTEST_F(ExternalStorageDeviceMountPolicyPluginTest, TestOnHandlePolicyInvalidPolicy, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("volume_test");
    data.WriteInt32(999);
    std::shared_ptr<IPlugin> plugin = std::make_shared<ExternalStorageDeviceMountPolicyPlugin>();
    std::uint32_t funcCode = POLICY_FUNC_CODE_NEW((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::EXTERNAL_STORAGE_DEVICE_MOUNT_POLICY);
    HandlePolicyData handlePolicyData{"", "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestExecuteMountPolicyInvalid
 * @tc.desc: Test ExecuteMountPolicy with invalid policy value.
 * @tc.type: FUNC
 */
HWTEST_F(ExternalStorageDeviceMountPolicyPluginTest, TestExecuteMountPolicyInvalid, TestSize.Level1)
{
    ExternalStorageDeviceMountPolicyPlugin plugin;
    ErrCode ret = plugin.ExecuteMountPolicy("volume_test", -1);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnAdminRemove
 * @tc.desc: Test ExternalStorageDeviceMountPolicyPlugin::OnAdminRemove function.
 * @tc.type: FUNC
 */
HWTEST_F(ExternalStorageDeviceMountPolicyPluginTest, TestOnAdminRemove, TestSize.Level1)
{
    ExternalStorageDeviceMountPolicyPlugin plugin;
    std::string adminName{"testAdminName"};
    std::string policyData;
    std::string mergeData;
    ErrCode ret = plugin.OnAdminRemove(adminName, policyData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
