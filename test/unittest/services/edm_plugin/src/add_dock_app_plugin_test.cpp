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

#include "add_dock_app_plugin.h"

#include <gtest/gtest.h>

#include "edm_ipc_interface_code.h"
#include "message_parcel.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class AddDockAppPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);
    static void TearDownTestSuite(void);
};

void AddDockAppPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void AddDockAppPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

HWTEST_F(AddDockAppPluginTest, TestOnHandlePolicy, TestSize.Level1)
{
    AddDockAppPlugin plugin;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    int32_t userId = 0;

    ErrCode ret = plugin.OnHandlePolicy(EdmInterfaceCode::ADD_DOCK_APP, data, reply, policyData, userId);
    ASSERT_TRUE(ret == EdmReturnErrCode::INTERFACE_UNSUPPORTED);
}

HWTEST_F(AddDockAppPluginTest, TestOnGetPolicy, TestSize.Level1)
{
    AddDockAppPlugin plugin;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    int32_t userId = 0;

    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, userId);
    ASSERT_TRUE(ret == EdmReturnErrCode::INTERFACE_UNSUPPORTED);
}

HWTEST_F(AddDockAppPluginTest, TestPluginCode, TestSize.Level1)
{
    AddDockAppPlugin plugin;
    ASSERT_TRUE(plugin.GetCode() == EdmInterfaceCode::ADD_DOCK_APP);
}

HWTEST_F(AddDockAppPluginTest, TestPluginName, TestSize.Level1)
{
    AddDockAppPlugin plugin;
    ASSERT_TRUE(plugin.GetPolicyName() == PolicyName::POLICY_ADD_DOCK_APP);
}

HWTEST_F(AddDockAppPluginTest, TestOnAdminRemove, TestSize.Level1)
{
    AddDockAppPlugin plugin;
    std::string adminName = "test_admin";
    std::string policyData = "{}";
    std::string mergeJsonData = "{}";
    int32_t userId = 0;

    ErrCode ret = plugin.OnAdminRemove(adminName, policyData, mergeJsonData, userId);
    ASSERT_TRUE(ret == ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS