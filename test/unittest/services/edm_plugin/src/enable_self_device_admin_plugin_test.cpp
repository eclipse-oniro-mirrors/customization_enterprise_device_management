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

#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "enable_self_device_admin_plugin.h"
#include "iplugin.h"
#include "message_parcel.h"
#include "edm_constants.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class EnableSelfDeviceAdminPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void EnableSelfDeviceAdminPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void EnableSelfDeviceAdminPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
}

/**
 * @tc.name: TestOnSetPolicy
 * @tc.desc: Test EnableSelfDeviceAdminPlugin::OnSetPolicy returns unsupported.
 * @tc.type: FUNC
 */
HWTEST_F(EnableSelfDeviceAdminPluginTest, TestOnSetPolicy, TestSize.Level1)
{
    EnableSelfDeviceAdminPlugin plugin;
    ErrCode ret = plugin.OnSetPolicy();
    EXPECT_EQ(ret, EdmReturnErrCode::INTERFACE_UNSUPPORTED);
}

/**
 * @tc.name: TestPluginAttributes
 * @tc.desc: Test EnableSelfDeviceAdminPlugin policy code and policy name.
 * @tc.type: FUNC
 */
HWTEST_F(EnableSelfDeviceAdminPluginTest, TestPluginAttributes, TestSize.Level1)
{
    auto plugin = EnableSelfDeviceAdminPlugin::GetPlugin();
    ASSERT_NE(plugin, nullptr);
    EXPECT_EQ(plugin->GetCode(), EdmInterfaceCode::ENABLE_SELF_DEVICE_ADMIN);
    EXPECT_EQ(plugin->GetPolicyName(), PolicyName::POLICY_ENABLE_SELF_DEVICE_ADMIN);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
