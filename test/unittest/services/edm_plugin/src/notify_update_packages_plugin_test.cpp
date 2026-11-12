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

#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "iplugin.h"
#include "message_parcel.h"
#include "notify_update_packages_plugin.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class NotifyUpdatePackagesPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void NotifyUpdatePackagesPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void NotifyUpdatePackagesPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
}

/**
 * @tc.name: TestOnSetPolicyNormal
 * @tc.desc: Test NotifyUpdatePackagesPlugin::OnSetPolicy clears authInfo and returns unsupported.
 * @tc.type: FUNC
 */
HWTEST_F(NotifyUpdatePackagesPluginTest, TestOnSetPolicyNormal, TestSize.Level1)
{
    NotifyUpdatePackagesPlugin plugin;
    UpgradePackageInfo packageInfo;
    packageInfo.authInfoSize = 8;
    packageInfo.authInfo[0] = 'a';
    ErrCode ret = plugin.OnSetPolicy(packageInfo);
    EXPECT_EQ(ret, EdmReturnErrCode::INTERFACE_UNSUPPORTED);
    EXPECT_EQ(packageInfo.authInfo[0], '\0');
}

/**
 * @tc.name: TestOnSetPolicyAuthInfoTooLarge
 * @tc.desc: Test NotifyUpdatePackagesPlugin::OnSetPolicy rejects an oversized authInfo.
 * @tc.type: FUNC
 */
HWTEST_F(NotifyUpdatePackagesPluginTest, TestOnSetPolicyAuthInfoTooLarge, TestSize.Level1)
{
    NotifyUpdatePackagesPlugin plugin;
    UpgradePackageInfo packageInfo;
    packageInfo.authInfoSize = EdmConstants::AUTH_INFO_MAX_SIZE + 1;
    ErrCode ret = plugin.OnSetPolicy(packageInfo);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnGetPolicy
 * @tc.desc: Test NotifyUpdatePackagesPlugin::OnGetPolicy returns unsupported.
 * @tc.type: FUNC
 */
HWTEST_F(NotifyUpdatePackagesPluginTest, TestOnGetPolicy, TestSize.Level1)
{
    NotifyUpdatePackagesPlugin plugin;
    MessageParcel data;
    MessageParcel reply;
    std::string policyData;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::INTERFACE_UNSUPPORTED);
}

/**
 * @tc.name: TestPluginAttributes
 * @tc.desc: Test NotifyUpdatePackagesPlugin policy code and policy name.
 * @tc.type: FUNC
 */
HWTEST_F(NotifyUpdatePackagesPluginTest, TestPluginAttributes, TestSize.Level1)
{
    auto plugin = NotifyUpdatePackagesPlugin::GetPlugin();
    ASSERT_NE(plugin, nullptr);
    EXPECT_EQ(plugin->GetCode(), EdmInterfaceCode::NOTIFY_UPGRADE_PACKAGES);
    EXPECT_EQ(plugin->GetPolicyName(), PolicyName::POLICY_NOTIFY_UPGRADE_PACKAGES);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
