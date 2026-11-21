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
#include "disallow_system_sharing_panel_plugin.h"
#undef protected
#undef private
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "basic_bool_plugin.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string TEST_BUNDLE_NAME = "testBundleName";
class DisallowSystemSharingPanelPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void DisallowSystemSharingPanelPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DisallowSystemSharingPanelPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: DisallowSystemSharingPanelOnSetPolicy
 * @tc.desc: Test DisallowSystemSharingPanelPlugin::OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowSystemSharingPanelPluginTest, DisallowSystemSharingPanelOnSetPolicy, TestSize.Level1)
{
    DisallowSystemSharingPanelPlugin plugin;
    bool data = true;
    bool currentData = false;
    bool mergeData = false;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    // idempotent: repeat the same disallow value
    ret = plugin.OnSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    data = false;
    ret = plugin.OnSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: DisallowSystemSharingPanelAdminRemove
 * @tc.desc: Test DisallowSystemSharingPanelPlugin::OnAdminRemove function.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowSystemSharingPanelPluginTest, DisallowSystemSharingPanelAdminRemove, TestSize.Level1)
{
    DisallowSystemSharingPanelPlugin plugin;
    bool data = false;
    bool mergeData = true;
    ErrCode ret = plugin.OnAdminRemove(TEST_BUNDLE_NAME, data, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    data = true;
    mergeData = false;
    ret = plugin.OnAdminRemove(TEST_BUNDLE_NAME, data, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: DisallowSystemSharingPanelSetOtherModulePolicyFail
 * @tc.desc: Test SetOtherModulePolicy failure path returns EXECUTE_TIME_OUT.
 *           Fault injection: invalid (non-existent) os account id makes
 *           SetSpecificOsAccountConstraints fail in the UT environment.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowSystemSharingPanelPluginTest, DisallowSystemSharingPanelSetOtherModulePolicyFail, TestSize.Level1)
{
    DisallowSystemSharingPanelPlugin plugin;
    const int32_t invalidUserId = 999999;
    ErrCode ret = plugin.SetOtherModulePolicy(true, invalidUserId);
    ASSERT_TRUE(ret == EdmReturnErrCode::EXECUTE_TIME_OUT);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
