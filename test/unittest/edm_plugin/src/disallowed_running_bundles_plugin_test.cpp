/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "disallowed_running_bundles_plugin_test.h"
#include "bundle_mgr_proxy.h"
#include "edm_constants.h"
#include "edm_sys_manager.h"
#include "if_system_ability_manager.h"
#include "iremote_stub.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string TEST_BUNDLE = "testBundle";

void DisallowedRunningBundlesPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DisallowedRunningBundlesPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestDisallowedRunningBundlesPlugin
 * @tc.desc: Test DisallowedRunningBundlesPlugin::OnSetPolicy when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedRunningBundlesPluginTest, TestDisallowedRunningBundlesPlugin001, TestSize.Level1)
{
    DisallowedRunningBundlesPlugin plugin;
    std::vector<std::string> data;
    std::vector<std::string> currentData;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDisallowedRunningBundlesPlugin
 * @tc.desc: Test DisallowedRunningBundlesPlugin::OnSetPolicy when data.size() > MAX_SIZE.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedRunningBundlesPluginTest, TestDisallowedRunningBundlesPlugin002, TestSize.Level1)
{
    DisallowedRunningBundlesPlugin plugin;
    std::vector<std::string> data(EdmConstants::APPID_MAX_SIZE + 1, TEST_BUNDLE);
    std::vector<std::string> currentData;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestDisallowedRunningBundlesPlugin
 * @tc.desc: Test DisallowedRunningBundlesPlugin::OnSetPolicy func.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedRunningBundlesPluginTest, TestDisallowedRunningBundlesPlugin003, TestSize.Level1)
{
    Utils::ResetTokenTypeAndUid();
    DisallowedRunningBundlesPlugin plugin;
    std::vector<std::string> data = { TEST_BUNDLE };
    std::vector<std::string> currentData;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
    Utils::SetEdmInitialEnv();
}

/**
 * @tc.name: TestDisallowedRunningBundlesPlugin
 * @tc.desc: Test DisallowedRunningBundlesPlugin::OnGetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedRunningBundlesPluginTest, TestDisallowedRunningBundlesPlugin004, TestSize.Level1)
{
    DisallowedRunningBundlesPlugin plugin;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDisallowedRunningBundlesPlugin
 * @tc.desc: Test DisallowedRunningBundlesPlugin::OnRemovePolicy when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedRunningBundlesPluginTest, TestDisallowedRunningBundlesPlugin005, TestSize.Level1)
{
    DisallowedRunningBundlesPlugin plugin;
    std::vector<std::string> data;
    std::vector<std::string> currentData;
    ErrCode ret = plugin.OnRemovePolicy(data, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDisallowedRunningBundlesPlugin
 * @tc.desc: Test DisallowedRunningBundlesPlugin::OnRemovePolicy func when it is SYSTEM_ABNORMALLY.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedRunningBundlesPluginTest, TestDisallowedRunningBundlesPlugin006, TestSize.Level1)
{
    Utils::ResetTokenTypeAndUid();
    DisallowedRunningBundlesPlugin plugin;
    std::vector<std::string> data = { TEST_BUNDLE };
    std::vector<std::string> currentData;
    ErrCode ret = plugin.OnRemovePolicy(data, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
    Utils::SetEdmInitialEnv();
}

/**
 * @tc.name: TestDisallowedRunningBundlesPlugin
 * @tc.desc: Test DisallowedRunningBundlesPlugin::OnAdminRemoveDone func.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedRunningBundlesPluginTest, TestDisallowedRunningBundlesPlugin007, TestSize.Level1)
{
    sptr<AppExecFwk::BundleMgrProxy> bundleMgrProxy = iface_cast<AppExecFwk::BundleMgrProxy>(
        EdmSysManager::GetRemoteObjectOfSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID));
    sptr<AppExecFwk::IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();
    // set policy that "testBundle" is disallowed to run.
    DisallowedRunningBundlesPlugin plugin;
    std::vector<std::string> data = { TEST_BUNDLE };
    std::vector<std::string> currentData;
    ErrCode res = plugin.OnSetPolicy(data, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(currentData.size() == 1);
    ASSERT_TRUE(currentData[0] == TEST_BUNDLE);

    // get current policy.
    std::vector<std::string> result;
    res = appControlProxy->
        GetAppRunningControlRule(DEFAULT_USER_ID, result);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(result.size() == 1);
    ASSERT_TRUE(result[0] == TEST_BUNDLE);

    // remove policy.
    std::string adminName = TEST_BUNDLE;
    std::vector<std::string> appIds = { TEST_BUNDLE };
    plugin.OnAdminRemoveDone(adminName, appIds, DEFAULT_USER_ID);

    // get current policy.
    result.clear();
    res = appControlProxy->GetAppRunningControlRule(DEFAULT_USER_ID, result);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(result.size() == 0);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS