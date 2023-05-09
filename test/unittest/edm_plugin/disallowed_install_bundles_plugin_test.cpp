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

#include "disallowed_install_bundles_plugin_test.h"
#include "bundle_mgr_proxy.h"
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
constexpr int32_t OVER_MAX_SIZE = 201;

void DisallowedInstallBundlesPluginTest::SetUpTestCase(void)
{
    Utils::SetEdmInitialEnv();
}

void DisallowedInstallBundlesPluginTest::TearDownTestCase(void)
{
    Utils::ResetTokenTypeAndUid();
}

/**
 * @tc.name: TestDisallowedInstallBundlesPlugin
 * @tc.desc: Test DisallowedInstallBundlesPlugin::OnSetPolicy when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedInstallBundlesPluginTest, TestDisallowedInstallBundlesPlugin001, TestSize.Level1)
{
    DisallowedInstallBundlesPlugin plugin;
    std::vector<std::string> data;
    std::vector<std::string> currentData;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDisallowedInstallBundlesPlugin
 * @tc.desc: Test DisallowedInstallBundlesPlugin::OnSetPolicy when data.size() > MAX_SIZE.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedInstallBundlesPluginTest, TestDisallowedInstallBundlesPlugin002, TestSize.Level1)
{
    DisallowedInstallBundlesPlugin plugin;
    std::vector<std::string> data(OVER_MAX_SIZE, "testData");
    std::vector<std::string> currentData;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestDisallowedInstallBundlesPlugin
 * @tc.desc: Test DisallowedInstallBundlesPlugin::OnSetPolicy func is SYSTEM_ABNORMALLY.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedInstallBundlesPluginTest, TestDisallowedInstallBundlesPlugin003, TestSize.Level1)
{
    Utils::ResetTokenTypeAndUid();
    DisallowedInstallBundlesPlugin plugin;
    std::vector<std::string> data = {"testBundles"};
    std::vector<std::string> currentData;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
    Utils::SetEdmInitialEnv();
}

/**
 * @tc.name: TestDisallowedInstallBundlesPlugin
 * @tc.desc: Test DisallowedInstallBundlesPlugin::OnGetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedInstallBundlesPluginTest, TestDisallowedInstallBundlesPlugin004, TestSize.Level1)
{
    DisallowedInstallBundlesPlugin plugin;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDisallowedInstallBundlesPlugin
 * @tc.desc: Test DisallowedInstallBundlesPlugin::OnRemovePolicy when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedInstallBundlesPluginTest, TestDisallowedInstallBundlesPlugin005, TestSize.Level1)
{
    DisallowedInstallBundlesPlugin plugin;
    std::vector<std::string> data;
    std::vector<std::string> currentData;
    ErrCode ret = plugin.OnRemovePolicy(data, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDisallowedInstallBundlesPlugin
 * @tc.desc: Test DisallowedInstallBundlesPlugin::OnRemovePolicy func when it is SYSTEM_ABNORMALLY.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedInstallBundlesPluginTest, TestDisallowedInstallBundlesPlugin006, TestSize.Level1)
{
    Utils::ResetTokenTypeAndUid();
    DisallowedInstallBundlesPlugin plugin;
    std::vector<std::string> data = {"testBundles"};
    std::vector<std::string> currentData;
    ErrCode ret = plugin.OnRemovePolicy(data, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
    Utils::SetEdmInitialEnv();
}

/**
 * @tc.name: TestDisallowedInstallBundlesPlugin
 * @tc.desc: Test DisallowedInstallBundlesPlugin::OnAdminRemoveDone func.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedInstallBundlesPluginTest, TestDisallowedInstallBundlesPlugin007, TestSize.Level1)
{
    sptr<AppExecFwk::BundleMgrProxy> bundleMgrProxy = iface_cast<AppExecFwk::BundleMgrProxy>(
        EdmSysManager::GetRemoteObjectOfSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID));
    sptr<AppExecFwk::IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();
    // set policy that "testBundle" is allowed to install.
    DisallowedInstallBundlesPlugin plugin;
    std::vector<std::string> data = {"testBundle"};
    std::vector<std::string> currentData;
    ErrCode res = plugin.OnSetPolicy(data, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(currentData.size() == 1);
    ASSERT_TRUE(currentData[0] == "testBundle");

    // get current policy.
    std::vector<std::string> result;
    res = appControlProxy->
        GetAppInstallControlRule(AppExecFwk::AppInstallControlRuleType::DISALLOWED_INSTALL, DEFAULT_USER_ID, result);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(result.size() == 1);
    ASSERT_TRUE(result[0] == "testBundle");

    // remove policy.
    std::string adminName = "testName";
    plugin.OnAdminRemoveDone(adminName, data, DEFAULT_USER_ID);

    // get current policy.
    result.clear();
    res = appControlProxy->
        GetAppInstallControlRule(AppExecFwk::AppInstallControlRuleType::DISALLOWED_INSTALL, DEFAULT_USER_ID, result);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(result.size() == 0);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS