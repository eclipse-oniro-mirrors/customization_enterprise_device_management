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

#include "disallowed_uninstall_bundles_plugin_test.h"
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

void DisallowedUninstallBundlesPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DisallowedUninstallBundlesPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestDisallowedUninstallBundlesPlugin
 * @tc.desc: Test DisallowedUninstallBundlesPlugin::OnSetPolicy when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUninstallBundlesPluginTest, TestDisallowedUninstallBundlesPlugin001, TestSize.Level1)
{
    DisallowedUninstallBundlesPlugin plugin;
    std::vector<std::string> data;
    std::vector<std::string> currentData;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDisallowedUninstallBundlesPlugin
 * @tc.desc: Test DisallowedUninstallBundlesPlugin::OnSetPolicy when data.size() > MAX_SIZE.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUninstallBundlesPluginTest, TestDisallowedUninstallBundlesPlugin002, TestSize.Level1)
{
    DisallowedUninstallBundlesPlugin plugin;
    std::vector<std::string> data(OVER_MAX_SIZE, "testData");
    std::vector<std::string> currentData;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestDisallowedUninstallBundlesPlugin
 * @tc.desc: Test DisallowedUninstallBundlesPlugin::OnSetPolicy func is SYSTEM_ABNORMALLY.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUninstallBundlesPluginTest, TestDisallowedUninstallBundlesPlugin003, TestSize.Level1)
{
    Utils::ResetTokenTypeAndUid();
    DisallowedUninstallBundlesPlugin plugin;
    std::vector<std::string> data = {"testBundles"};
    std::vector<std::string> currentData;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
    Utils::SetEdmInitialEnv();
}

/**
 * @tc.name: TestDisallowedUninstallBundlesPlugin
 * @tc.desc: Test DisallowedUninstallBundlesPlugin::OnGetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUninstallBundlesPluginTest, TestDisallowedUninstallBundlesPlugin004, TestSize.Level1)
{
    DisallowedUninstallBundlesPlugin plugin;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDisallowedUninstallBundlesPlugin
 * @tc.desc: Test DisallowedUninstallBundlesPlugin::OnRemovePolicy when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUninstallBundlesPluginTest, TestDisallowedUninstallBundlesPlugin005, TestSize.Level1)
{
    DisallowedUninstallBundlesPlugin plugin;
    std::vector<std::string> data;
    std::vector<std::string> currentData;
    ErrCode ret = plugin.OnRemovePolicy(data, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDisallowedUninstallBundlesPlugin
 * @tc.desc: Test DisallowedUninstallBundlesPlugin::OnRemovePolicy func when it is SYSTEM_ABNORMALLY.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUninstallBundlesPluginTest, TestDisallowedUninstallBundlesPlugin006, TestSize.Level1)
{
    Utils::ResetTokenTypeAndUid();
    DisallowedUninstallBundlesPlugin plugin;
    std::vector<std::string> data = {"testBundles"};
    std::vector<std::string> currentData;
    ErrCode ret = plugin.OnRemovePolicy(data, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
    Utils::SetEdmInitialEnv();
}

/**
 * @tc.name: TestDisallowedUninstallBundlesPlugin
 * @tc.desc: Test DisallowedUninstallBundlesPlugin::OnAdminRemoveDone func.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUninstallBundlesPluginTest, TestDisallowedUninstallBundlesPlugin007, TestSize.Level1)
{
    sptr<AppExecFwk::BundleMgrProxy> bundleMgrProxy = iface_cast<AppExecFwk::BundleMgrProxy>(
        EdmSysManager::GetRemoteObjectOfSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID));
    sptr<AppExecFwk::IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();
    // set policy that "testBundle" is allowed to install.
    DisallowedUninstallBundlesPlugin plugin;
    std::vector<std::string> data = {"testBundle"};
    std::vector<std::string> currentData;
    ErrCode res = plugin.OnSetPolicy(data, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(currentData.size() == 1);
    ASSERT_TRUE(currentData[0] == "testBundle");

    // get current policy.
    std::vector<std::string> result;
    res = appControlProxy->
        GetAppInstallControlRule(AppExecFwk::AppInstallControlRuleType::DISALLOWED_UNINSTALL, DEFAULT_USER_ID, result);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(result.size() == 1);
    ASSERT_TRUE(result[0] == "testBundle");

    // remove policy.
    std::string adminName = "testName";
    plugin.OnAdminRemoveDone(adminName, data, DEFAULT_USER_ID);

    // get current policy.
    result.clear();
    res = appControlProxy->
        GetAppInstallControlRule(AppExecFwk::AppInstallControlRuleType::DISALLOWED_UNINSTALL, DEFAULT_USER_ID, result);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(result.size() == 0);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS