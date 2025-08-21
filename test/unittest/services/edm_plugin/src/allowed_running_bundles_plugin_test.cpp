/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "allowed_running_bundles_plugin_test.h"

#define protected public
#define private public
#include "allowed_running_bundles_plugin.h"
#include "disallowed_running_bundles_plugin.h"
#include "policy_manager.h"
#undef private
#undef protected

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
const std::string TEST_ADMIN_NAME = "com.edm.test.demo";
const std::string TEST_MERAGE_POLICY_VALUE = "mergedValue";

void AllowedRunningBundlesPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void AllowedRunningBundlesPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestAllowedRunningBundlesPlugin
 * @tc.desc: Test AllowedRunningBundlesPlugin::OnSetPolicy when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedRunningBundlesPluginTest, TestAllowedRunningBundlesPlugin001, TestSize.Level1)
{
    AllowedRunningBundlesPlugin plugin;
    plugin.maxListSize_ = EdmConstants::APPID_MAX_SIZE;
    std::vector<std::string> data;
    std::vector<std::string> currentData;
    std::vector<std::string> mergeData;
    ErrCode ret = plugin.OnBasicSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestAllowedRunningBundlesPlugin
 * @tc.desc: Test AllowedRunningBundlesPlugin::OnSetPolicy when data.size() > MAX_SIZE.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedRunningBundlesPluginTest, TestAllowedRunningBundlesPlugin002, TestSize.Level1)
{
    AllowedRunningBundlesPlugin plugin;
    plugin.maxListSize_ = EdmConstants::APPID_MAX_SIZE;
    std::vector<std::string> data(EdmConstants::APPID_MAX_SIZE + 1, TEST_BUNDLE);
    std::vector<std::string> currentData;
    std::vector<std::string> mergeData;
    ErrCode ret = plugin.OnBasicSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestAllowedRunningBundlesPlugin
 * @tc.desc: Test AllowedRunningBundlesPlugin::OnSetPolicy func.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedRunningBundlesPluginTest, TestAllowedRunningBundlesPlugin003, TestSize.Level1)
{
    Utils::ResetTokenTypeAndUid();
    AllowedRunningBundlesPlugin plugin;
    plugin.maxListSize_ = EdmConstants::APPID_MAX_SIZE;
    std::vector<std::string> data = {TEST_BUNDLE};
    std::vector<std::string> currentData;
    std::vector<std::string> mergeData;
    ErrCode ret = plugin.OnBasicSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
    Utils::SetEdmInitialEnv();
}

/**
 * @tc.name: TestAllowedRunningBundlesPlugin
 * @tc.desc: Test AllowedRunningBundlesPlugin::OnGetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedRunningBundlesPluginTest, TestAllowedRunningBundlesPlugin004, TestSize.Level1)
{
    AllowedRunningBundlesPlugin plugin;
    plugin.maxListSize_ = EdmConstants::APPID_MAX_SIZE;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestAllowedRunningBundlesPlugin
 * @tc.desc: Test AllowedRunningBundlesPlugin::OnAdminRemoveDone func.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedRunningBundlesPluginTest, TestAllowedRunningBundlesPlugin005, TestSize.Level1)
{
    sptr<AppExecFwk::BundleMgrProxy> bundleMgrProxy = iface_cast<AppExecFwk::BundleMgrProxy>(
        EdmSysManager::GetRemoteObjectOfSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID));
    sptr<AppExecFwk::IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();
    // set policy that "testBundle" is allowed to run.
    AllowedRunningBundlesPlugin plugin;
    plugin.maxListSize_ = EdmConstants::APPID_MAX_SIZE;
    std::vector<std::string> data = {TEST_BUNDLE};
    std::vector<std::string> currentData;
    std::vector<std::string> mergeData;
    ErrCode res = plugin.OnBasicSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(currentData.size() == 1);
    ASSERT_TRUE(currentData[0] == TEST_BUNDLE);

    // get current policy.
    std::vector<std::string> result;
    bool isAllowRunningRule = false;
    res = appControlProxy->GetAppRunningControlRule(DEFAULT_USER_ID, result, isAllowRunningRule);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(result.size() == 1);
    ASSERT_TRUE(result[0] == TEST_BUNDLE);

    // remove policy.
    std::string adminName = TEST_BUNDLE;
    std::vector<std::string> appIds = {TEST_BUNDLE};
    mergeData.clear();
    plugin.OnBasicAdminRemove(adminName, appIds, mergeData, DEFAULT_USER_ID);

    // get current policy.
    result.clear();
    isAllowRunningRule = true;
    res = appControlProxy->GetAppRunningControlRule(DEFAULT_USER_ID, result, isAllowRunningRule);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(result.size() == 0);
}

/**
 * @tc.name: TestSetOtherModulePolicyConflict
 * @tc.desc: Test AllowedRunningBundlesPlugin::SetOtherModulePolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedRunningBundlesPluginTest, TestSetOtherModulePolicyConflict, TestSize.Level1)
{
    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();
    ErrCode res = policyManager->SetPolicy(TEST_ADMIN_NAME, PolicyName::POLICY_DISALLOW_RUNNING_BUNDLES,
        TEST_MERAGE_POLICY_VALUE, TEST_MERAGE_POLICY_VALUE, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);

    AllowedRunningBundlesPlugin plugin;
    std::vector<std::string> allowedData = {"allowedData"};
    std::vector<std::string> failedData;
    ErrCode ret = plugin.SetOtherModulePolicy(allowedData, DEFAULT_USER_ID, failedData);
    ASSERT_TRUE(ret == EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);
    ASSERT_TRUE(failedData.empty());
    ErrCode clearRes = policyManager->SetPolicy(TEST_ADMIN_NAME, PolicyName::POLICY_DISALLOW_RUNNING_BUNDLES,
        "", "", DEFAULT_USER_ID);
    ASSERT_TRUE(clearRes == ERR_OK);
    IPolicyManager::policyManagerInstance_ = nullptr;
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS