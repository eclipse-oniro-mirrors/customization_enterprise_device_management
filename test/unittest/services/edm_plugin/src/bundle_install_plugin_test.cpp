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

#include "bundle_install_plugin_test.h"

#include "allowed_install_bundles_plugin.h"
#include "bundle_mgr_proxy.h"
#include "disallowed_install_bundles_plugin.h"
#include "disallowed_uninstall_bundles_plugin.h"
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

void BundleInstallPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void BundleInstallPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnSetPolicySuc
 * @tc.desc: Test BundleInstallPlugin::OnSetPolicy when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(BundleInstallPluginTest, TestOnSetPolicySuc, TestSize.Level1)
{
    BundleInstallPlugin plugin;
    for (int32_t policyType = static_cast<int32_t>(AppExecFwk::AppInstallControlRuleType::DISALLOWED_UNINSTALL);
        policyType <= static_cast<int32_t>(AppExecFwk::AppInstallControlRuleType::DISALLOWED_INSTALL); policyType++) {
        plugin.SetAppInstallControlRuleType(static_cast<AppExecFwk::AppInstallControlRuleType>(policyType));
        std::vector<std::string> data;
        std::vector<std::string> currentData;
        ErrCode ret = plugin.OnSetPolicy(data, currentData, DEFAULT_USER_ID);
        ASSERT_TRUE(ret == ERR_OK);
    }
}

/**
 * @tc.name: TestOnSetPolicyFail
 * @tc.desc: Test BundleInstallPlugin::OnSetPolicy when data.size() > EdmConstants::APPID_MAX_SIZE.
 * @tc.type: FUNC
 */
HWTEST_F(BundleInstallPluginTest, TestOnSetPolicyFail, TestSize.Level1)
{
    BundleInstallPlugin plugin;
    for (int32_t policyType = static_cast<int32_t>(AppExecFwk::AppInstallControlRuleType::DISALLOWED_UNINSTALL);
        policyType <= static_cast<int32_t>(AppExecFwk::AppInstallControlRuleType::DISALLOWED_INSTALL); policyType++) {
        plugin.SetAppInstallControlRuleType(static_cast<AppExecFwk::AppInstallControlRuleType>(policyType));
        std::vector<std::string> data(EdmConstants::APPID_MAX_SIZE + 1, TEST_BUNDLE);
        std::vector<std::string> currentData;
        ErrCode ret = plugin.OnSetPolicy(data, currentData, DEFAULT_USER_ID);
        ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
    }
}

/**
 * @tc.name: TestOnSetPolicySysAbnormally
 * @tc.desc: Test BundleInstallPluginTest::OnSetPolicy func is SYSTEM_ABNORMALLY.
 * @tc.type: FUNC
 */
HWTEST_F(BundleInstallPluginTest, TestOnSetPolicySysAbnormally, TestSize.Level1)
{
    Utils::ResetTokenTypeAndUid();
    BundleInstallPlugin plugin;
    for (int32_t policyType = static_cast<int32_t>(AppExecFwk::AppInstallControlRuleType::DISALLOWED_UNINSTALL);
        policyType <= static_cast<int32_t>(AppExecFwk::AppInstallControlRuleType::DISALLOWED_INSTALL); policyType++) {
        plugin.SetAppInstallControlRuleType(static_cast<AppExecFwk::AppInstallControlRuleType>(policyType));
        std::vector<std::string> data = { TEST_BUNDLE };
        std::vector<std::string> currentData;
        ErrCode ret = plugin.OnSetPolicy(data, currentData, DEFAULT_USER_ID);
        ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
    }
    Utils::SetEdmInitialEnv();
}

/**
 * @tc.name: TestOnGetPolicy
 * @tc.desc: Test AllowedInstallBundlesPlugin::OnGetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(BundleInstallPluginTest, TestOnGetPolicy, TestSize.Level1)
{
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;

    AllowedInstallBundlesPlugin allowedInsatllPlugin;
    ErrCode ret = allowedInsatllPlugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);

    DisallowedInstallBundlesPlugin disallowedInsatllPlugin;
    ret = disallowedInsatllPlugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);

    DisallowedUninstallBundlesPlugin disallowedUninsatllPlugin;
    ret = disallowedUninsatllPlugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestAllowedInstallBundlesPlugin
 * @tc.desc: Test AllowedInstallBundlesPlugin::OnRemovePolicy when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(BundleInstallPluginTest, TestAllowedInstallBundlesPlugin005, TestSize.Level1)
{
    BundleInstallPlugin plugin;
    for (int32_t policyType = static_cast<int32_t>(AppExecFwk::AppInstallControlRuleType::DISALLOWED_UNINSTALL);
        policyType <= static_cast<int32_t>(AppExecFwk::AppInstallControlRuleType::DISALLOWED_INSTALL); policyType++) {
        plugin.SetAppInstallControlRuleType(static_cast<AppExecFwk::AppInstallControlRuleType>(policyType));
        std::vector<std::string> data;
        std::vector<std::string> currentData;
        ErrCode ret = plugin.OnRemovePolicy(data, currentData, DEFAULT_USER_ID);
        ASSERT_TRUE(ret == ERR_OK);
    }
}

/**
 * @tc.name: TestAllowedInstallBundlesPlugin
 * @tc.desc: Test AllowedInstallBundlesPlugin::OnRemovePolicy func when it is SYSTEM_ABNORMALLY.
 * @tc.type: FUNC
 */
HWTEST_F(BundleInstallPluginTest, TestAllowedInstallBundlesPlugin006, TestSize.Level1)
{
    Utils::ResetTokenTypeAndUid();
    BundleInstallPlugin plugin;
    for (int32_t policyType = static_cast<int32_t>(AppExecFwk::AppInstallControlRuleType::DISALLOWED_UNINSTALL);
        policyType <= static_cast<int32_t>(AppExecFwk::AppInstallControlRuleType::DISALLOWED_INSTALL); policyType++) {
        plugin.SetAppInstallControlRuleType(static_cast<AppExecFwk::AppInstallControlRuleType>(policyType));
        std::vector<std::string> data = { TEST_BUNDLE };
        std::vector<std::string> currentData;
        ErrCode ret = plugin.OnRemovePolicy(data, currentData, DEFAULT_USER_ID);
        ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
    }
    Utils::SetEdmInitialEnv();
}

/**
 * @tc.name: TestAllowedInstallBundlesPlugin
 * @tc.desc: Test AllowedInstallBundlesPlugin::OnRemovePolicy function success.
 * @tc.type: FUNC
 */
HWTEST_F(BundleInstallPluginTest, TestAllowedInstallBundlesPluginSuc, TestSize.Level1)
{
    BundleInstallPlugin plugin;
    for (int32_t policyType = static_cast<int32_t>(AppExecFwk::AppInstallControlRuleType::DISALLOWED_UNINSTALL);
        policyType <= static_cast<int32_t>(AppExecFwk::AppInstallControlRuleType::DISALLOWED_INSTALL); policyType++) {
        plugin.SetAppInstallControlRuleType(static_cast<AppExecFwk::AppInstallControlRuleType>(policyType));
        std::vector<std::string> data = { TEST_BUNDLE };
        std::vector<std::string> currentData;
        ErrCode ret = plugin.OnRemovePolicy(data, currentData, DEFAULT_USER_ID);
        ASSERT_TRUE(ret == ERR_OK);
    }
}

/**
 * @tc.name: TestAllowedInstallBundlesPlugin
 * @tc.desc: Test AllowedInstallBundlesPlugin::OnAdminRemoveDone func.
 * @tc.type: FUNC
 */
HWTEST_F(BundleInstallPluginTest, TestAllowedInstallBundlesPlugin007, TestSize.Level1)
{
    sptr<AppExecFwk::BundleMgrProxy> bundleMgrProxy = iface_cast<AppExecFwk::BundleMgrProxy>(
        EdmSysManager::GetRemoteObjectOfSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID));
    sptr<AppExecFwk::IAppControlMgr> appControlProxy = bundleMgrProxy->GetAppControlProxy();
    BundleInstallPlugin plugin;
    for (int32_t policyType = static_cast<int32_t>(AppExecFwk::AppInstallControlRuleType::DISALLOWED_UNINSTALL);
        policyType <= static_cast<int32_t>(AppExecFwk::AppInstallControlRuleType::DISALLOWED_INSTALL); policyType++) {
        plugin.SetAppInstallControlRuleType(static_cast<AppExecFwk::AppInstallControlRuleType>(policyType));
        // set policy that "testBundle" is allowed to install.
        std::vector<std::string> data = { TEST_BUNDLE };
        std::vector<std::string> currentData;
        ErrCode res = plugin.OnSetPolicy(data, currentData, DEFAULT_USER_ID);
        ASSERT_TRUE(res == ERR_OK);
        ASSERT_TRUE(currentData.size() == 1);
        ASSERT_TRUE(currentData[0] == TEST_BUNDLE);

        // get current policy.
        std::vector<std::string> result;
        res = appControlProxy->GetAppInstallControlRule(static_cast<AppExecFwk::AppInstallControlRuleType>(policyType),
             DEFAULT_USER_ID, result);
        ASSERT_TRUE(res == ERR_OK);
        ASSERT_TRUE(result.size() == 1);
        ASSERT_TRUE(result[0] == TEST_BUNDLE);

        // remove policy.
        std::string adminName = TEST_BUNDLE;
        plugin.OnAdminRemoveDone(adminName, data, DEFAULT_USER_ID);

        // get current policy.
        result.clear();
        res = appControlProxy->GetAppInstallControlRule(static_cast<AppExecFwk::AppInstallControlRuleType>(policyType),
            DEFAULT_USER_ID, result);
        ASSERT_TRUE(res == ERR_OK);
        ASSERT_TRUE(result.size() == 0);
    }
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS