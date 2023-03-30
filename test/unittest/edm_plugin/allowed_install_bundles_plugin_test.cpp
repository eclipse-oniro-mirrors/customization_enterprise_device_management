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

#include "allowed_install_bundles_plugin_test.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
constexpr int32_t DEFAULT_USER_ID = 100;
/**
 * @tc.name: TestAllowedInstallBundlesPlugin
 * @tc.desc: Test AllowedInstallBundlesPlugin::OnSetPolicy when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedInstallBundlesPluginTest, TestAllowedInstallBundlesPlugin001, TestSize.Level1)
{
    AllowedInstallBundlesPlugin plugin;
    std::vector<std::string> data;
    std::vector<std::string> currentData;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestAllowedInstallBundlesPlugin
 * @tc.desc: Test AllowedInstallBundlesPlugin::OnSetPolicy when data.size() > MAX_SIZE.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedInstallBundlesPluginTest, TestAllowedInstallBundlesPlugin002, TestSize.Level1)
{
    AllowedInstallBundlesPlugin plugin;
    std::vector<std::string> data(201, "testData");
    std::vector<std::string> currentData;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestAllowedInstallBundlesPlugin
 * @tc.desc: Test AllowedInstallBundlesPlugin::OnSetPolicy func.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedInstallBundlesPluginTest, TestAllowedInstallBundlesPlugin003, TestSize.Level1)
{
    AllowedInstallBundlesPlugin plugin;
    std::vector<std::string> data = {"testBundles"};
    std::vector<std::string> currentData;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestAllowedInstallBundlesPlugin
 * @tc.desc: Test AllowedInstallBundlesPlugin::OnGetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedInstallBundlesPluginTest, TestAllowedInstallBundlesPlugin004, TestSize.Level1)
{
    AllowedInstallBundlesPlugin plugin;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestAllowedInstallBundlesPlugin
 * @tc.desc: Test AllowedInstallBundlesPlugin::OnRemovePolicy when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedInstallBundlesPluginTest, TestAllowedInstallBundlesPlugin005, TestSize.Level1)
{
    AllowedInstallBundlesPlugin plugin;
    std::vector<std::string> data;
    std::vector<std::string> currentData;
    ErrCode ret = plugin.OnRemovePolicy(data, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestAllowedInstallBundlesPlugin
 * @tc.desc: Test AllowedInstallBundlesPlugin::OnRemovePolicy func.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedInstallBundlesPluginTest, TestAllowedInstallBundlesPlugin006, TestSize.Level1)
{
    AllowedInstallBundlesPlugin plugin;
    std::vector<std::string> data = {"testBundles"};
    std::vector<std::string> currentData;
    ErrCode ret = plugin.OnRemovePolicy(data, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestAllowedInstallBundlesPlugin
 * @tc.desc: Test AllowedInstallBundlesPlugin::OnAdminRemoveDone func.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedInstallBundlesPluginTest, TestAllowedInstallBundlesPlugin007, TestSize.Level1)
{
    AllowedInstallBundlesPlugin plugin;
    std::string adminName = "testName";
    std::vector<std::string> data = {"testBundles"};
    plugin.OnAdminRemoveDone(adminName, data, DEFAULT_USER_ID);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS