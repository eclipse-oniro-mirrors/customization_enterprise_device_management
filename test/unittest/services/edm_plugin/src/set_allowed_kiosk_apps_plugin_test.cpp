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

#include <gtest/gtest.h>
#include "set_allowed_kiosk_apps_plugin.h"
#include "system_ability_definition.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "plugin_singleton.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string TEST_BUNDLE_NAME = "testBundleName";
class SetAllowedKioskAppsPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void SetAllowedKioskAppsPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void SetAllowedKioskAppsPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: SetAllowedKioskAppsPluginDataEmpty
 * @tc.desc: Test SetAllowedKioskAppsPlugin::OnSetPolicy when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(SetAllowedKioskAppsPluginTest, SetAllowedKioskAppsPluginDataEmpty, TestSize.Level1)
{
    SetAllowedKioskAppsPlugin plugin;
    std::vector<std::string> data;
    std::vector<std::string> currentData;
    std::vector<std::string> mergeData;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: SetAllowedKioskAppsPluginDataOverLimit
 * @tc.desc: Test SetAllowedKioskAppsPlugin::OnSetPolicy when data is over limit.
 * @tc.type: FUNC
 */
HWTEST_F(SetAllowedKioskAppsPluginTest, SetAllowedKioskAppsPluginDataOverLimit, TestSize.Level1)
{
    SetAllowedKioskAppsPlugin plugin;
    std::vector<std::string> data(EdmConstants::POLICIES_MAX_SIZE + 1, TEST_BUNDLE_NAME);
    std::vector<std::string> currentData;
    std::vector<std::string> mergeData;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: SetAllowedKioskAppsPluginSuc
 * @tc.desc: Test SetAllowedKioskAppsPlugin::OnGetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(SetAllowedKioskAppsPluginTest, SetAllowedKioskAppsPluginSuc, TestSize.Level1)
{
    SetAllowedKioskAppsPlugin plugin;
    std::vector<std::string> data;
    data.push_back(TEST_BUNDLE_NAME);
    std::vector<std::string> currentData;
    std::vector<std::string> mergeData;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    plugin.OnOtherServiceStart(ABILITY_MGR_SERVICE_ID);
    plugin.OnOtherServiceStart(WINDOW_MANAGER_SERVICE_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: SetAllowedKioskAppsPluginGetTest
 * @tc.desc: Test SetAllowedKioskAppsPlugin::OnGetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(SetAllowedKioskAppsPluginTest, SetAllowedKioskAppsPluginGetTest, TestSize.Level1)
{
    SetAllowedKioskAppsPlugin plugin;
    std::string policyData = "[\"com.example.edmtest\"]";
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS