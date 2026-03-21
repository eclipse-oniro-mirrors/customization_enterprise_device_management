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

#include "hidden_settings_menu_plugin_test.h"

#include <gtest/gtest.h>
#include "edm_data_ability_utils_mock.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string TEST_POLICY_DATA = "[\"1\", \"2\", \"3\"]";
const std::string TEST_ADMIN_NAME = "test_admin_name";

void HiddenSettingsMenuPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void HiddenSettingsMenuPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestMergePolicyData
 * @tc.desc: Test HiddenSettingsMenuPlugin::MergePolicyData
 * @tc.type: FUNC
 */
HWTEST_F(HiddenSettingsMenuPluginTest, TestMergePolicyData, TestSize.Level1)
{
    HiddenSettingsMenuPlugin plugin;
    std::string adminName = TEST_ADMIN_NAME;
    std::string policyData = TEST_POLICY_DATA;
    int32_t userId100 = 100;
    auto ret = plugin.GetOthersMergePolicyData(adminName, userId100, policyData);
    ASSERT_EQ(ret, ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
