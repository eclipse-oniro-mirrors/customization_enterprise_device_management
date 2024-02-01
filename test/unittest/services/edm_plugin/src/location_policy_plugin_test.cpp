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

#include "location_policy_plugin.h"

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

class LocationPolicyPluginTest : public testing::TestWithParam<std::pair<int32_t, int32_t>> {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void LocationPolicyPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmServiceEnable();
    Utils::SetEdmInitialEnv();
}

void LocationPolicyPluginTest::TearDownTestSuite(void)
{
    LocationPolicyPlugin plugin;
    int32_t defaultPolicy = static_cast<int32_t>(LocationPolicy::DEFAULT_LOCATION_SERVICE);
    ErrCode code = plugin.OnSetPolicy(defaultPolicy);
    EXPECT_TRUE(code == ERR_OK);
    Utils::SetEdmServiceDisable();
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

INSTANTIATE_TEST_CASE_P(TestOnSetPolicy, LocationPolicyPluginTest,
    testing::ValuesIn(std::vector<std::pair<int32_t, int32_t>>({
        {-1, EdmReturnErrCode::PARAM_ERROR},
        {0, ERR_OK},
        {1, ERR_OK},
        {2, ERR_OK},
    })));

/**
 * @tc.name: TestOnSetPolicy
 * @tc.desc: Test OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_P(LocationPolicyPluginTest, TestOnSetPolicy, TestSize.Level1)
{
    LocationPolicyPlugin plugin;
    std::pair<int32_t, int32_t> keyValue = GetParam();
    std::cout << "LocationPolicyPluginTest " << keyValue.first << " " << keyValue.second << std::endl;
    ErrCode code = plugin.OnSetPolicy(keyValue.first);
    EXPECT_TRUE(code == keyValue.second);
}

/**
 * @tc.name: TestOnGetPolicy
 * @tc.desc: Test OnGetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(LocationPolicyPluginTest, TestOnGetPolicy, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = LocationPolicyPlugin::GetPlugin();
    std::string policyValue{"TestString"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode code = plugin->OnGetPolicy(policyValue, data, reply, DEFAULT_USER_ID);
    EXPECT_TRUE(code == ERR_OK);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS