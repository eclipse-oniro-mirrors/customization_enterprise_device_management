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

#include "screen_off_time_plugin.h"

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

class ScreenOffTimePluginTest : public testing::TestWithParam<std::pair<int32_t, int32_t>> {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void ScreenOffTimePluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmServiceEnable();
    Utils::SetEdmInitialEnv();
}

void ScreenOffTimePluginTest::TearDownTestSuite(void)
{
    Utils::SetEdmServiceDisable();
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

INSTANTIATE_TEST_CASE_P(TestOnSetPolicy, ScreenOffTimePluginTest,
    testing::ValuesIn(std::vector<std::pair<int32_t, int32_t>>({
        {-1, ERR_OK},
        {-2, EdmReturnErrCode::PARAM_ERROR},
        {-30000, EdmReturnErrCode::PARAM_ERROR},
        {0, EdmReturnErrCode::PARAM_ERROR},
        {1, EdmReturnErrCode::PARAM_ERROR},
        {14999, EdmReturnErrCode::PARAM_ERROR},
        {15000, ERR_OK},
        {36000000, ERR_OK},
        {30000, ERR_OK},
    })));

/**
 * @tc.name: TestOnSetPolicy
 * @tc.desc: Test OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_P(ScreenOffTimePluginTest, TestOnSetPolicy, TestSize.Level1)
{
    ScreenOffTimePlugin plugin;
    std::pair<int32_t, int32_t> keyValue = GetParam();
    std::cout << "ScreenOffTimePluginTest " << keyValue.first << " " << keyValue.second << std::endl;
    ErrCode code = plugin.OnSetPolicy(keyValue.first);
    EXPECT_TRUE(code == keyValue.second);
}

/**
 * @tc.name: TestOnGetPolicy
 * @tc.desc: Test OnGetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(ScreenOffTimePluginTest, TestOnGetPolicy, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = ScreenOffTimePlugin::GetPlugin();
    std::string policyValue{"TestString"};
    MessageParcel data;
    MessageParcel reply;

    EdmDataAbilityUtils::SetResult("SYSTEM_ABNORMALLY");
    ErrCode code = plugin->OnGetPolicy(policyValue, data, reply, DEFAULT_USER_ID);
    EXPECT_TRUE(code == EdmReturnErrCode::SYSTEM_ABNORMALLY);

    EdmDataAbilityUtils::SetResult("test success");
    code = plugin->OnGetPolicy(policyValue, data, reply, DEFAULT_USER_ID);
    EXPECT_TRUE(code == ERR_OK);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS