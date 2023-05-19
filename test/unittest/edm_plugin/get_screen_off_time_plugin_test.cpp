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
#include "edm_data_ability_utils_mock.h"
#include "get_screen_off_time_plugin.h"
#include "iplugin_manager.h"
#include "policy_info.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class GetScreenOffTimePluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void GetScreenOffTimePluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void GetScreenOffTimePluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnGetPolicy
 * @tc.desc: Test OnGetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(GetScreenOffTimePluginTest, TestOnGetPolicy, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = GetScreenOffTimePlugin::GetPlugin();
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