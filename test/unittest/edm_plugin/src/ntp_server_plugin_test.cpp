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

#include "ntp_server_plugin.h"

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

class NTPServerPluginTest : public testing::TestWithParam<std::pair<std::string, int32_t>> {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void NTPServerPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmServiceEnable();
    Utils::SetEdmInitialEnv();
}

void NTPServerPluginTest::TearDownTestSuite(void)
{
    Utils::SetEdmServiceDisable();
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnGetPolicy
 * @tc.desc: Test OnGetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(NTPServerPluginTest, TestOnGetPolicy, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = NTPServerPlugin::GetPlugin();
    std::string policyValue{"TestString"};
    MessageParcel data;
    MessageParcel reply;

    plugin->OnGetPolicy(policyValue, data, reply, DEFAULT_USER_ID);
    EXPECT_TRUE(reply.ReadInt32() == ERR_OK);
    EXPECT_TRUE(reply.ReadString() == "");
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS