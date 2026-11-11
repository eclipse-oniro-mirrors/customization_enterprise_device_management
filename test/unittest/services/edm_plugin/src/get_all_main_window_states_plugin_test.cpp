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

#include "get_all_main_window_states_plugin.h"

#include <gtest/gtest.h>

#include "edm_ipc_interface_code.h"
#include "main_window_states.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {

class GetAllMainWindowStatesPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void GetAllMainWindowStatesPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void GetAllMainWindowStatesPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnGetPolicy
 * @tc.desc: Test GetAllMainWindowStatesPlugin::OnGetPolicy without window service.
 * @tc.type: FUNC
 */
HWTEST_F(GetAllMainWindowStatesPluginTest, TestOnGetPolicy, TestSize.Level1)
{
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    std::vector<MainWindowStates> mainWindowStates;
    GetAllMainWindowStatesPlugin plugin;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::EXECUTE_TIME_OUT);
    int32_t replyCode = 0;
    ASSERT_TRUE(reply.ReadInt32(replyCode));
    if (ret == ERR_OK) {
        ASSERT_EQ(replyCode, ERR_OK);
        ASSERT_TRUE(MainWindowStatesHandle::ReadMainWindowStatesVector(reply, mainWindowStates));
    } else {
        ASSERT_EQ(replyCode, EdmReturnErrCode::EXECUTE_TIME_OUT);
    }
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
