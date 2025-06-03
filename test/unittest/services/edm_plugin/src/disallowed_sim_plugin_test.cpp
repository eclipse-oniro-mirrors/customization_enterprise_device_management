/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <vector>

#include "disallowed_sim_plugin.h"
#include "edm_ipc_interface_code.h"
#include "inactive_user_freeze_plugin.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class DisallowedSimPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void DisallowedSimPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DisallowedSimPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestDisallowedSim0Success
 * @tc.desc: Test DisallowedSimPlugin::OnSetPolicy function sucess.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedSimPluginTest, TestDisallowedSim0Success, TestSize.Level1)
{
    DisallowedSimPlugin plugin;
    int32_t  policies = 0;
    int32_t currentData = 0;
    int32_t mergeData = 0;
    ErrCode ret = plugin.OnSetPolicy(policies, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDisallowedSim1Success
 * @tc.desc: Test DisallowedSimPlugin::OnSetPolicy function sucess.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedSimPluginTest, TestDisallowedSim1Success, TestSize.Level1)
{
    DisallowedSimPlugin plugin;
    int32_t  policies = 1;
    int32_t currentData = 0;
    int32_t mergeData = 0;
    ErrCode ret = plugin.OnSetPolicy(policies, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestEnableSim0Success
 * @tc.desc: Test DisallowedSimPlugin::OnRemovePolicy function sucess.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedSimPluginTest, TestEnableSim0Success, TestSize.Level1)
{
    DisallowedSimPlugin plugin;
    int32_t  policies = 0;
    int32_t currentData = 0;
    int32_t mergeData = 0;
    ErrCode ret = plugin.OnRemovePolicy(policies, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestEnableSim1Success
 * @tc.desc: Test DisallowedSimPlugin::OnRemovePolicy function sucess.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedSimPluginTest, TestEnableSim1Success, TestSize.Level1)
{
    DisallowedSimPlugin plugin;
    int32_t  policies = 1;
    int32_t currentData = 0;
    int32_t mergeData = 0;
    ErrCode ret = plugin.OnRemovePolicy(policies, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestIsDisallowedSim0Success
 * @tc.desc: Test DisallowedSimPlugin::OnGetPolicy function sucess.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedSimPluginTest, TestIsDisallowedSim0Success, TestSize.Level1)
{
    MessageParcel data;
    data.WriteInt32(0);
    MessageParcel reply;
    std::shared_ptr<IPlugin> plugin = DisallowedSimPlugin::GetPlugin();
    std::string policyData{""};
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    ASSERT_FALSE(reply.ReadBool());
}

/**
 * @tc.name: TestIsDisallowedSim1Success
 * @tc.desc: Test DisallowedSimPlugin::OnGetPolicy function sucess.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedSimPluginTest, TestIsDisallowedSim1Success, TestSize.Level1)
{
    MessageParcel data;
    data.WriteInt32(1);
    MessageParcel reply;
    std::shared_ptr<IPlugin> plugin = DisallowedSimPlugin::GetPlugin();
    std::string policyData{""};
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    ASSERT_FALSE(reply.ReadBool());
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS