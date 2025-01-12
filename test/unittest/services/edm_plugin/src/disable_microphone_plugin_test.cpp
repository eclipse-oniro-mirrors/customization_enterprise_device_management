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

#define protected public
#include "disable_microphone_plugin.h"
#undef protected

#include <gtest/gtest.h>

#include "parameters.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string PARAM_EDM_MIC_DISABLE = "persist.edm.mic_disable";
class DisableMicrophonePluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void DisableMicrophonePluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DisableMicrophonePluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestDisableMicrophonePluginTestSetTrue
 * @tc.desc: Test DisableMicrophonePluginTest::OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DisableMicrophonePluginTest, TestDisableMicrophonePluginTestSetTrue, TestSize.Level1)
{
    bool isDisallow = true;
    bool currentdata = false;
    bool mergeData = false;
    DisableMicrophonePlugin plugin;
    ErrCode ret = plugin.OnSetPolicy(isDisallow, currentdata, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(system::GetBoolParameter(PARAM_EDM_MIC_DISABLE, false));
}

/**
 * @tc.name: TestDisableMicrophonePluginTestSetFalse
 * @tc.desc: Test DisableMicrophonePluginTest::OnSetPolicy function and audioSystemManager::SetMicrophoneMute.
 * @tc.type: FUNC
 */
HWTEST_F(DisableMicrophonePluginTest, TestDisableMicrophonePluginTestSetFalse, TestSize.Level1)
{
    bool isDisallow = false;
    bool currentdata = false;
    bool mergeData = false;
    DisableMicrophonePlugin plugin;
    ErrCode ret = plugin.OnSetPolicy(isDisallow, currentdata, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_FALSE(system::GetBoolParameter(PARAM_EDM_MIC_DISABLE, true));
}

/**
 * @tc.name: TestDisableMicrophonePluginTestGet
 * @tc.desc: Test DisableMicrophonePluginTest::OnGetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DisableMicrophonePluginTest, TestDisableMicrophonePluginTestGet, TestSize.Level1)
{
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    int32_t userId = 0;
    DisableMicrophonePlugin plugin;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, userId);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    ASSERT_FALSE(reply.ReadBool());
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
