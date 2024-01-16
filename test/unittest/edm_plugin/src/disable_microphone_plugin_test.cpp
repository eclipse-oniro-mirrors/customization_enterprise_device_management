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

#include "disable_microphone_plugin.h"

#include <gtest/gtest.h>

#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "parameters.h"
#include "utils.h"
#include "audio_system_manager.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string PARAM_EDM_MIC_DISABLE = "persist.edm.mic_disable";
const int32_t AUDIO_SET_MICROPHONE_MUTE_SUCCESS = 0;
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
 * @tc.name: TestDisableMicrophonePluginTestSet
 * @tc.desc: Test DisableMicrophonePluginTest::OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DisableMicrophonePluginTest, TestDisableMicrophonePluginTestSet, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(false);
    std::shared_ptr<IPlugin> plugin = DisableMicrophonePlugin::GetPlugin();
    std::string policyData{"false"};
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DISABLE_MICROPHONE);
    bool isChanged = false;
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, policyData, isChanged, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(!system::GetBoolParameter(PARAM_EDM_MIC_DISABLE, false));

    bool isDisallow = true;
    auto audioSystemManager = OHOS::AudioStandard::AudioSystemManager::GetInstance();
    uid_t euid = geteuid();
    seteuid(Utils::ROOT_UID);
    ret = audioSystemManager->SetMicrophoneMute(isDisallow);
    seteuid(euid);
    ASSERT_TRUE(ret == AUDIO_SET_MICROPHONE_MUTE_SUCCESS);

    uint64_t selfTokenId = GetSelfTokenID();
    SetSelfTokenID(0);
    data.WriteBool(true);
    isChanged = false;
    ret = plugin->OnHandlePolicy(funcCode, data, reply, policyData, isChanged, DEFAULT_USER_ID);
    SetSelfTokenID(selfTokenId);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
    ASSERT_TRUE(!system::GetBoolParameter(PARAM_EDM_MIC_DISABLE, false));

    data.WriteBool(true);
    isChanged = false;
    ret = plugin->OnHandlePolicy(funcCode, data, reply, policyData, isChanged, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(system::GetBoolParameter(PARAM_EDM_MIC_DISABLE, false));

    isDisallow = false;
    euid = geteuid();
    seteuid(Utils::ROOT_UID);
    ret = audioSystemManager->SetMicrophoneMute(isDisallow);
    seteuid(euid);
    ASSERT_TRUE(ret != AUDIO_SET_MICROPHONE_MUTE_SUCCESS);

    data.WriteBool(false);
    isChanged = false;
    ret = plugin->OnHandlePolicy(funcCode, data, reply, policyData, isChanged, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(!system::GetBoolParameter(PARAM_EDM_MIC_DISABLE, false));

    isDisallow = true;
    seteuid(Utils::ROOT_UID);
    ret = audioSystemManager->SetMicrophoneMute(isDisallow);
    seteuid(euid);
    ASSERT_TRUE(ret == AUDIO_SET_MICROPHONE_MUTE_SUCCESS);

    isDisallow = false;
    seteuid(Utils::ROOT_UID);
    ret = audioSystemManager->SetMicrophoneMute(isDisallow);
    seteuid(euid);
    ASSERT_TRUE(ret == AUDIO_SET_MICROPHONE_MUTE_SUCCESS);
}

/**
 * @tc.name: TestDisableMicrophonePluginTestGet
 * @tc.desc: Test DisableMicrophonePluginTest::OnGetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DisableMicrophonePluginTest, TestDisableMicrophonePluginTestGet, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = DisableMicrophonePlugin::GetPlugin();
    std::string policyData{"false"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(result == system::GetBoolParameter(PARAM_EDM_MIC_DISABLE, false));
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
