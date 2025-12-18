/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "set_device_name_plugin.h"

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


class SetValueForAccountPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void SetValueForAccountPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmServiceEnable();
    Utils::SetEdmInitialEnv();
}

void SetValueForAccountPluginTest::TearDownTestSuite(void)
{
    Utils::SetEdmServiceDisable();
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnSetPolicy_001
 * @tc.desc: Test OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(SetValueForAccountPluginTest, TestOnSetPolicy_001, TestSize.Level1)
{
    SetDeviceNamePlugin plugin;
    std::string data = "test";
    std::string currentData = "";
    std::string mergeData = "";
    int32_t id = 100;
    ErrCode code = plugin.OnSetPolicy(data, currentData, mergeData, id);
    EXPECT_TRUE(code == ERR_OK);
}

/**
 * @tc.name: TestOnSetPolicy_002
 * @tc.desc: Test OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(SetValueForAccountPluginTest, TestOnSetPolicy_002, TestSize.Level1)
{
    SetDeviceNamePlugin plugin;
    std::string data;
    std::string currentData = "";
    std::string mergeData = "";
    int32_t id = 100;
    ErrCode code = plugin.OnSetPolicy(data, currentData, mergeData, id);
    EXPECT_TRUE(code == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnGetPolicy_001
 * @tc.desc: Test OnGetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(SetValueForAccountPluginTest, TestOnGetPolicy_001, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = SetDeviceNamePlugin::GetPlugin();
    std::string policyValue{"TestString"};
    MessageParcel data;
    MessageParcel reply;

    ErrCode code = plugin->OnGetPolicy(policyValue, data, reply, DEFAULT_USER_ID);

    EdmDataAbilityUtils::SetResult("test success");
    code = plugin->OnGetPolicy(policyValue, data, reply, DEFAULT_USER_ID);
    EXPECT_TRUE(code == ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS