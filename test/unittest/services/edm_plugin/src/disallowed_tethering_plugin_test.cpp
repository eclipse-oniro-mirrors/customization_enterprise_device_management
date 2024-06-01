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

#include "disallowed_tethering_plugin.h"
#include "edm_ipc_interface_code.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class DisallowedTetheringPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void DisallowedTetheringPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DisallowedTetheringPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestDisallowedTetheringPluginTestSet
 * @tc.desc: Test DisallowedTetheringPluginTest::OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedTetheringPluginTest, TestDisallowedTetheringPluginTestSet, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(true);
    std::shared_ptr<IPlugin> plugin = DisallowedTetheringPlugin::GetPlugin();
    HandlePolicyData handlePolicyData{"false", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DISALLOWED_TETHERING);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(handlePolicyData.policyData == "true");
    ASSERT_TRUE(handlePolicyData.isChanged);

    std::string policyData{"false"};
    MessageParcel data1;
    MessageParcel reply1;
    ret = plugin->OnGetPolicy(policyData, data1, reply1, 100);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply1.ReadInt32() == ERR_OK);
    ASSERT_TRUE(reply1.ReadBool());
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS