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

#include "disallowed_mms_plugin.h"
#include "edm_ipc_interface_code.h"
#include "inactive_user_freeze_plugin.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class DisallowedMMSPluginTest
    : public testing::TestWithParam<std::pair<std::shared_ptr<IPlugin>, EdmInterfaceCode>> {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void DisallowedMMSPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DisallowedMMSPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

INSTANTIATE_TEST_SUITE_P(TestOnSetPolicy, DisallowedMMSPluginTest,
    testing::ValuesIn(std::vector<std::pair<std::shared_ptr<IPlugin>, EdmInterfaceCode>>({
        {DisallowedMMSPlugin::GetPlugin(), EdmInterfaceCode::DISALLOWED_MMS}
    })));

/**
 * @tc.name: TestOnSetPolicy
 * @tc.desc: Test DisallowedTetheringPluginTest::OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_P(DisallowedMMSPluginTest, TestOnSetPolicy, TestSize.Level1)
{
    auto param = GetParam();
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(true);
    std::shared_ptr<IPlugin> plugin = param.first;
    HandlePolicyData handlePolicyData{"false", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, param.second);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(handlePolicyData.policyData == "true");
    ASSERT_TRUE(handlePolicyData.isChanged);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
