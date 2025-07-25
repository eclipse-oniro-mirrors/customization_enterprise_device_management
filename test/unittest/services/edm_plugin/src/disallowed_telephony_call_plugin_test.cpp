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

#include <gtest/gtest.h>
#include <vector>

#include "disallowed_telephony_call_plugin.h"
#include "edm_ipc_interface_code.h"
#include "utils.h"
#include "parameters.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string PARAM_DISALLOWED_TELEPHONY_CALL = "persist.edm.telephony_call_disable";

class DisallowedTelephonyCallPluginTest
    : public testing::TestWithParam<std::pair<std::shared_ptr<IPlugin>, EdmInterfaceCode>> {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void DisallowedTelephonyCallPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DisallowedTelephonyCallPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

INSTANTIATE_TEST_SUITE_P(TestOnSetPolicy, DisallowedTelephonyCallPluginTest,
    testing::ValuesIn(std::vector<std::pair<std::shared_ptr<IPlugin>, EdmInterfaceCode>>({
        {DisallowedTelephonyCallPlugin::GetPlugin(), EdmInterfaceCode::DISALLOWED_TELEPHONY_CALL},
    })));

/**
 * @tc.name: TestOnSetPolicy
 * @tc.desc: Test DisallowedTelephonyCallPluginTest::OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_P(DisallowedTelephonyCallPluginTest, TestOnSetPolicy, TestSize.Level1)
{
    auto param = GetParam();
    bool currentval = system::GetBoolParameter(PARAM_DISALLOWED_TELEPHONY_CALL, false);
    std::string setData = currentval? "true" : "false";
    std::string afterData = currentval? "false" : "true";
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(!currentval);
    std::shared_ptr<IPlugin> plugin = param.first;
    HandlePolicyData handlePolicyData{"false", "", false};
    if (currentval) {
        handlePolicyData.policyData = "true";
    }
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, param.second);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(handlePolicyData.policyData == afterData);
    ASSERT_TRUE(handlePolicyData.isChanged);
    system::SetParameter(PARAM_DISALLOWED_TELEPHONY_CALL, setData);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
