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

#include "security_manager/unlock_policy_plugin_test.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "func_code.h"
#include "unlock_policy.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {

void UnlockPolicyPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void UnlockPolicyPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

HWTEST_F(UnlockPolicyPluginTest, TestOnHandlePolicyInvalidPolicyValue, TestSize.Level1)
{
    UnlockPolicyPlugin plugin;
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::UNLOCK_POLICY);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(99);
    data.WriteInt32(100);
    ErrCode ret = plugin.OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

HWTEST_F(UnlockPolicyPluginTest, TestOnGetPolicy, TestSize.Level1)
{
    UnlockPolicyPlugin plugin;
    uint32_t setCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::UNLOCK_POLICY);
    HandlePolicyData handlePolicyData{"", "", false};

    std::vector<UnlockPolicyType> policyTypes = {
        UnlockPolicyType::DEFAULT,
        UnlockPolicyType::EXTENDED_AUTH_ONLY,
        UnlockPolicyType::EXTENDED_AUTH_REQUIRED
    };

    for (auto policyType : policyTypes) {
        MessageParcel setData;
        MessageParcel setReply;
        setData.WriteInt32(static_cast<int32_t>(policyType));
        setData.WriteInt32(100);
        ErrCode setRet = plugin.OnHandlePolicy(setCode, setData, setReply, handlePolicyData, DEFAULT_USER_ID);
        ASSERT_TRUE(setRet == ERR_OK);

        std::string policyData;
        MessageParcel getData;
        MessageParcel getReply;
        getData.WriteInt32(100);
        ErrCode getRet = plugin.OnGetPolicy(policyData, getData, getReply, DEFAULT_USER_ID);
        ASSERT_TRUE(getRet == ERR_OK);

        int32_t errCode = 0;
        getReply.ReadInt32(errCode);
        ASSERT_EQ(errCode, ERR_OK);

        int32_t actualPolicy = 0;
        getReply.ReadInt32(actualPolicy);
        ASSERT_EQ(actualPolicy, static_cast<int32_t>(policyType));
    }

    MessageParcel resetData;
    MessageParcel resetReply;
    resetData.WriteInt32(static_cast<int32_t>(UnlockPolicyType::DEFAULT));
    resetData.WriteInt32(100);
    plugin.OnHandlePolicy(setCode, resetData, resetReply, handlePolicyData, DEFAULT_USER_ID);
}

HWTEST_F(UnlockPolicyPluginTest, TestPluginInit, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = std::make_shared<UnlockPolicyPlugin>();
    ASSERT_NE(plugin, nullptr);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
