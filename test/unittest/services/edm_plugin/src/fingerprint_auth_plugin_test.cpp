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

#include "fingerprint_auth_plugin.h"

#include <gtest/gtest.h>

#include "edm_ipc_interface_code.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string PERSIST_FINGERPRINT_AUTH_CONTROL = "persist.useriam.enable.fingerprintauth";
class FingerprintAuthPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void FingerprintAuthPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
    setegid(Utils::USERIAM_UID);
    ASSERT_TRUE(getegid() == Utils::USERIAM_UID);
}

void FingerprintAuthPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    setegid(Utils::EDM_UID);
    ASSERT_TRUE(getegid() == Utils::EDM_UID);
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnHandlePolicyFingerprintAuthType
 * @tc.desc: Test FingerprintAuthPluginTest::OnHandlePolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(FingerprintAuthPluginTest, TestOnHandlePolicyFingerprintAuthType, TestSize.Level1)
{
    MessageParcel data;
    data.WriteString(EdmConstants::FINGERPRINT_AUTH_TYPE);
    data.WriteBool(false);
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.policyData = "true";
    FingerprintAuthPlugin plugin;
    ErrCode ret = plugin.OnHandlePolicy(0, data, reply, policyData, 100);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(policyData.policyData.empty());
}

/**
 * @tc.name: TestOnHandlePolicyDisallowForAccountType
 * @tc.desc: Test FingerprintAuthPluginTest::OnHandlePolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(FingerprintAuthPluginTest, TestOnHandlePolicyDisallowForAccountType, TestSize.Level1)
{
    MessageParcel data;
    data.WriteString(EdmConstants::DISALLOW_FOR_ACCOUNT_TYPE);
    data.WriteBool(false);
    data.WriteInt32(100);
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.policyData = "[100]";
    FingerprintAuthPlugin plugin;
    ErrCode ret = plugin.OnHandlePolicy(0, data, reply, policyData, 100);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(policyData.policyData.empty());
}

/**
 * @tc.name: TestHandleFingerprintAuthPolicy
 * @tc.desc: Test FingerprintAuthPluginTest::HandleFingerprintAuthPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(FingerprintAuthPluginTest, TestHandleFingerprintAuthPolicy, TestSize.Level1)
{
    FingerprintAuthPlugin plugin;
    FingerprintPolicy policy;
    policy.accountIds.insert(100);
    ErrCode ret = plugin.HandleFingerprintAuthPolicy(true, policy);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(policy.accountIds.empty());
    ASSERT_TRUE(policy.globalDisallow);

    policy.accountIds.insert(100);
    policy.globalDisallow = false;
    ret = plugin.HandleFingerprintAuthPolicy(false, policy);
    ASSERT_TRUE(ret == EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);

    policy.accountIds.clear();
    ret = plugin.HandleFingerprintAuthPolicy(false, policy);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(policy.accountIds.empty());
    ASSERT_FALSE(policy.globalDisallow);
}

/**
 * @tc.name: TestHandleFingerprintForAccountPolicy
 * @tc.desc: Test FingerprintAuthPluginTest::HandleFingerprintForAccountPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(FingerprintAuthPluginTest, TestHandleFingerprintForAccountPolicy, TestSize.Level1)
{
    FingerprintAuthPlugin plugin;
    FingerprintPolicy policy;
    policy.globalDisallow = true;
    ErrCode ret = plugin.HandleFingerprintForAccountPolicy(true, 100, policy);
    ASSERT_TRUE(ret == EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);

    policy.globalDisallow = false;
    ret = plugin.HandleFingerprintForAccountPolicy(true, 100, policy);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(policy.accountIds.find(100) != policy.accountIds.end());
    ASSERT_FALSE(policy.globalDisallow);

    ret = plugin.HandleFingerprintForAccountPolicy(false, 100, policy);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(policy.accountIds.empty());
    ASSERT_FALSE(policy.globalDisallow);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS