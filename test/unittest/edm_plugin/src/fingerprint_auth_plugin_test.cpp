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
#include "iplugin_manager.h"
#include "parameters.h"
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
}

void FingerprintAuthPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestFingerprintAuthPluginTestSetFalse
 * @tc.desc: Test FingerprintAuthPluginTest::OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(FingerprintAuthPluginTest, TestFingerprintAuthPluginTestSetFalse, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(false);
    std::shared_ptr<IPlugin> plugin = FingerprintAuthPlugin::GetPlugin();
    std::string policyData{"false"};
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::FINGERPRINT_AUTH);
    bool isChanged = false;
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, policyData, isChanged, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(isChanged);
}

/**
 * @tc.name: TestFingerprintAuthPluginTestSetTrue
 * @tc.desc: Test FingerprintAuthPluginTest::OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(FingerprintAuthPluginTest, TestFingerprintAuthPluginTestSetTrue, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(false);
    std::shared_ptr<IPlugin> plugin = FingerprintAuthPlugin::GetPlugin();
    std::string policyData{"true"};
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::FINGERPRINT_AUTH);
    bool isChanged = false;
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, policyData, isChanged, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(isChanged);
}

/**
 * @tc.name: TestFingerprintAuthPluginTestGet
 * @tc.desc: Test FingerprintAuthPluginTest::OnGetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(FingerprintAuthPluginTest, TestFingerprintAuthPluginTestGet, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = FingerprintAuthPlugin::GetPlugin();
    std::string policyData{"false"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(result != system::GetBoolParameter(PERSIST_FINGERPRINT_AUTH_CONTROL, true));
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
