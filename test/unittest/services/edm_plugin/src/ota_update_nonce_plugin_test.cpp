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
 
#include "ota_update_nonce_plugin.h"
 
#include <gtest/gtest.h>
 
#include "edm_ipc_interface_code.h"
#include "message_parcel.h"
#include "utils.h"
 
using namespace testing::ext;
using namespace testing;
 
namespace OHOS {
namespace EDM {
namespace TEST {
class OtaUpdateNoncePluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);
    static void TearDownTestSuite(void);
};
 
void OtaUpdateNoncePluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}
 
void OtaUpdateNoncePluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}
 
/**
 * @tc.name: TestOnHandlePolicySet
 * @tc.desc: Test OtaUpdateNoncePlugin::OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(OtaUpdateNoncePluginTest, TestOnHandlePolicySet, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(true);
    auto plugin = OtaUpdateNoncePlugin::GetPlugin();
    HandlePolicyData handlePolicyData{"false", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::OTA_UPDATE_NONCE);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::INTERFACE_UNSUPPORTED);
}
 
/**
 * @tc.name: TestOnGetPolicy
 * @tc.desc: Test OtaUpdateNoncePlugin::OnGetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(OtaUpdateNoncePluginTest, TestOnGetPolicy, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    std::string policyData = "";
    OtaUpdateNoncePlugin plugin;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_EQ(reply.ReadBool(), false);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS