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

#include <gtest/gtest.h>

#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "func_code.h"
#include "local_hota_domain_plugin.h"
#include "message_parcel.h"
#include "edm_constants.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class LocalHotaDomainPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void LocalHotaDomainPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void LocalHotaDomainPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
}

/**
 * @tc.name: TestOnHandlePolicy
 * @tc.desc: Test LocalHotaDomainPlugin::OnHandlePolicy returns unsupported.
 * @tc.type: FUNC
 */
HWTEST_F(LocalHotaDomainPluginTest, TestOnHandlePolicy, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(true);
    LocalHotaDomainPlugin plugin;
    HandlePolicyData handlePolicyData{"false", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::LOCAL_HOTA_DOMAIN);
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::INTERFACE_UNSUPPORTED);
}

/**
 * @tc.name: TestOnGetPolicy
 * @tc.desc: Test LocalHotaDomainPlugin::OnGetPolicy replies ERR_OK with an empty domain.
 * @tc.type: FUNC
 */
HWTEST_F(LocalHotaDomainPluginTest, TestOnGetPolicy, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    std::string policyData;
    LocalHotaDomainPlugin plugin;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    reply.RewindRead(0);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_EQ(reply.ReadString(), std::string(""));
}

/**
 * @tc.name: TestPluginAttributes
 * @tc.desc: Test LocalHotaDomainPlugin policy code and policy name.
 * @tc.type: FUNC
 */
HWTEST_F(LocalHotaDomainPluginTest, TestPluginAttributes, TestSize.Level1)
{
    LocalHotaDomainPlugin plugin;
    EXPECT_EQ(plugin.GetCode(), EdmInterfaceCode::LOCAL_HOTA_DOMAIN);
    EXPECT_EQ(plugin.GetPolicyName(), PolicyName::POLICY_LOCAL_HOTA_DOMAIN);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
