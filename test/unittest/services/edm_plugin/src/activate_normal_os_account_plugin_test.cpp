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

#include "activate_normal_os_account_plugin.h"

#include <gtest/gtest.h>
#include "add_os_account_plugin.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "func_code_utils.h"
#include "manage_normal_os_account_plugin.h"
#include "utils.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {

class ActivateNormalOsAccountPluginTest : public testing::Test {
public:
    static void SetUpTestSuite(void);
    static void TearDownTestSuite(void);
};

void ActivateNormalOsAccountPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void ActivateNormalOsAccountPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is original ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnSetPolicyActivateAccount
 * @tc.desc: Test ActivateNormalOsAccountPlugin::OnSetPolicy function activate normalOsAccount success.
 * @tc.type: FUNC
 */
HWTEST_F(ActivateNormalOsAccountPluginTest, TestOnSetPolicyActivateAccount, TestSize.Level1)
{
    ActivateNormalOsAccountPlugin plugin;
    int32_t id = 100;
    ErrCode ret = plugin.OnSetPolicy(id);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestOnSetPolicyActivateAccountFail
 * @tc.desc: Test ActivateNormalOsAccountPlugin::OnSetPolicy function activate normalOsAccount fail.
 * @tc.type: FUNC
 */
HWTEST_F(ActivateNormalOsAccountPluginTest, TestOnSetPolicyActivateAccountFail, TestSize.Level1)
{
    ActivateNormalOsAccountPlugin plugin;
    int32_t id = -1;
    ErrCode ret = plugin.OnSetPolicy(id);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);

    AddOsAccountPlugin pluginAddOs;
    MessageParcel reply;
    std::map<std::string, std::string> policies;
    policies.insert(std::make_pair("ut_test_user_name", "2"));
    ret = pluginAddOs.OnSetPolicy(policies, reply);
    EXPECT_EQ(ret, ERR_OK);
    reply.ReadInt32();
    OHOS::AccountSA::OsAccountInfo *result = OHOS::AccountSA::OsAccountInfo::Unmarshalling(reply);
    id = result->GetLocalId();
    ret = plugin.OnSetPolicy(id);
    EXPECT_EQ(ret, EdmReturnErrCode::ACCOUNT_RESTRICTED);

    std::shared_ptr<ManageNormalOsAccountPlugin> pluginRemove = std::make_shared<ManageNormalOsAccountPlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE,
        EdmInterfaceCode::MANAGE_NORMAL_OS_ACCOUNT);
    HandlePolicyData handlePolicyData{"", "", true};
    MessageParcel data;
    data.WriteInt32(id);
    MessageParcel replyRemove;
    ret = pluginRemove->OnHandlePolicy(code, data, replyRemove, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS