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

#include "manage_normal_os_account_plugin.h"

#include <gtest/gtest.h>
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "func_code_utils.h"
#include "utils.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {

static int32_t accountId = 0;

class ManageNormalOsAccountPluginTest : public testing::Test {
public:
    static void SetUpTestSuite(void);
    static void TearDownTestSuite(void);
};

void ManageNormalOsAccountPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void ManageNormalOsAccountPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is original ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnHandlePolicyCreateAccount
 * @tc.desc: Test ManageNormalOsAccountPlugin::OnHandlePolicy function create normalOsAccount success.
 * @tc.type: FUNC
 */
HWTEST_F(ManageNormalOsAccountPluginTest, TestOnHandlePolicyCreateAccount, TestSize.Level1)
{
    std::shared_ptr<ManageNormalOsAccountPlugin> plugin = std::make_shared<ManageNormalOsAccountPlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::MANAGE_NORMAL_OS_ACCOUNT);
    HandlePolicyData handlePolicyData{"", "", true};
    MessageParcel data;
    std::string name = "testName1";
    data.WriteString(EdmConstants::CREATE_NORMAL_OS_ACCOUNT);
    data.WriteString(name);
    MessageParcel reply;
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    reply.ReadInt32();
    OHOS::AccountSA::OsAccountInfo *result = OHOS::AccountSA::OsAccountInfo::Unmarshalling(reply);
    accountId = result->GetLocalId();
}

/**
 * @tc.name: TestOnHandlePolicyActivateAccount
 * @tc.desc: Test ManageNormalOsAccountPlugin::OnHandlePolicy function activate normalOsAccount success.
 * @tc.type: FUNC
 */
HWTEST_F(ManageNormalOsAccountPluginTest, TestOnHandlePolicyActivateAccount, TestSize.Level1)
{
    std::shared_ptr<ManageNormalOsAccountPlugin> plugin = std::make_shared<ManageNormalOsAccountPlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::MANAGE_NORMAL_OS_ACCOUNT);
    HandlePolicyData handlePolicyData{"", "", true};
    MessageParcel data;
    data.WriteString(EdmConstants::ACTIVATE_OS_ACCOUNT);
    data.WriteInt32(100);
    MessageParcel reply;
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestOnHandlePolicyRemoveAccount
 * @tc.desc: Test ManageNormalOsAccountPlugin::OnHandlePolicy function remove normalOsAccount success.
 * @tc.type: FUNC
 */
HWTEST_F(ManageNormalOsAccountPluginTest, TestOnHandlePolicyRemoveAccount, TestSize.Level1)
{
    std::shared_ptr<ManageNormalOsAccountPlugin> plugin = std::make_shared<ManageNormalOsAccountPlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE,
        EdmInterfaceCode::MANAGE_NORMAL_OS_ACCOUNT);
    HandlePolicyData handlePolicyData{"", "", true};
    MessageParcel data;
    data.WriteInt32(accountId);
    MessageParcel reply;
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS