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

#include "add_os_account_plugin.h"
#include "edm_ipc_interface_code.h"
#include "os_account_info.h"
#include "os_account_manager.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
const int32_t ACCOUNT_NAME_LENGTH_MAX = 1024;

class AddOsAccountAccountPluginTest : public testing::Test {
public:
    static std::vector<int> accountIdArray;

protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

std::vector<int> AddOsAccountAccountPluginTest::accountIdArray;

void AddOsAccountAccountPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void AddOsAccountAccountPluginTest::TearDownTestSuite(void)
{
    std::for_each(accountIdArray.begin(), accountIdArray.end(), [&](const int accountId) {
        AccountSA::OsAccountManager::RemoveOsAccount(accountId);
    });
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is original ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnSetPolicyEmpty
 * @tc.desc: Test AddOsAccountPlugin::OnSetPolicy function when policy is empty.
 * @tc.type: FUNC
 */
HWTEST_F(AddOsAccountAccountPluginTest, TestOnSetPolicyEmpty, TestSize.Level1)
{
    AddOsAccountPlugin plugin;
    MessageParcel reply;
    std::map<std::string, std::string> policies;
    ErrCode ret = plugin.OnSetPolicy(policies, reply);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnSetPolicyNameUnavailable
 * @tc.desc: Test AddOsAccountPlugin::OnSetPolicy when account name value is empty.
 * @tc.type: FUNC
 */
HWTEST_F(AddOsAccountAccountPluginTest, TestOnSetPolicyNameUnavailable, TestSize.Level1)
{
    AddOsAccountPlugin plugin;
    MessageParcel reply;
    std::map<std::string, std::string> policies;
    std::string name = "abc";
    for (int i = 0; i < ACCOUNT_NAME_LENGTH_MAX; i++) {
        name.append("z");
    }
    policies.insert(std::make_pair(name, "1"));
    ErrCode ret = plugin.OnSetPolicy(policies, reply);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADD_OS_ACCOUNT_FAILED);
}

/**
 * @tc.name: TestOnSetPolicyTypeEmpty
 * @tc.desc: Test AddOsAccountPlugin::OnSetPolicy when account type value is empty.
 * @tc.type: FUNC
 */
HWTEST_F(AddOsAccountAccountPluginTest, TestOnSetPolicyTypeEmpty, TestSize.Level1)
{
    AddOsAccountPlugin plugin;
    MessageParcel reply;
    std::map<std::string, std::string> policies;
    policies.insert(std::make_pair("ut_test_user_name", ""));
    ErrCode ret = plugin.OnSetPolicy(policies, reply);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestOnSetPolicyTypeUnavailable
 * @tc.desc: Test AddOsAccountPlugin::OnSetPolicy when account type value is empty.
 * @tc.type: FUNC
 */
HWTEST_F(AddOsAccountAccountPluginTest, TestOnSetPolicyTypeUnavailable, TestSize.Level1)
{
    AddOsAccountPlugin plugin;
    MessageParcel reply;
    std::map<std::string, std::string> policies;
    policies.insert(std::make_pair("ut_test_user_name",
        std::to_string(static_cast<int>(AccountSA::OsAccountType::END))));
    ErrCode ret = plugin.OnSetPolicy(policies, reply);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnSetPolicyAddAdmin
 * @tc.desc: Test AddOsAccountPlugin::OnSetPolicy to add an admin account.
 * @tc.type: FUNC
 */
HWTEST_F(AddOsAccountAccountPluginTest, TestOnSetPolicyAddAdmin, TestSize.Level1)
{
    AddOsAccountPlugin plugin;
    MessageParcel reply;
    std::map<std::string, std::string> policies;
    policies.insert(std::make_pair("ut_test_user_name1", "0"));
    ErrCode ret = plugin.OnSetPolicy(policies, reply);
    ASSERT_TRUE(ret == ERR_OK);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    AccountSA::OsAccountInfo *info = AccountSA::OsAccountInfo::Unmarshalling(reply);
    AccountSA::OsAccountInfo accountInfo = *info;
    accountIdArray.push_back(accountInfo.GetLocalId());
    ASSERT_EQ(accountInfo.GetLocalName(), "ut_test_user_name1");
    ASSERT_TRUE(accountInfo.GetType() == AccountSA::OsAccountType::ADMIN);
}

/**
 * @tc.name: TestOnSetPolicyAddNormal
 * @tc.desc: Test AddOsAccountPlugin::OnSetPolicy to add an normal account.
 * @tc.type: FUNC
 */
HWTEST_F(AddOsAccountAccountPluginTest, TestOnSetPolicyAddNormal, TestSize.Level1)
{
    AddOsAccountPlugin plugin;
    MessageParcel reply;
    std::map<std::string, std::string> policies;
    policies.insert(std::make_pair("ut_test_user_name2", "1"));
    ErrCode ret = plugin.OnSetPolicy(policies, reply);
    ASSERT_TRUE(ret == ERR_OK);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    AccountSA::OsAccountInfo *info = AccountSA::OsAccountInfo::Unmarshalling(reply);
    AccountSA::OsAccountInfo accountInfo = *info;
    accountIdArray.push_back(accountInfo.GetLocalId());
    ASSERT_EQ(accountInfo.GetLocalName(), "ut_test_user_name2");
    ASSERT_TRUE(accountInfo.GetType() == AccountSA::OsAccountType::NORMAL);
}

/**
 * @tc.name: TestOnSetPolicyAddGuest
 * @tc.desc: Test AddOsAccountPlugin::OnSetPolicy to add an guest account.
 * @tc.type: FUNC
 */
HWTEST_F(AddOsAccountAccountPluginTest, TestOnSetPolicyAddGuest, TestSize.Level1)
{
    AddOsAccountPlugin plugin;
    MessageParcel reply;
    std::map<std::string, std::string> policies;
    policies.insert(std::make_pair("ut_test_user_name3", "2"));
    ErrCode ret = plugin.OnSetPolicy(policies, reply);
    ASSERT_TRUE(ret == ERR_OK);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    AccountSA::OsAccountInfo *info = AccountSA::OsAccountInfo::Unmarshalling(reply);
    AccountSA::OsAccountInfo accountInfo = *info;
    accountIdArray.push_back(accountInfo.GetLocalId());
    ASSERT_EQ(accountInfo.GetLocalName(), "ut_test_user_name3");
    ASSERT_TRUE(accountInfo.GetType() == AccountSA::OsAccountType::GUEST);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS