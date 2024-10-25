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

#define private public
#include "add_os_account_plugin.h"
#undef private

#include "edm_ipc_interface_code.h"
#include "edm_os_account_manager_impl_mock.h"
#include "external_manager_factory_mock.h"
#include "os_account_info.h"
#include "os_account_manager.h"
#include "utils.h"
#include <gtest/gtest.h>

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
const int32_t ACCOUNT_NAME_LENGTH_MAX = 1024;

class AddOsAccountAccountPluginTest : public testing::Test {
public:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);

protected:
    static std::shared_ptr<ExternalManagerFactoryMock> factoryMock_;

    static std::shared_ptr<EdmOsAccountManagerImplMock> osAccountMgrMock_;
};

std::shared_ptr<ExternalManagerFactoryMock> AddOsAccountAccountPluginTest::factoryMock_ = nullptr;
std::shared_ptr<EdmOsAccountManagerImplMock> AddOsAccountAccountPluginTest::osAccountMgrMock_ = nullptr;

void AddOsAccountAccountPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
    osAccountMgrMock_ = std::make_shared<EdmOsAccountManagerImplMock>();
    factoryMock_ = std::make_shared<ExternalManagerFactoryMock>();
}

void AddOsAccountAccountPluginTest::TearDownTestSuite(void)
{
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
    auto factory = std::make_shared<ExternalManagerFactoryMock>();
    auto osAccountMgrMock = std::make_shared<EdmOsAccountManagerImplMock>();
    plugin.externalManagerFactory_ = factory;
    MessageParcel reply;
    std::map<std::string, std::string> policies;
    policies.insert(std::make_pair("ut_test_user_name1", "0"));
    EXPECT_CALL(*factory, CreateOsAccountManager).Times(1).WillOnce(Return(osAccountMgrMock));
    EXPECT_CALL(*osAccountMgrMock, CreateOsAccount).Times(1).WillOnce(Return(ERR_OK));
    ErrCode ret = plugin.OnSetPolicy(policies, reply);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnSetPolicyAddNormal
 * @tc.desc: Test AddOsAccountPlugin::OnSetPolicy to add an normal account.
 * @tc.type: FUNC
 */
HWTEST_F(AddOsAccountAccountPluginTest, TestOnSetPolicyAddNormal, TestSize.Level1)
{
    AddOsAccountPlugin plugin;
    auto factory = std::make_shared<ExternalManagerFactoryMock>();
    auto osAccountMgrMock = std::make_shared<EdmOsAccountManagerImplMock>();
    plugin.externalManagerFactory_ = factory;
    MessageParcel reply;
    std::map<std::string, std::string> policies;
    policies.insert(std::make_pair("ut_test_user_name2", "1"));
    EXPECT_CALL(*factory, CreateOsAccountManager).Times(1).WillOnce(Return(osAccountMgrMock));
    EXPECT_CALL(*osAccountMgrMock, CreateOsAccount).Times(1).WillOnce(Return(ERR_OK));
    ErrCode ret = plugin.OnSetPolicy(policies, reply);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnSetPolicyAddGuest
 * @tc.desc: Test AddOsAccountPlugin::OnSetPolicy to add an guest account.
 * @tc.type: FUNC
 */
HWTEST_F(AddOsAccountAccountPluginTest, TestOnSetPolicyAddGuest, TestSize.Level1)
{
    AddOsAccountPlugin plugin;
    auto factory = std::make_shared<ExternalManagerFactoryMock>();
    auto osAccountMgrMock = std::make_shared<EdmOsAccountManagerImplMock>();
    plugin.externalManagerFactory_ = factory;
    MessageParcel reply;
    std::map<std::string, std::string> policies;
    policies.insert(std::make_pair("ut_test_user_name3", "2"));
    EXPECT_CALL(*factory, CreateOsAccountManager).Times(1).WillOnce(Return(osAccountMgrMock));
    EXPECT_CALL(*osAccountMgrMock, CreateOsAccount).Times(1).WillOnce(Return(ERR_OK));
    ErrCode ret = plugin.OnSetPolicy(policies, reply);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnSetPolicyAddFail
 * @tc.desc: Test AddOsAccountPlugin::OnSetPolicy to add an guest account fail.
 * @tc.type: FUNC
 */
HWTEST_F(AddOsAccountAccountPluginTest, TestOnSetPolicyAddFail, TestSize.Level1)
{
    AddOsAccountPlugin plugin;
    auto factory = std::make_shared<ExternalManagerFactoryMock>();
    auto osAccountMgrMock = std::make_shared<EdmOsAccountManagerImplMock>();
    plugin.externalManagerFactory_ = factory;
    MessageParcel reply;
    std::map<std::string, std::string> policies;
    policies.insert(std::make_pair("ut_test_user_name3", "2"));
    EXPECT_CALL(*factory, CreateOsAccountManager).Times(1).WillOnce(Return(osAccountMgrMock));
    EXPECT_CALL(*osAccountMgrMock, CreateOsAccount).Times(1).WillOnce(Return(EdmReturnErrCode::ADD_OS_ACCOUNT_FAILED));
    ErrCode ret = plugin.OnSetPolicy(policies, reply);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADD_OS_ACCOUNT_FAILED);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS