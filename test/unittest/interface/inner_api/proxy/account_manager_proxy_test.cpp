/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#include <string>
#include <system_ability_definition.h>

#include "account_manager_proxy.h"
#include "edm_sys_manager_mock.h"
#include "enterprise_device_mgr_stub_mock.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string ADMIN_PACKAGENAME = "com.edm.test.demo";
class AccountManagerProxyTest : public testing::Test {
protected:
    void SetUp() override;

    void TearDown() override;

    static void TearDownTestSuite(void);
    std::shared_ptr<AccountManagerProxy> accountManagerProxy = nullptr;
    std::shared_ptr<EdmSysManager> edmSysManager_ = nullptr;
    sptr<EnterpriseDeviceMgrStubMock> object_ = nullptr;
};

void AccountManagerProxyTest::SetUp()
{
    accountManagerProxy = AccountManagerProxy::GetAccountManagerProxy();
    edmSysManager_ = std::make_shared<EdmSysManager>();
    object_ = new (std::nothrow) EnterpriseDeviceMgrStubMock();
    edmSysManager_->RegisterSystemAbilityOfRemoteObject(ENTERPRISE_DEVICE_MANAGER_SA_ID, object_);
    Utils::SetEdmServiceEnable();
}

void AccountManagerProxyTest::TearDown()
{
    accountManagerProxy.reset();
    edmSysManager_->UnregisterSystemAbilityOfRemoteObject(ENTERPRISE_DEVICE_MANAGER_SA_ID);
    object_ = nullptr;
    Utils::SetEdmServiceDisable();
}

void AccountManagerProxyTest::TearDownTestSuite()
{
    ASSERT_FALSE(Utils::GetEdmServiceState());
    std::cout << "EdmServiceState : " << Utils::GetEdmServiceState() << std::endl;
}

/**
 * @tc.name: TestDisallowAddLocalAccountSuc
 * @tc.desc: Test DisallowAddLocalAccount success func.
 * @tc.type: FUNC
 */
HWTEST_F(AccountManagerProxyTest, TestDisallowAddLocalAccountSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    ErrCode ret = accountManagerProxy->DisallowAddLocalAccount(admin, true);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDisallowAddLocalAccountFail
 * @tc.desc: Test DisallowAddLocalAccount without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(AccountManagerProxyTest, TestDisallowAddLocalAccountFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    ErrCode ret = accountManagerProxy->DisallowAddLocalAccount(admin, true);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestIsAddLocalAccountDisallowedSuc
 * @tc.desc: Test IsAddLocalAccountDisallowed success.
 * @tc.type: FUNC
 */
    HWTEST_F(AccountManagerProxyTest, TestIsAddLocalAccountDisallowedSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
    .Times(1)
    .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeBoolSendRequestGetPolicy));
    bool isDisabled = false;
    ErrCode ret = accountManagerProxy->IsAddLocalAccountDisallowed(&admin, isDisabled);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(isDisabled);
}

/**
 * @tc.name: TestIsAddLocalAccountDisallowedFail
 * @tc.desc: Test IsAddLocalAccountDisallowed without enable edm service.
 * @tc.type: FUNC
 */
HWTEST_F(AccountManagerProxyTest, TestIsAddLocalAccountDisallowedFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    bool isDisabled = false;
    ErrCode ret = accountManagerProxy->IsAddLocalAccountDisallowed(&admin, isDisabled);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestDisallowAddOsAccountByUserSuc
 * @tc.desc: Test DisallowAddOsAccountByUser success.
 * @tc.type: FUNC
 */
HWTEST_F(AccountManagerProxyTest, TestDisallowAddOsAccountByUserSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    ErrCode ret = accountManagerProxy->DisallowAddOsAccountByUser(admin, DEFAULT_USER_ID, true);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDisallowAddOsAccountByUserFail
 * @tc.desc: Test DisallowAddOsAccountByUser without enable edm service.
 * @tc.type: FUNC
 */
HWTEST_F(AccountManagerProxyTest, TestDisallowAddOsAccountByUserFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    ErrCode ret = accountManagerProxy->DisallowAddOsAccountByUser(admin, DEFAULT_USER_ID, true);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestIsAddOsAccountByUserDisallowedSuc
 * @tc.desc: Test IsAddOsAccountByUserDisallowed success.
 * @tc.type: FUNC
 */
HWTEST_F(AccountManagerProxyTest, TestIsAddOsAccountByUserDisallowedSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeBoolSendRequestGetPolicy));
    bool isDisabled = false;
    ErrCode ret = accountManagerProxy->IsAddOsAccountByUserDisallowed(&admin, DEFAULT_USER_ID, isDisabled);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(isDisabled);
}

/**
 * @tc.name: TestIsAddOsAccountByUserDisallowedFail
 * @tc.desc: Test IsAddOsAccountByUserDisallowed without enable edm service.
 * @tc.type: FUNC
 */
HWTEST_F(AccountManagerProxyTest, TestIsAddOsAccountByUserDisallowedFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    bool isDisabled = false;
    ErrCode ret = accountManagerProxy->IsAddOsAccountByUserDisallowed(&admin, DEFAULT_USER_ID, isDisabled);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestAddOsAccountSuc
 * @tc.desc: Test AddOsAccount success.
 * @tc.type: FUNC
 */
HWTEST_F(AccountManagerProxyTest, TestAddOsAccountSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeAccountProxySendRequestAddOsAccount));
    std::string name = "ut_user_1";
    int32_t type = 1;
    OHOS::AccountSA::OsAccountInfo accountInfo;
    std::string distributedInfoName;
    std::string distributedInfoId;
    ErrCode ret = accountManagerProxy->AddOsAccount(admin, name, type, accountInfo, distributedInfoName,
        distributedInfoId);
    ASSERT_TRUE(ret == ERR_OK);
    GTEST_LOG_(INFO) << "AccountManagerProxyTest TestAddOsAccountSuc code :" << accountInfo.GetLocalName();
    ASSERT_TRUE(accountInfo.GetLocalName() == RETURN_STRING);
    ASSERT_TRUE(distributedInfoName == RETURN_STRING);
    ASSERT_TRUE(distributedInfoId == RETURN_STRING);
}

/**
 * @tc.name: TestAddOsAccountFail
 * @tc.desc: Test AddOsAccount without enable edm service.
 * @tc.type: FUNC
 */
HWTEST_F(AccountManagerProxyTest, TestAddOsAccountFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    std::string name = "ut_user_2";
    int32_t type = 1;
    OHOS::AccountSA::OsAccountInfo accountInfo;
    std::string distributedInfoName;
    std::string distributedInfoId;
    ErrCode ret = accountManagerProxy->AddOsAccount(admin, name, type, accountInfo, distributedInfoName,
        distributedInfoId);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
    ASSERT_TRUE(accountInfo.GetLocalName().empty());
    ASSERT_TRUE(distributedInfoName.empty());
    ASSERT_TRUE(distributedInfoId.empty());
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
