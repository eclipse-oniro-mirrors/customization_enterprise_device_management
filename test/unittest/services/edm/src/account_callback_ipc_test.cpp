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

#define private public
#include "enterprise_admin_stub.h"
#undef private

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "callback_strategies.h"
#include "enterprise_admin_proxy.h"
#include "ienterprise_admin.h"
#include "mock/enterprise_admin_stub_mock.h"
#include "sms_receive_info.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {

namespace {
constexpr int32_t TEST_SWITCHED_IN_ACCOUNT_ID = 102;
constexpr int32_t TEST_SWITCHED_OUT_ACCOUNT_ID = 100;
} // namespace

/* 记录 OnAccount 回调参数的最小 Stub 子类，用于验证 OnAccountInner 的 parcel 解析 */
class AccountRecordStub : public EnterpriseAdminStub {
public:
    bool OnAdmin(uint32_t code) override { return true; }

    bool OnBundle(uint32_t code, const std::string &bundleName, int32_t accountId) override { return true; }

    bool OnApp(uint32_t code, const std::string &bundleName) override { return true; }

    bool OnSystemUpdate(const UpdateInfo &updateInfo) override { return true; }

    bool OnAccount(uint32_t code, const int32_t accountId, const int32_t oldAccountId) override
    {
        lastCode_ = code;
        lastAccountId_ = accountId;
        lastOldAccountId_ = oldAccountId;
        return true;
    }

    bool OnKioskMode(uint32_t code, const std::string &bundleName, int32_t accountId) override { return true; }

    bool OnMarketAppsInstallStatusChanged(const std::string &bundleName, int32_t status) override { return true; }

    bool OnDeviceAdmin(uint32_t code, const std::string &bundleName) override { return true; }

    bool OnLogCollected(bool isSuccess) override { return true; }

    bool OnKeyEvent(const std::string &keyEvent) override { return true; }

    bool OnStartupGuideCompleted(int32_t type) override { return true; }

    bool OnDeviceBootCompleted() override { return true; }

    bool OnAdminPolicyChanged(const PolicyChangedEvent &event) override { return true; }

    bool OnUnmountExternalStorageDevice(const ExternalStorageDeviceInfo &deviceInfo) override { return true; }

    bool OnPasswordFailed(int32_t cumulativeFailedCount, int32_t userId) override { return true; }

    bool OnSmsReceived(const SmsReceiveInfo &smsInfo) override { return true; }

    uint32_t lastCode_ = 0;
    int32_t lastAccountId_ = 0;
    int32_t lastOldAccountId_ = 0;
};

class AccountCallbackIpcTest : public testing::Test {
protected:
    void SetUp() override
    {
    }

    void TearDown() override
    {
    }
};

/**
 * @tc.name: Test_OnAccountInner_LegacyParcel_OldAccountIdInvalid
 * @tc.desc: Test legacy protocol where Proxy only writes accountId: OnAccountInner must fall back
 *           to INVALID_ACCOUNT_ID so old-version Proxy keeps working.
 * @tc.type: FUNC
 */
HWTEST_F(AccountCallbackIpcTest, OnAccountInner_LegacyParcel_OldAccountIdInvalid, TestSize.Level1)
{
    AccountRecordStub stub;
    MessageParcel data;
    data.WriteInt32(TEST_SWITCHED_IN_ACCOUNT_ID);
    MessageParcel reply;
    ASSERT_TRUE(stub.OnAccountInner(IEnterpriseAdmin::COMMAND_ON_ACCOUNT_SWITCHED, data, reply));
    EXPECT_EQ(stub.lastCode_, static_cast<uint32_t>(IEnterpriseAdmin::COMMAND_ON_ACCOUNT_SWITCHED));
    EXPECT_EQ(stub.lastAccountId_, TEST_SWITCHED_IN_ACCOUNT_ID);
    EXPECT_EQ(stub.lastOldAccountId_, INVALID_ACCOUNT_ID);
}

/**
 * @tc.name: Test_OnAccountInner_NewParcel_BothAccountIds
 * @tc.desc: Test new protocol where Proxy writes accountId then oldAccountId: both values must be
 *           read in order. Also locks the documented parcel layout contract.
 * @tc.type: FUNC
 */
HWTEST_F(AccountCallbackIpcTest, OnAccountInner_NewParcel_BothAccountIds, TestSize.Level1)
{
    AccountRecordStub stub;
    MessageParcel data;
    data.WriteInt32(TEST_SWITCHED_IN_ACCOUNT_ID);
    data.WriteInt32(TEST_SWITCHED_OUT_ACCOUNT_ID);
    MessageParcel reply;
    ASSERT_TRUE(stub.OnAccountInner(IEnterpriseAdmin::COMMAND_ON_ACCOUNT_SWITCHED, data, reply));
    EXPECT_EQ(stub.lastAccountId_, TEST_SWITCHED_IN_ACCOUNT_ID);
    EXPECT_EQ(stub.lastOldAccountId_, TEST_SWITCHED_OUT_ACCOUNT_ID);
}

/**
 * @tc.name: Test_ProxyOnAccount_WritesBothAccountIds
 * @tc.desc: Test Proxy serialization path via AccountStrategy: parcel must contain accountId then
 *           oldAccountId in order, with the account-switched command code.
 * @tc.type: FUNC
 */
HWTEST_F(AccountCallbackIpcTest, ProxyOnAccount_WritesBothAccountIds, TestSize.Level1)
{
    auto strategy = std::make_shared<AccountStrategy>(IEnterpriseAdmin::COMMAND_ON_ACCOUNT_SWITCHED,
        TEST_SWITCHED_IN_ACCOUNT_ID, TEST_SWITCHED_OUT_ACCOUNT_ID);
    ASSERT_NE(strategy, nullptr);
    sptr<EnterpriseAdminStubMock> stubMock = new EnterpriseAdminStubMock();
    ASSERT_NE(stubMock, nullptr);
    uint32_t sentCode = 0;
    int32_t readAccountId = 0;
    int32_t readOldAccountId = 0;
    EXPECT_CALL(*stubMock, SendRequest).WillOnce(Invoke(
        [&](uint32_t code, MessageParcel &parcel, MessageParcel &, MessageOption &) -> int {
            sentCode = code;
            parcel.ReadInterfaceToken();
            readAccountId = parcel.ReadInt32();
            readOldAccountId = parcel.ReadInt32();
            return 0;
        }));
    sptr<EnterpriseAdminProxy> proxy = new EnterpriseAdminProxy(stubMock);
    ASSERT_NE(proxy, nullptr);
    EXPECT_TRUE(strategy->Execute(proxy));
    EXPECT_EQ(sentCode, static_cast<uint32_t>(IEnterpriseAdmin::COMMAND_ON_ACCOUNT_SWITCHED));
    EXPECT_EQ(readAccountId, TEST_SWITCHED_IN_ACCOUNT_ID);
    EXPECT_EQ(readOldAccountId, TEST_SWITCHED_OUT_ACCOUNT_ID);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
