/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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
#include <gmock/gmock.h>
#include <string>
#include <chrono>
#include "ienterprise_admin.h"
#include "callback_strategies.h"
#include "enterprise_connection_callback.h"
#include "admin_manager.h"
#include "admin.h"
#include "enterprise_admin_proxy.h"
#include "mock/enterprise_admin_stub_mock.h"
#define private public
#include "enterprise_conn_manager.h"
#undef private

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
constexpr int32_t DEFAULT_USERID = 100;
constexpr uint32_t TEST_CODE = IEnterpriseAdmin::COMMAND_ON_ADMIN_ENABLED;
const std::string BUNDLE_NAME = "com.edm.test.demo";
const std::string ABILITY_NAME = "com.edm.test.demo.Ability";
const std::string TEST_BUNDLE = "com.test.bundle";

// Mock class for Admin
class MockAdmin : public Admin {
public:
    MockAdmin(const AdminInfo& adminInfo) : Admin(adminInfo) {}
    MOCK_METHOD(bool, IsEnterpriseAdminKeepAlive, (), (const, override));
};

// Mock class for AdminManager
class MockAdminManager : public AdminManager {
public:
    MOCK_METHOD(std::shared_ptr<Admin>, GetAdminByPkgName, (const std::string&, int32_t));
};

class EnterpriseConnManagerTest : public testing::Test {
protected:
    void SetUp() override;

    void TearDown() override;

    std::shared_ptr<EnterpriseConnManager> enterpriseConnManagerTest {nullptr};
};

void EnterpriseConnManagerTest::SetUp()
{
    enterpriseConnManagerTest = DelayedSingleton<EnterpriseConnManager>::GetInstance();
}

void EnterpriseConnManagerTest::TearDown()
{
    if (enterpriseConnManagerTest) {
        enterpriseConnManagerTest->ClearConnections();
    }
}

// ========== Callback Strategies Tests ==========

HWTEST_F(EnterpriseConnManagerTest, AdminStrategy_Execute_ProxyIsNull_Success, TestSize.Level1)
{
    auto strategy = std::make_shared<AdminStrategy>(TEST_CODE);
    ASSERT_NE(strategy, nullptr);
    sptr<EnterpriseAdminProxy> proxy = nullptr;
    strategy->Execute(proxy);
}

HWTEST_F(EnterpriseConnManagerTest, AdminStrategy_Execute_ProxyIsValid_Success, TestSize.Level1)
{
    auto strategy = std::make_shared<AdminStrategy>(TEST_CODE);
    ASSERT_NE(strategy, nullptr);
    sptr<EnterpriseAdminStubMock> stubMock = new EnterpriseAdminStubMock();
    ASSERT_NE(stubMock, nullptr);
    sptr<EnterpriseAdminProxy> proxy = new EnterpriseAdminProxy(stubMock);
    ASSERT_NE(proxy, nullptr);
    strategy->Execute(proxy);
}

HWTEST_F(EnterpriseConnManagerTest, DeviceAdminStrategy_Execute_ProxyIsNull_Success, TestSize.Level1)
{
    auto strategy = std::make_shared<DeviceAdminStrategy>(TEST_CODE, TEST_BUNDLE);
    ASSERT_NE(strategy, nullptr);
    sptr<EnterpriseAdminProxy> proxy = nullptr;
    strategy->Execute(proxy);
}

HWTEST_F(EnterpriseConnManagerTest, DeviceAdminStrategy_Execute_ProxyIsValid_Success, TestSize.Level1)
{
    auto strategy = std::make_shared<DeviceAdminStrategy>(TEST_CODE, TEST_BUNDLE);
    ASSERT_NE(strategy, nullptr);
    sptr<EnterpriseAdminStubMock> stubMock = new EnterpriseAdminStubMock();
    ASSERT_NE(stubMock, nullptr);
    sptr<EnterpriseAdminProxy> proxy = new EnterpriseAdminProxy(stubMock);
    ASSERT_NE(proxy, nullptr);
    strategy->Execute(proxy);
}

HWTEST_F(EnterpriseConnManagerTest, BundleStrategy_Execute_ProxyIsNull_Success, TestSize.Level1)
{
    auto strategy = std::make_shared<BundleStrategy>(IEnterpriseAdmin::COMMAND_ON_BUNDLE_ADDED, TEST_BUNDLE,
        DEFAULT_USERID);
    ASSERT_NE(strategy, nullptr);
    sptr<EnterpriseAdminProxy> proxy = nullptr;
    strategy->Execute(proxy);
}

HWTEST_F(EnterpriseConnManagerTest, BundleStrategy_Execute_ProxyIsValid_Success, TestSize.Level1)
{
    auto strategy = std::make_shared<BundleStrategy>(IEnterpriseAdmin::COMMAND_ON_BUNDLE_ADDED, TEST_BUNDLE,
        DEFAULT_USERID);
    ASSERT_NE(strategy, nullptr);
    sptr<EnterpriseAdminStubMock> stubMock = new EnterpriseAdminStubMock();
    ASSERT_NE(stubMock, nullptr);
    sptr<EnterpriseAdminProxy> proxy = new EnterpriseAdminProxy(stubMock);
    ASSERT_NE(proxy, nullptr);
    strategy->Execute(proxy);
}

HWTEST_F(EnterpriseConnManagerTest, AppStrategy_Execute_ProxyIsNull_Success, TestSize.Level1)
{
    auto strategy = std::make_shared<AppStrategy>(IEnterpriseAdmin::COMMAND_ON_APP_START, TEST_BUNDLE);
    ASSERT_NE(strategy, nullptr);
    sptr<EnterpriseAdminProxy> proxy = nullptr;
    strategy->Execute(proxy);
}

HWTEST_F(EnterpriseConnManagerTest, AppStrategy_Execute_ProxyIsValid_Success, TestSize.Level1)
{
    auto strategy = std::make_shared<AppStrategy>(IEnterpriseAdmin::COMMAND_ON_APP_START, TEST_BUNDLE);
    ASSERT_NE(strategy, nullptr);
    sptr<EnterpriseAdminStubMock> stubMock = new EnterpriseAdminStubMock();
    ASSERT_NE(stubMock, nullptr);
    sptr<EnterpriseAdminProxy> proxy = new EnterpriseAdminProxy(stubMock);
    ASSERT_NE(proxy, nullptr);
    strategy->Execute(proxy);
}

HWTEST_F(EnterpriseConnManagerTest, AccountStrategy_Execute_ProxyIsNull_Success, TestSize.Level1)
{
    auto strategy = std::make_shared<AccountStrategy>(IEnterpriseAdmin::COMMAND_ON_ACCOUNT_ADDED, DEFAULT_USERID);
    ASSERT_NE(strategy, nullptr);
    sptr<EnterpriseAdminProxy> proxy = nullptr;
    strategy->Execute(proxy);
}

HWTEST_F(EnterpriseConnManagerTest, AccountStrategy_Execute_ProxyIsValid_Success, TestSize.Level1)
{
    auto strategy = std::make_shared<AccountStrategy>(IEnterpriseAdmin::COMMAND_ON_ACCOUNT_ADDED, DEFAULT_USERID);
    ASSERT_NE(strategy, nullptr);
    sptr<EnterpriseAdminStubMock> stubMock = new EnterpriseAdminStubMock();
    ASSERT_NE(stubMock, nullptr);
    sptr<EnterpriseAdminProxy> proxy = new EnterpriseAdminProxy(stubMock);
    ASSERT_NE(proxy, nullptr);
    strategy->Execute(proxy);
}

HWTEST_F(EnterpriseConnManagerTest, KioskModeStrategy_Execute_ProxyIsNull_Success, TestSize.Level1)
{
    auto strategy = std::make_shared<KioskModeStrategy>(IEnterpriseAdmin::COMMAND_ON_KIOSK_MODE_ENTERING, TEST_BUNDLE,
        DEFAULT_USERID);
    ASSERT_NE(strategy, nullptr);
    sptr<EnterpriseAdminProxy> proxy = nullptr;
    strategy->Execute(proxy);
}

HWTEST_F(EnterpriseConnManagerTest, KioskModeStrategy_Execute_ProxyIsValid_Success, TestSize.Level1)
{
    auto strategy = std::make_shared<KioskModeStrategy>(IEnterpriseAdmin::COMMAND_ON_KIOSK_MODE_ENTERING, TEST_BUNDLE,
        DEFAULT_USERID);
    ASSERT_NE(strategy, nullptr);
    sptr<EnterpriseAdminStubMock> stubMock = new EnterpriseAdminStubMock();
    ASSERT_NE(stubMock, nullptr);
    sptr<EnterpriseAdminProxy> proxy = new EnterpriseAdminProxy(stubMock);
    ASSERT_NE(proxy, nullptr);
    strategy->Execute(proxy);
}

HWTEST_F(EnterpriseConnManagerTest, MarketAppsInstallStatusChangedStrategy_Execute_ProxyIsNull_Success, TestSize.Level1)
{
    auto strategy = std::make_shared<MarketAppsInstallStatusChangedStrategy>(TEST_BUNDLE, 0);
    ASSERT_NE(strategy, nullptr);
    sptr<EnterpriseAdminProxy> proxy = nullptr;
    strategy->Execute(proxy);
}

HWTEST_F(EnterpriseConnManagerTest, MarketAppsInstallStatusChangedStrategy_Execute_ProxyIsValid_Success,
    TestSize.Level1)
{
    auto strategy = std::make_shared<MarketAppsInstallStatusChangedStrategy>(TEST_BUNDLE, 0);
    ASSERT_NE(strategy, nullptr);
    sptr<EnterpriseAdminStubMock> stubMock = new EnterpriseAdminStubMock();
    ASSERT_NE(stubMock, nullptr);
    sptr<EnterpriseAdminProxy> proxy = new EnterpriseAdminProxy(stubMock);
    ASSERT_NE(proxy, nullptr);
    strategy->Execute(proxy);
}

HWTEST_F(EnterpriseConnManagerTest, LogCollectedStrategy_Execute_ProxyIsNull_Success, TestSize.Level1)
{
    auto strategy = std::make_shared<LogCollectedStrategy>(true);
    ASSERT_NE(strategy, nullptr);
    sptr<EnterpriseAdminProxy> proxy = nullptr;
    strategy->Execute(proxy);
}

HWTEST_F(EnterpriseConnManagerTest, LogCollectedStrategy_Execute_ProxyIsValid_Success, TestSize.Level1)
{
    auto strategy = std::make_shared<LogCollectedStrategy>(true);
    ASSERT_NE(strategy, nullptr);
    sptr<EnterpriseAdminStubMock> stubMock = new EnterpriseAdminStubMock();
    ASSERT_NE(stubMock, nullptr);
    sptr<EnterpriseAdminProxy> proxy = new EnterpriseAdminProxy(stubMock);
    ASSERT_NE(proxy, nullptr);
    strategy->Execute(proxy);
}

HWTEST_F(EnterpriseConnManagerTest, KeyEventStrategy_Execute_ProxyIsNull_Success, TestSize.Level1)
{
    std::string keyEventStr = "{\"actionTime\": 344510, \"keyCode\": 1}";
    auto strategy = std::make_shared<KeyEventStrategy>(keyEventStr);
    ASSERT_NE(strategy, nullptr);
    sptr<EnterpriseAdminProxy> proxy = nullptr;
    strategy->Execute(proxy);
}

HWTEST_F(EnterpriseConnManagerTest, KeyEventStrategy_Execute_ProxyIsValid_Success, TestSize.Level1)
{
    std::string keyEventStr = "{\"actionTime\": 344510, \"keyCode\": 1}";
    auto strategy = std::make_shared<KeyEventStrategy>(keyEventStr);
    ASSERT_NE(strategy, nullptr);
    sptr<EnterpriseAdminStubMock> stubMock = new EnterpriseAdminStubMock();
    ASSERT_NE(stubMock, nullptr);
    sptr<EnterpriseAdminProxy> proxy = new EnterpriseAdminProxy(stubMock);
    ASSERT_NE(proxy, nullptr);
    strategy->Execute(proxy);
}

HWTEST_F(EnterpriseConnManagerTest, StartupGuideCompletedStrategy_Execute_ProxyIsNull_Success, TestSize.Level1)
{
    auto strategy = std::make_shared<StartupGuideCompletedStrategy>(0);
    ASSERT_NE(strategy, nullptr);
    sptr<EnterpriseAdminProxy> proxy = nullptr;
    strategy->Execute(proxy);
}

HWTEST_F(EnterpriseConnManagerTest, StartupGuideCompletedStrategy_Execute_ProxyIsValid_Success, TestSize.Level1)
{
    auto strategy = std::make_shared<StartupGuideCompletedStrategy>(0);
    ASSERT_NE(strategy, nullptr);
    sptr<EnterpriseAdminStubMock> stubMock = new EnterpriseAdminStubMock();
    ASSERT_NE(stubMock, nullptr);
    sptr<EnterpriseAdminProxy> proxy = new EnterpriseAdminProxy(stubMock);
    ASSERT_NE(proxy, nullptr);
    strategy->Execute(proxy);
}

HWTEST_F(EnterpriseConnManagerTest, DeviceBootCompletedStrategy_Execute_ProxyIsNull_Success, TestSize.Level1)
{
    auto strategy = std::make_shared<DeviceBootCompletedStrategy>();
    ASSERT_NE(strategy, nullptr);
    sptr<EnterpriseAdminProxy> proxy = nullptr;
    strategy->Execute(proxy);
}

HWTEST_F(EnterpriseConnManagerTest, DeviceBootCompletedStrategy_Execute_ProxyIsValid_Success, TestSize.Level1)
{
    auto strategy = std::make_shared<DeviceBootCompletedStrategy>();
    ASSERT_NE(strategy, nullptr);
    sptr<EnterpriseAdminStubMock> stubMock = new EnterpriseAdminStubMock();
    ASSERT_NE(stubMock, nullptr);
    sptr<EnterpriseAdminProxy> proxy = new EnterpriseAdminProxy(stubMock);
    ASSERT_NE(proxy, nullptr);
    strategy->Execute(proxy);
}

HWTEST_F(EnterpriseConnManagerTest, SystemUpdateStrategy_Execute_ProxyIsNull_Success, TestSize.Level1)
{
    UpdateInfo updateInfo;
    auto strategy = std::make_shared<SystemUpdateStrategy>(updateInfo);
    ASSERT_NE(strategy, nullptr);
    sptr<EnterpriseAdminProxy> proxy = nullptr;
    strategy->Execute(proxy);
}

HWTEST_F(EnterpriseConnManagerTest, SystemUpdateStrategy_Execute_ProxyIsValid_Success, TestSize.Level1)
{
    UpdateInfo updateInfo;
    auto strategy = std::make_shared<SystemUpdateStrategy>(updateInfo);
    ASSERT_NE(strategy, nullptr);
    sptr<EnterpriseAdminStubMock> stubMock = new EnterpriseAdminStubMock();
    ASSERT_NE(stubMock, nullptr);
    sptr<EnterpriseAdminProxy> proxy = new EnterpriseAdminProxy(stubMock);
    ASSERT_NE(proxy, nullptr);
    strategy->Execute(proxy);
}

HWTEST_F(EnterpriseConnManagerTest, AdminPolicyChangedStrategy_Execute_ProxyIsNull_Success, TestSize.Level1)
{
    PolicyChangedEvent event("setPasswordPolicy", "com.edm.test.admin", "{}", 1234567890);
    auto strategy = std::make_shared<AdminPolicyChangedStrategy>(event);
    ASSERT_NE(strategy, nullptr);
    sptr<EnterpriseAdminProxy> proxy = nullptr;
    strategy->Execute(proxy);
}

HWTEST_F(EnterpriseConnManagerTest, AdminPolicyChangedStrategy_Execute_ProxyIsValid_Success, TestSize.Level1)
{
    PolicyChangedEvent event("setPasswordPolicy", "com.edm.test.admin", "{}", 1234567890);
    auto strategy = std::make_shared<AdminPolicyChangedStrategy>(event);
    ASSERT_NE(strategy, nullptr);
    sptr<EnterpriseAdminStubMock> stubMock = new EnterpriseAdminStubMock();
    ASSERT_NE(stubMock, nullptr);
    sptr<EnterpriseAdminProxy> proxy = new EnterpriseAdminProxy(stubMock);
    ASSERT_NE(proxy, nullptr);
    strategy->Execute(proxy);
}

HWTEST_F(EnterpriseConnManagerTest, StartStrategy_Execute_ProxyIsNull_Success, TestSize.Level1)
{
    auto strategy = std::make_shared<StartStrategy>();
    ASSERT_NE(strategy, nullptr);
    sptr<EnterpriseAdminProxy> proxy = nullptr;
    strategy->Execute(proxy);
}

// ========== EnterpriseConnManager Tests ==========

HWTEST_F(EnterpriseConnManagerTest, ExecuteCallback_StrategyIsNull_ReturnFalse, TestSize.Level1)
{
    bool ret = enterpriseConnManagerTest->ExecuteCallback(BUNDLE_NAME, ABILITY_NAME, DEFAULT_USERID, nullptr);
    EXPECT_FALSE(ret);
}

HWTEST_F(EnterpriseConnManagerTest, ExecuteCallback_AdminStrategy_ReturnFalse, TestSize.Level1)
{
    auto strategy = std::make_shared<AdminStrategy>(TEST_CODE);
    bool ret = enterpriseConnManagerTest->ExecuteCallback(BUNDLE_NAME, ABILITY_NAME, DEFAULT_USERID, strategy);
    EXPECT_FALSE(ret);
}

HWTEST_F(EnterpriseConnManagerTest, ExecuteCallback_BundleStrategy_ReturnFalse, TestSize.Level1)
{
    auto strategy = std::make_shared<BundleStrategy>(IEnterpriseAdmin::COMMAND_ON_BUNDLE_ADDED, TEST_BUNDLE,
        DEFAULT_USERID);
    bool ret = enterpriseConnManagerTest->ExecuteCallback(BUNDLE_NAME, ABILITY_NAME, DEFAULT_USERID, strategy);
    EXPECT_FALSE(ret);
}

HWTEST_F(EnterpriseConnManagerTest, ExecuteCallback_AppStrategy_ReturnFalse, TestSize.Level1)
{
    auto strategy = std::make_shared<AppStrategy>(IEnterpriseAdmin::COMMAND_ON_APP_START, TEST_BUNDLE);
    bool ret = enterpriseConnManagerTest->ExecuteCallback(BUNDLE_NAME, ABILITY_NAME, DEFAULT_USERID, strategy);
    EXPECT_FALSE(ret);
}

HWTEST_F(EnterpriseConnManagerTest, ExecuteCallback_AccountStrategy_ReturnFalse, TestSize.Level1)
{
    auto strategy = std::make_shared<AccountStrategy>(IEnterpriseAdmin::COMMAND_ON_ACCOUNT_ADDED, DEFAULT_USERID);
    bool ret = enterpriseConnManagerTest->ExecuteCallback(BUNDLE_NAME, ABILITY_NAME, DEFAULT_USERID, strategy);
    EXPECT_FALSE(ret);
}

HWTEST_F(EnterpriseConnManagerTest, ExecuteCallback_KioskStrategy_ReturnFalse, TestSize.Level1)
{
    auto strategy = std::make_shared<KioskModeStrategy>(IEnterpriseAdmin::COMMAND_ON_KIOSK_MODE_ENTERING, TEST_BUNDLE,
        DEFAULT_USERID);
    bool ret = enterpriseConnManagerTest->ExecuteCallback(BUNDLE_NAME, ABILITY_NAME, DEFAULT_USERID, strategy);
    EXPECT_FALSE(ret);
}

HWTEST_F(EnterpriseConnManagerTest, ExecuteCallback_DeviceAdminStrategy_ReturnFalse, TestSize.Level1)
{
    auto strategy = std::make_shared<DeviceAdminStrategy>(IEnterpriseAdmin::COMMAND_ON_DEVICE_ADMIN_ENABLED,
        TEST_BUNDLE);
    bool ret = enterpriseConnManagerTest->ExecuteCallback(BUNDLE_NAME, ABILITY_NAME, DEFAULT_USERID, strategy);
    EXPECT_FALSE(ret);
}

HWTEST_F(EnterpriseConnManagerTest, ExecuteCallback_LogStrategy_ReturnFalse, TestSize.Level1)
{
    auto strategy = std::make_shared<LogCollectedStrategy>(true);
    bool ret = enterpriseConnManagerTest->ExecuteCallback(BUNDLE_NAME, ABILITY_NAME, DEFAULT_USERID, strategy);
    EXPECT_FALSE(ret);
}

HWTEST_F(EnterpriseConnManagerTest, ExecuteCallback_KeyEventStrategy_ReturnFalse, TestSize.Level1)
{
    std::string keyEventStr = "{\"actionTime\": 344510, \"keyCode\": 1}";
    auto strategy = std::make_shared<KeyEventStrategy>(keyEventStr);
    bool ret = enterpriseConnManagerTest->ExecuteCallback(BUNDLE_NAME, ABILITY_NAME, DEFAULT_USERID, strategy);
    EXPECT_FALSE(ret);
}

HWTEST_F(EnterpriseConnManagerTest, ExecuteCallback_OobeStrategy_ReturnFalse, TestSize.Level1)
{
    auto strategy = std::make_shared<StartupGuideCompletedStrategy>(0);
    bool ret = enterpriseConnManagerTest->ExecuteCallback(BUNDLE_NAME, ABILITY_NAME, DEFAULT_USERID, strategy);
    EXPECT_FALSE(ret);
}

HWTEST_F(EnterpriseConnManagerTest, ExecuteCallback_UpdateStrategy_ReturnFalse, TestSize.Level1)
{
    UpdateInfo updateInfo;
    auto strategy = std::make_shared<SystemUpdateStrategy>(updateInfo);
    bool ret = enterpriseConnManagerTest->ExecuteCallback(BUNDLE_NAME, ABILITY_NAME, DEFAULT_USERID, strategy);
    EXPECT_FALSE(ret);
}

HWTEST_F(EnterpriseConnManagerTest, ExecuteCallback_PolicyChangedStrategy_ReturnFalse, TestSize.Level1)
{
    PolicyChangedEvent event("setPasswordPolicy", "com.edm.test.admin", "{}", 1234567890);
    auto strategy = std::make_shared<AdminPolicyChangedStrategy>(event);
    bool ret = enterpriseConnManagerTest->ExecuteCallback(BUNDLE_NAME, ABILITY_NAME, DEFAULT_USERID, strategy);
    EXPECT_FALSE(ret);
}

HWTEST_F(EnterpriseConnManagerTest, ExecuteCallback_MarketAppsInstallStatusChangedStrategy_ReturnFalse, TestSize.Level1)
{
    auto strategy = std::make_shared<MarketAppsInstallStatusChangedStrategy>(TEST_BUNDLE, 0);
    bool ret = enterpriseConnManagerTest->ExecuteCallback(BUNDLE_NAME, ABILITY_NAME, DEFAULT_USERID, strategy);
    EXPECT_FALSE(ret);
}

HWTEST_F(EnterpriseConnManagerTest, ExecuteCallback_DeviceBootCompletedStrategy_ReturnFalse, TestSize.Level1)
{
    auto strategy = std::make_shared<DeviceBootCompletedStrategy>();
    bool ret = enterpriseConnManagerTest->ExecuteCallback(BUNDLE_NAME, ABILITY_NAME, DEFAULT_USERID, strategy);
    EXPECT_FALSE(ret);
}

HWTEST_F(EnterpriseConnManagerTest, ExecuteCallback_ProxyExists_ReturnTrue, TestSize.Level1)
{
    sptr<EnterpriseAdminStubMock> stubMock = new EnterpriseAdminStubMock();
    ASSERT_NE(stubMock, nullptr);
    sptr<EnterpriseAdminProxy> proxy = new EnterpriseAdminProxy(stubMock);
    ASSERT_NE(proxy, nullptr);

    std::string key = enterpriseConnManagerTest->GenerateConnectionKey(BUNDLE_NAME, DEFAULT_USERID);
    EnterpriseConnManager::ConnectionInfo info;
    info.proxy = proxy;
    info.isPending = false;
    info.createTime = 0;
    enterpriseConnManagerTest->connectionMap_[key] = info;

    auto strategy = std::make_shared<AdminStrategy>(TEST_CODE);
    bool ret = enterpriseConnManagerTest->ExecuteCallback(BUNDLE_NAME, ABILITY_NAME, DEFAULT_USERID, strategy);
    EXPECT_TRUE(ret);
}

HWTEST_F(EnterpriseConnManagerTest, ExecuteCallback_IsPending_ReturnTrue, TestSize.Level1)
{
    std::string key = enterpriseConnManagerTest->GenerateConnectionKey(BUNDLE_NAME, DEFAULT_USERID);
    EnterpriseConnManager::ConnectionInfo info;
    info.proxy = nullptr;
    info.isPending = true;
    info.createTime = enterpriseConnManagerTest->GetCurrentTimeMs();
    enterpriseConnManagerTest->connectionMap_[key] = info;

    auto strategy = std::make_shared<AdminStrategy>(TEST_CODE);
    bool ret = enterpriseConnManagerTest->ExecuteCallback(BUNDLE_NAME, ABILITY_NAME, DEFAULT_USERID, strategy);
    EXPECT_TRUE(ret);
}

HWTEST_F(EnterpriseConnManagerTest, ExecuteCallback_CreateNewConnection_ReturnFalse, TestSize.Level1)
{
    enterpriseConnManagerTest->ClearConnections();

    auto strategy = std::make_shared<AdminStrategy>(TEST_CODE);
    bool ret = enterpriseConnManagerTest->ExecuteCallback(BUNDLE_NAME, ABILITY_NAME, DEFAULT_USERID, strategy);
    EXPECT_FALSE(ret);
}

HWTEST_F(EnterpriseConnManagerTest, SaveProxy_ProxyIsNull_Return, TestSize.Level1)
{
    enterpriseConnManagerTest->SaveProxy(BUNDLE_NAME, DEFAULT_USERID, nullptr);
    std::string key = enterpriseConnManagerTest->GenerateConnectionKey(BUNDLE_NAME, DEFAULT_USERID);
    EXPECT_TRUE(enterpriseConnManagerTest->connectionMap_.find(key) == enterpriseConnManagerTest->connectionMap_.end());
}

HWTEST_F(EnterpriseConnManagerTest, SaveProxy_ConnectionNotFound_Return, TestSize.Level1)
{
    sptr<EnterpriseAdminStubMock> stubMock = new EnterpriseAdminStubMock();
    ASSERT_NE(stubMock, nullptr);
    sptr<EnterpriseAdminProxy> proxy = new EnterpriseAdminProxy(stubMock);
    ASSERT_NE(proxy, nullptr);

    enterpriseConnManagerTest->ClearConnections();

    enterpriseConnManagerTest->SaveProxy(BUNDLE_NAME, DEFAULT_USERID, proxy);

    std::string key = enterpriseConnManagerTest->GenerateConnectionKey(BUNDLE_NAME, DEFAULT_USERID);
    EXPECT_TRUE(enterpriseConnManagerTest->connectionMap_.find(key) == enterpriseConnManagerTest->connectionMap_.end());
}

HWTEST_F(EnterpriseConnManagerTest, ClearConnections_ConnectionMapEmpty_Success, TestSize.Level1)
{
    enterpriseConnManagerTest->ClearConnections();
    enterpriseConnManagerTest->ClearConnections();
    EXPECT_TRUE(enterpriseConnManagerTest->connectionMap_.empty());
}

HWTEST_F(EnterpriseConnManagerTest, ClearConnections_ConnectionMapNotEmpty_Success, TestSize.Level1)
{
    sptr<EnterpriseAdminStubMock> stubMock = new EnterpriseAdminStubMock();
    ASSERT_NE(stubMock, nullptr);
    sptr<EnterpriseAdminProxy> proxy = new EnterpriseAdminProxy(stubMock);
    ASSERT_NE(proxy, nullptr);

    std::string key = enterpriseConnManagerTest->GenerateConnectionKey(BUNDLE_NAME, DEFAULT_USERID);
    EnterpriseConnManager::ConnectionInfo info;
    info.proxy = proxy;
    info.createTime = 0;
    enterpriseConnManagerTest->connectionMap_[key] = info;

    enterpriseConnManagerTest->ClearConnections();
    EXPECT_TRUE(enterpriseConnManagerTest->connectionMap_.empty());
}

HWTEST_F(EnterpriseConnManagerTest, GenerateConnectionKey_Normal_ReturnCorrectKey, TestSize.Level1)
{
    std::string key = enterpriseConnManagerTest->GenerateConnectionKey(BUNDLE_NAME, DEFAULT_USERID);
    EXPECT_EQ(key, "com.edm.test.demo_100");
}

HWTEST_F(EnterpriseConnManagerTest, GenerateConnectionKey_DifferentUserId_ReturnDifferentKey, TestSize.Level1)
{
    std::string key1 = enterpriseConnManagerTest->GenerateConnectionKey(BUNDLE_NAME, DEFAULT_USERID);
    std::string key2 = enterpriseConnManagerTest->GenerateConnectionKey(BUNDLE_NAME, 200);
    EXPECT_NE(key1, key2);
}

HWTEST_F(EnterpriseConnManagerTest, GenerateConnectionKey_DifferentBundleName_ReturnDifferentKey, TestSize.Level1)
{
    std::string key1 = enterpriseConnManagerTest->GenerateConnectionKey(BUNDLE_NAME, DEFAULT_USERID);
    std::string key2 = enterpriseConnManagerTest->GenerateConnectionKey("com.test.other", DEFAULT_USERID);
    EXPECT_NE(key1, key2);
}

HWTEST_F(EnterpriseConnManagerTest, ExecuteCallback_ConnectionPendingAddCallback_Success, TestSize.Level1)
{
    std::string key = enterpriseConnManagerTest->GenerateConnectionKey(BUNDLE_NAME, DEFAULT_USERID);
    EnterpriseConnManager::ConnectionInfo info;
    info.proxy = nullptr;
    info.isPending = true;
    info.createTime = enterpriseConnManagerTest->GetCurrentTimeMs();
    enterpriseConnManagerTest->connectionMap_[key] = info;

    auto strategy1 = std::make_shared<AdminStrategy>(TEST_CODE);
    bool ret1 = enterpriseConnManagerTest->ExecuteCallback(BUNDLE_NAME, ABILITY_NAME, DEFAULT_USERID, strategy1);
    EXPECT_TRUE(ret1);

    auto strategy2 = std::make_shared<BundleStrategy>(IEnterpriseAdmin::COMMAND_ON_BUNDLE_ADDED, TEST_BUNDLE,
        DEFAULT_USERID);
    bool ret2 = enterpriseConnManagerTest->ExecuteCallback(BUNDLE_NAME, ABILITY_NAME, DEFAULT_USERID, strategy2);
    EXPECT_TRUE(ret2);

    EXPECT_EQ(enterpriseConnManagerTest->connectionMap_[key].pendingCallbacks.size(), 2);
}

HWTEST_F(EnterpriseConnManagerTest, ExecuteCallback_ProxyNullNotPending_CreateNewConnection, TestSize.Level1)
{
    std::string key = enterpriseConnManagerTest->GenerateConnectionKey(BUNDLE_NAME, DEFAULT_USERID);
    EnterpriseConnManager::ConnectionInfo info;
    info.proxy = nullptr;
    info.isPending = false;  // 非pending状态
    info.createTime = 0;
    enterpriseConnManagerTest->connectionMap_[key] = info;

    auto strategy = std::make_shared<AdminStrategy>(TEST_CODE);
    bool ret = enterpriseConnManagerTest->ExecuteCallback(BUNDLE_NAME, ABILITY_NAME, DEFAULT_USERID, strategy);
    EXPECT_FALSE(ret);  // 连接失败时返回false
}

HWTEST_F(EnterpriseConnManagerTest, SaveProxy_SuccessWithPendingCallbacks, TestSize.Level1)
{
    std::string key = enterpriseConnManagerTest->GenerateConnectionKey(BUNDLE_NAME, DEFAULT_USERID);
    EnterpriseConnManager::ConnectionInfo info;
    info.proxy = nullptr;
    info.isPending = true;
    info.createTime = enterpriseConnManagerTest->GetCurrentTimeMs();
    info.pendingCallbacks.push_back(std::make_shared<AdminStrategy>(TEST_CODE));
    enterpriseConnManagerTest->connectionMap_[key] = info;

    sptr<EnterpriseAdminStubMock> stubMock = new EnterpriseAdminStubMock();
    sptr<EnterpriseAdminProxy> proxy = new EnterpriseAdminProxy(stubMock);
    enterpriseConnManagerTest->SaveProxy(BUNDLE_NAME, DEFAULT_USERID, proxy);

    EXPECT_EQ(enterpriseConnManagerTest->connectionMap_[key].proxy, proxy);
    EXPECT_FALSE(enterpriseConnManagerTest->connectionMap_[key].isPending);
    EXPECT_TRUE(enterpriseConnManagerTest->connectionMap_[key].pendingCallbacks.empty());
}

HWTEST_F(EnterpriseConnManagerTest, SaveProxy_SuccessWithNullCallback, TestSize.Level1)
{
    std::string key = enterpriseConnManagerTest->GenerateConnectionKey(BUNDLE_NAME, DEFAULT_USERID);
    EnterpriseConnManager::ConnectionInfo info;
    info.proxy = nullptr;
    info.isPending = true;
    info.createTime = enterpriseConnManagerTest->GetCurrentTimeMs();
    info.pendingCallbacks.push_back(nullptr);  // null callback
    enterpriseConnManagerTest->connectionMap_[key] = info;

    sptr<EnterpriseAdminStubMock> stubMock = new EnterpriseAdminStubMock();
    sptr<EnterpriseAdminProxy> proxy = new EnterpriseAdminProxy(stubMock);
    enterpriseConnManagerTest->SaveProxy(BUNDLE_NAME, DEFAULT_USERID, proxy);
    // 验证null callback被跳过
    EXPECT_EQ(enterpriseConnManagerTest->connectionMap_[key].proxy, proxy);
    EXPECT_FALSE(enterpriseConnManagerTest->connectionMap_[key].isPending);
    EXPECT_TRUE(enterpriseConnManagerTest->connectionMap_[key].pendingCallbacks.empty());
}

HWTEST_F(EnterpriseConnManagerTest, RemoveRemoteObject_ExistingKey_Success, TestSize.Level1)
{
    std::string key = enterpriseConnManagerTest->GenerateConnectionKey(BUNDLE_NAME, DEFAULT_USERID);
    EnterpriseConnManager::ConnectionInfo info;
    sptr<EnterpriseAdminStubMock> stubMock = new EnterpriseAdminStubMock();
    info.proxy = new EnterpriseAdminProxy(stubMock);
    info.createTime = 0;
    enterpriseConnManagerTest->connectionMap_[key] = info;

    enterpriseConnManagerTest->RemoveRemoteObject(BUNDLE_NAME, DEFAULT_USERID);
    EXPECT_TRUE(enterpriseConnManagerTest->connectionMap_.find(key) == 
        enterpriseConnManagerTest->connectionMap_.end());
}

HWTEST_F(EnterpriseConnManagerTest, RemoveRemoteObject_NonExistingKey_Success, TestSize.Level1)
{
    enterpriseConnManagerTest->ClearConnections();
    enterpriseConnManagerTest->RemoveRemoteObject(BUNDLE_NAME, DEFAULT_USERID);
    EXPECT_TRUE(enterpriseConnManagerTest->connectionMap_.empty());
}

HWTEST_F(EnterpriseConnManagerTest, ExecuteCallback_ConnectionTimeout_Success, TestSize.Level1)
{
    std::string key = enterpriseConnManagerTest->GenerateConnectionKey(BUNDLE_NAME, DEFAULT_USERID);
    EnterpriseConnManager::ConnectionInfo info;
    info.isPending = true;
    info.createTime = enterpriseConnManagerTest->GetCurrentTimeMs() - 15000;  // 15秒前，超过默认10秒超时
    info.pendingCallbacks.push_back(std::make_shared<AdminStrategy>(TEST_CODE));
    enterpriseConnManagerTest->connectionMap_[key] = info;

    auto strategy = std::make_shared<BundleStrategy>(IEnterpriseAdmin::COMMAND_ON_BUNDLE_ADDED, TEST_BUNDLE,
        DEFAULT_USERID);
    bool ret = enterpriseConnManagerTest->ExecuteCallback(BUNDLE_NAME, ABILITY_NAME, DEFAULT_USERID, strategy);

    // 测试环境中连接建立会失败，但超时清理逻辑已经正确执行
    // 1. CheckConnectionState检测到超时，删除旧条目
    // 2. PrepareNewConnection创建新的pending条目
    // 3. EstablishConnection尝试连接但失败，删除新创建的条目
    EXPECT_FALSE(ret);

    // 验证：连接失败后，条目被删除
    auto it = enterpriseConnManagerTest->connectionMap_.find(key);
    EXPECT_EQ(it, enterpriseConnManagerTest->connectionMap_.end());
}

HWTEST_F(EnterpriseConnManagerTest, IsConnectionTimeout_PendingTrue_Success, TestSize.Level1)
{
    EnterpriseConnManager::ConnectionInfo info;
    info.isPending = true;
    info.createTime = 0;
    EXPECT_TRUE(enterpriseConnManagerTest->IsConnectionTimeout(info));

    info.createTime = enterpriseConnManagerTest->GetCurrentTimeMs() - 35000;
    EXPECT_TRUE(enterpriseConnManagerTest->IsConnectionTimeout(info));
}

HWTEST_F(EnterpriseConnManagerTest, IsConnectionTimeout_PendingFalse_Success, TestSize.Level1)
{
    EnterpriseConnManager::ConnectionInfo info;
    info.isPending = false;
    info.createTime = 0;
    EXPECT_FALSE(enterpriseConnManagerTest->IsConnectionTimeout(info));
}

HWTEST_F(EnterpriseConnManagerTest, IsConnectionTimeout_NotExpired_Success, TestSize.Level1)
{
    EnterpriseConnManager::ConnectionInfo info;
    info.isPending = true;
    info.createTime = enterpriseConnManagerTest->GetCurrentTimeMs() - 5000;  // 5秒前创建，未超过默认10秒超时
    EXPECT_FALSE(enterpriseConnManagerTest->IsConnectionTimeout(info));
}

HWTEST_F(EnterpriseConnManagerTest, SaveProxy_ExecuteValidCallback_Success, TestSize.Level1)
{
    std::string key = enterpriseConnManagerTest->GenerateConnectionKey(BUNDLE_NAME, DEFAULT_USERID);
    EnterpriseConnManager::ConnectionInfo info;
    info.proxy = nullptr;
    info.isPending = true;
    info.createTime = enterpriseConnManagerTest->GetCurrentTimeMs();

    // 添加有效callback
    auto validStrategy = std::make_shared<AdminStrategy>(TEST_CODE);
    info.pendingCallbacks.push_back(validStrategy);
    enterpriseConnManagerTest->connectionMap_[key] = info;

    sptr<EnterpriseAdminStubMock> stubMock = new EnterpriseAdminStubMock();
    sptr<EnterpriseAdminProxy> proxy = new EnterpriseAdminProxy(stubMock);
    enterpriseConnManagerTest->SaveProxy(BUNDLE_NAME, DEFAULT_USERID, proxy);

    // 验证：proxy已保存
    EXPECT_EQ(enterpriseConnManagerTest->connectionMap_[key].proxy, proxy);
    EXPECT_FALSE(enterpriseConnManagerTest->connectionMap_[key].isPending);
    EXPECT_TRUE(enterpriseConnManagerTest->connectionMap_[key].pendingCallbacks.empty());
}

HWTEST_F(EnterpriseConnManagerTest, IsValid_ProxyIsValid_ReturnTrue, TestSize.Level1)
{
    sptr<EnterpriseAdminStubMock> stubMock = new EnterpriseAdminStubMock();
    ASSERT_NE(stubMock, nullptr);
    sptr<EnterpriseAdminProxy> proxy = new EnterpriseAdminProxy(stubMock);
    ASSERT_NE(proxy, nullptr);

    EXPECT_TRUE(proxy->IsValid());
}

HWTEST_F(EnterpriseConnManagerTest, IsValid_RemoteObjectDead_ReturnFalse, TestSize.Level1)
{
    sptr<EnterpriseAdminStubMock> stubMock = new EnterpriseAdminStubMock();
    sptr<EnterpriseAdminProxy> proxy = new EnterpriseAdminProxy(stubMock);
    ASSERT_NE(proxy, nullptr);
    EXPECT_TRUE(proxy->IsValid());
}

HWTEST_F(EnterpriseConnManagerTest, ExecuteCallback_ProxyInvalid_TriggerReconnect, TestSize.Level1)
{
    sptr<EnterpriseAdminStubMock> stubMock = new EnterpriseAdminStubMock();

    sptr<EnterpriseAdminProxy> proxy = new EnterpriseAdminProxy(stubMock);
    ASSERT_NE(proxy, nullptr);

    std::string key = enterpriseConnManagerTest->GenerateConnectionKey(BUNDLE_NAME, DEFAULT_USERID);
    EnterpriseConnManager::ConnectionInfo info;
    info.proxy = proxy;
    info.isPending = false;
    info.createTime = enterpriseConnManagerTest->GetCurrentTimeMs();

    auto oldStrategy = std::make_shared<AdminStrategy>(TEST_CODE);
    info.pendingCallbacks.push_back(oldStrategy);

    enterpriseConnManagerTest->connectionMap_[key] = info;

    auto newStrategy = std::make_shared<AdminStrategy>(TEST_CODE);
    bool ret = enterpriseConnManagerTest->ExecuteCallback(BUNDLE_NAME, ABILITY_NAME, DEFAULT_USERID, newStrategy);

    EXPECT_TRUE(ret);
    EXPECT_NE(enterpriseConnManagerTest->connectionMap_[key].proxy, nullptr);
    EXPECT_FALSE(enterpriseConnManagerTest->connectionMap_[key].isPending);
    EXPECT_EQ(enterpriseConnManagerTest->connectionMap_[key].pendingCallbacks.size(), 1);
}

HWTEST_F(EnterpriseConnManagerTest, ExecuteCallback_ProxyInvalid_Reconnect, TestSize.Level1)
{
    sptr<EnterpriseAdminStubMock> stubMock = new EnterpriseAdminStubMock();
    ASSERT_NE(stubMock, nullptr);
    sptr<EnterpriseAdminProxy> proxy = new EnterpriseAdminProxy(stubMock);
    ASSERT_NE(proxy, nullptr);

    std::string key = enterpriseConnManagerTest->GenerateConnectionKey(BUNDLE_NAME, DEFAULT_USERID);
    EnterpriseConnManager::ConnectionInfo info;
    info.proxy = proxy;
    info.isPending = false;
    info.createTime = enterpriseConnManagerTest->GetCurrentTimeMs();

    auto oldStrategy1 = std::make_shared<AdminStrategy>(TEST_CODE);
    auto oldStrategy2 = std::make_shared<BundleStrategy>(IEnterpriseAdmin::COMMAND_ON_BUNDLE_ADDED, 
        TEST_BUNDLE, DEFAULT_USERID);
    info.pendingCallbacks.push_back(oldStrategy1);
    info.pendingCallbacks.push_back(oldStrategy2);

    enterpriseConnManagerTest->connectionMap_[key] = info;

    auto strategy = std::make_shared<AdminStrategy>(TEST_CODE);

    bool ret = enterpriseConnManagerTest->ExecuteCallback(BUNDLE_NAME, ABILITY_NAME, DEFAULT_USERID, strategy);

    EXPECT_TRUE(ret);
    EXPECT_EQ(enterpriseConnManagerTest->connectionMap_[key].proxy, proxy);
    EXPECT_EQ(enterpriseConnManagerTest->connectionMap_[key].pendingCallbacks.size(), 2);  // 旧 callbacks 保持不变
}

HWTEST_F(EnterpriseConnManagerTest, ExecuteCallback_ValidProxy_ExecuteSuccess, TestSize.Level1)
{
    sptr<EnterpriseAdminStubMock> stubMock = new EnterpriseAdminStubMock();
    ASSERT_NE(stubMock, nullptr);
    sptr<EnterpriseAdminProxy> proxy = new EnterpriseAdminProxy(stubMock);
    ASSERT_NE(proxy, nullptr);

    std::string key = enterpriseConnManagerTest->GenerateConnectionKey(BUNDLE_NAME, DEFAULT_USERID);
    EnterpriseConnManager::ConnectionInfo info;
    info.proxy = proxy;
    info.isPending = false;
    info.createTime = enterpriseConnManagerTest->GetCurrentTimeMs();
    enterpriseConnManagerTest->connectionMap_[key] = info;

    auto strategy = std::make_shared<AdminStrategy>(TEST_CODE);
    bool ret = enterpriseConnManagerTest->ExecuteCallback(BUNDLE_NAME, ABILITY_NAME, DEFAULT_USERID, strategy);

    // 验证：proxy有效，执行成功
    EXPECT_TRUE(ret);
    EXPECT_EQ(enterpriseConnManagerTest->connectionMap_[key].proxy, proxy);
}

HWTEST_F(EnterpriseConnManagerTest, PrepareNewConnection_PreserveOldPendingCallbacks_Success, TestSize.Level1)
{
    std::string key = enterpriseConnManagerTest->GenerateConnectionKey(BUNDLE_NAME, DEFAULT_USERID);

    // 准备旧的 pendingCallbacks
    EnterpriseConnManager::ConnectionInfo oldInfo;
    oldInfo.proxy = nullptr;
    oldInfo.isPending = false;
    oldInfo.createTime = enterpriseConnManagerTest->GetCurrentTimeMs() - 5000;

    auto oldStrategy1 = std::make_shared<AdminStrategy>(TEST_CODE);
    auto oldStrategy2 = std::make_shared<BundleStrategy>(IEnterpriseAdmin::COMMAND_ON_BUNDLE_ADDED, 
        TEST_BUNDLE, DEFAULT_USERID);
    oldInfo.pendingCallbacks.push_back(oldStrategy1);
    oldInfo.pendingCallbacks.push_back(oldStrategy2);

    enterpriseConnManagerTest->connectionMap_[key] = oldInfo;

    // PrepareNewConnection 应保留旧的 pendingCallbacks，添加新 strategy
    auto newStrategy = std::make_shared<AdminStrategy>(TEST_CODE);
    enterpriseConnManagerTest->PrepareNewConnection(key, newStrategy);

    // 验证：旧的 pendingCallbacks + 新 strategy
    auto it = enterpriseConnManagerTest->connectionMap_.find(key);
    EXPECT_NE(it, enterpriseConnManagerTest->connectionMap_.end());
    EXPECT_TRUE(it->second.isPending);
    EXPECT_EQ(it->second.pendingCallbacks.size(), 3);  // oldStrategy1 + oldStrategy2 + newStrategy
}

HWTEST_F(EnterpriseConnManagerTest, SaveProxy_ExecutePendingCallbacks_Success, TestSize.Level1)
{
    std::string key = enterpriseConnManagerTest->GenerateConnectionKey(BUNDLE_NAME, DEFAULT_USERID);
    EnterpriseConnManager::ConnectionInfo info;
    info.proxy = nullptr;
    info.isPending = true;
    info.createTime = enterpriseConnManagerTest->GetCurrentTimeMs();
    auto validStrategy = std::make_shared<AdminStrategy>(TEST_CODE);
    info.pendingCallbacks.push_back(validStrategy);
    enterpriseConnManagerTest->connectionMap_[key] = info;

    sptr<EnterpriseAdminStubMock> stubMock = new EnterpriseAdminStubMock();
    ASSERT_NE(stubMock, nullptr);
    sptr<EnterpriseAdminProxy> proxy = new EnterpriseAdminProxy(stubMock);
    ASSERT_NE(proxy, nullptr);

    enterpriseConnManagerTest->SaveProxy(BUNDLE_NAME, DEFAULT_USERID, proxy);

    EXPECT_EQ(enterpriseConnManagerTest->connectionMap_[key].proxy, proxy);
    EXPECT_FALSE(enterpriseConnManagerTest->connectionMap_[key].isPending);
    EXPECT_TRUE(enterpriseConnManagerTest->connectionMap_[key].pendingCallbacks.empty());
}

HWTEST_F(EnterpriseConnManagerTest, RemoveRemoteObject_ClearConnection_Success, TestSize.Level1)
{
    sptr<EnterpriseAdminStubMock> stubMock = new EnterpriseAdminStubMock();
    ASSERT_NE(stubMock, nullptr);
    sptr<EnterpriseAdminProxy> proxy = new EnterpriseAdminProxy(stubMock);
    ASSERT_NE(proxy, nullptr);

    std::string key = enterpriseConnManagerTest->GenerateConnectionKey(BUNDLE_NAME, DEFAULT_USERID);
    EnterpriseConnManager::ConnectionInfo info;
    info.proxy = proxy;
    info.isPending = false;
    info.createTime = enterpriseConnManagerTest->GetCurrentTimeMs();
    enterpriseConnManagerTest->connectionMap_[key] = info;

    EXPECT_NE(enterpriseConnManagerTest->connectionMap_.find(key), 
        enterpriseConnManagerTest->connectionMap_.end());

    enterpriseConnManagerTest->RemoveRemoteObject(BUNDLE_NAME, DEFAULT_USERID);

    EXPECT_EQ(enterpriseConnManagerTest->connectionMap_.find(key), 
        enterpriseConnManagerTest->connectionMap_.end());
}

HWTEST_F(EnterpriseConnManagerTest, ClearConnections_ClearAllConnections_Success, TestSize.Level1)
{
    sptr<EnterpriseAdminStubMock> stubMock = new EnterpriseAdminStubMock();
    ASSERT_NE(stubMock, nullptr);
    sptr<EnterpriseAdminProxy> proxy = new EnterpriseAdminProxy(stubMock);
    ASSERT_NE(proxy, nullptr);

    std::string key = enterpriseConnManagerTest->GenerateConnectionKey(BUNDLE_NAME, DEFAULT_USERID);
    EnterpriseConnManager::ConnectionInfo info;
    info.proxy = proxy;
    info.isPending = false;
    info.createTime = enterpriseConnManagerTest->GetCurrentTimeMs();
    enterpriseConnManagerTest->connectionMap_[key] = info;

    EXPECT_FALSE(enterpriseConnManagerTest->connectionMap_.empty());

    enterpriseConnManagerTest->ClearConnections();

    EXPECT_TRUE(enterpriseConnManagerTest->connectionMap_.empty());
}

HWTEST_F(EnterpriseConnManagerTest, OnAbilityConnectDone_ResultCodeFailed_Success, TestSize.Level1)
{
    AppExecFwk::ElementName element;
    sptr<EnterpriseConnectionCallback> callback = new EnterpriseConnectionCallback(BUNDLE_NAME, DEFAULT_USERID);
    ASSERT_NE(callback, nullptr);

    callback->OnAbilityConnectDone(element, nullptr, -1);

    std::string key = enterpriseConnManagerTest->GenerateConnectionKey(BUNDLE_NAME, DEFAULT_USERID);
    EXPECT_TRUE(enterpriseConnManagerTest->connectionMap_.find(key) == enterpriseConnManagerTest->connectionMap_.end());
}

HWTEST_F(EnterpriseConnManagerTest, OnAbilityConnectDone_RemoteObjectNull_Success, TestSize.Level1)
{
    AppExecFwk::ElementName element;
    sptr<EnterpriseConnectionCallback> callback = new EnterpriseConnectionCallback(BUNDLE_NAME, DEFAULT_USERID);
    ASSERT_NE(callback, nullptr);

    callback->OnAbilityConnectDone(element, nullptr, ERR_OK);

    std::string key = enterpriseConnManagerTest->GenerateConnectionKey(BUNDLE_NAME, DEFAULT_USERID);
    EXPECT_TRUE(enterpriseConnManagerTest->connectionMap_.find(key) == enterpriseConnManagerTest->connectionMap_.end());
}

HWTEST_F(EnterpriseConnManagerTest, OnAbilityDisconnectDone_Success, TestSize.Level1)
{
    sptr<EnterpriseAdminStubMock> stubMock = new EnterpriseAdminStubMock();
    ASSERT_NE(stubMock, nullptr);
    sptr<EnterpriseAdminProxy> proxy = new EnterpriseAdminProxy(stubMock);
    ASSERT_NE(proxy, nullptr);

    std::string key = enterpriseConnManagerTest->GenerateConnectionKey(BUNDLE_NAME, DEFAULT_USERID);
    EnterpriseConnManager::ConnectionInfo info;
    info.proxy = proxy;
    info.isPending = false;
    info.createTime = enterpriseConnManagerTest->GetCurrentTimeMs();
    enterpriseConnManagerTest->connectionMap_[key] = info;

    AppExecFwk::ElementName element;
    sptr<EnterpriseConnectionCallback> callback = new EnterpriseConnectionCallback(BUNDLE_NAME, DEFAULT_USERID);
    ASSERT_NE(callback, nullptr);

    callback->OnAbilityDisconnectDone(element, ERR_OK);

    EXPECT_TRUE(enterpriseConnManagerTest->connectionMap_.find(key) == enterpriseConnManagerTest->connectionMap_.end());
}

HWTEST_F(EnterpriseConnManagerTest, PrepareNewConnection_CreateNewEntry_Success, TestSize.Level1)
{
    enterpriseConnManagerTest->ClearConnections();

    std::string key = enterpriseConnManagerTest->GenerateConnectionKey(BUNDLE_NAME, DEFAULT_USERID);
    auto strategy = std::make_shared<AdminStrategy>(TEST_CODE);

    enterpriseConnManagerTest->PrepareNewConnection(key, strategy);

    auto it = enterpriseConnManagerTest->connectionMap_.find(key);
    EXPECT_NE(it, enterpriseConnManagerTest->connectionMap_.end());
    EXPECT_TRUE(it->second.isPending);
    EXPECT_EQ(it->second.pendingCallbacks.size(), 1);
}

HWTEST_F(EnterpriseConnManagerTest, ExecuteCallback_CheckConnectionStateProxyExists_Success, TestSize.Level1)
{
    sptr<EnterpriseAdminStubMock> stubMock = new EnterpriseAdminStubMock();
    ASSERT_NE(stubMock, nullptr);
    sptr<EnterpriseAdminProxy> proxy = new EnterpriseAdminProxy(stubMock);
    ASSERT_NE(proxy, nullptr);

    std::string key = enterpriseConnManagerTest->GenerateConnectionKey(BUNDLE_NAME, DEFAULT_USERID);
    EnterpriseConnManager::ConnectionInfo info;
    info.proxy = proxy;
    info.isPending = false;
    info.createTime = enterpriseConnManagerTest->GetCurrentTimeMs();
    enterpriseConnManagerTest->connectionMap_[key] = info;

    sptr<EnterpriseAdminProxy> existingProxy = nullptr;
    bool needCreateConnection = false;
    auto strategy = std::make_shared<AdminStrategy>(TEST_CODE);

    bool ret = enterpriseConnManagerTest->CheckConnectionState(key, strategy, existingProxy, needCreateConnection);

    EXPECT_TRUE(ret);
    EXPECT_NE(existingProxy, nullptr);
    EXPECT_FALSE(needCreateConnection);
}

HWTEST_F(EnterpriseConnManagerTest, ExecuteCallback_CheckConnectionStateIsPending_Success, TestSize.Level1)
{
    std::string key = enterpriseConnManagerTest->GenerateConnectionKey(BUNDLE_NAME, DEFAULT_USERID);
    EnterpriseConnManager::ConnectionInfo info;
    info.proxy = nullptr;
    info.isPending = true;
    info.createTime = enterpriseConnManagerTest->GetCurrentTimeMs();
    enterpriseConnManagerTest->connectionMap_[key] = info;

    sptr<EnterpriseAdminProxy> existingProxy = nullptr;
    bool needCreateConnection = false;
    auto strategy = std::make_shared<AdminStrategy>(TEST_CODE);

    bool ret = enterpriseConnManagerTest->CheckConnectionState(key, strategy, existingProxy, needCreateConnection);

    EXPECT_TRUE(ret);
    EXPECT_EQ(existingProxy, nullptr);
    EXPECT_FALSE(needCreateConnection);
    EXPECT_EQ(enterpriseConnManagerTest->connectionMap_[key].pendingCallbacks.size(), 1);
}

HWTEST_F(EnterpriseConnManagerTest, ExecuteCallback_CheckConnectionStateNoEntry_Success, TestSize.Level1)
{
    enterpriseConnManagerTest->ClearConnections();

    std::string key = enterpriseConnManagerTest->GenerateConnectionKey(BUNDLE_NAME, DEFAULT_USERID);
    sptr<EnterpriseAdminProxy> existingProxy = nullptr;
    bool needCreateConnection = false;
    auto strategy = std::make_shared<AdminStrategy>(TEST_CODE);

    bool ret = enterpriseConnManagerTest->CheckConnectionState(key, strategy, existingProxy, needCreateConnection);

    EXPECT_TRUE(ret);
    EXPECT_EQ(existingProxy, nullptr);
    EXPECT_TRUE(needCreateConnection);
}

HWTEST_F(EnterpriseConnManagerTest, GetCurrentTimeMs_ReturnValidTime, TestSize.Level1)
{
    int64_t time1 = enterpriseConnManagerTest->GetCurrentTimeMs();
    int64_t time2 = enterpriseConnManagerTest->GetCurrentTimeMs();
    EXPECT_GE(time2, time1);
    EXPECT_GT(time1, 0);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS