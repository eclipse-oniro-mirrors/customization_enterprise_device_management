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
#include "default_application_plugin.h"
#undef private

#include <gtest/gtest.h>

#include "appexecfwk_errors.h"
#include "default_application_type.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_os_account_manager_impl_mock.h"
#include "external_manager_factory_mock.h"
#include "message_parcel.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
namespace {
constexpr int32_t TYPE_BROWSER = static_cast<int32_t>(DefaultApplicationType::BROWSER);
constexpr int32_t TYPE_INVALID = static_cast<int32_t>(DefaultApplicationType::EMAIL) + 1;
constexpr int32_t ACCOUNT_ID = 100;
constexpr int32_t ACCOUNT_ID_INVALID = -1;
const std::string BUNDLE_NAME = "com.example.browser";
const std::string ABILITY_NAME = "EntryAbility";
const std::string MODULE_NAME = "entry";
const std::string APP_TYPE = "BROWSER";
} // namespace

class DefaultAppMock : public AppExecFwk::IDefaultApp {
public:
    ErrCode SetDefaultApplicationForCustom(const int32_t userId, const std::string &type,
        const AppExecFwk::IDefaultApp::Want &want) override
    {
        setCallCount++;
        lastUserId = userId;
        lastType = type;
        return setRet;
    }

    ErrCode GetDefaultApplication(int32_t userId, const std::string &type,
        AppExecFwk::BundleInfo &bundleInfo) override
    {
        getCallCount++;
        lastType = type;
        if (getRet == ERR_OK) {
            bundleInfo.name = readBackBundleName;
        }
        return getRet;
    }

    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }

    ErrCode setRet = ERR_OK;
    ErrCode getRet = ERR_OK;
    std::string readBackBundleName;
    int32_t setCallCount = 0;
    int32_t getCallCount = 0;
    int32_t lastUserId = -1;
    std::string lastType;
};

class DefaultApplicationPluginMock : public DefaultApplicationPlugin {
public:
    ErrCode QueryModuleName(const std::string &bundleName, const std::string &abilityName,
        int32_t accountId, std::string &moduleName) override
    {
        if (FAILED(queryModuleRet)) {
            return queryModuleRet;
        }
        moduleName = MODULE_NAME;
        return ERR_OK;
    }

    sptr<AppExecFwk::IDefaultApp> GetDefaultAppProxy() override
    {
        return defaultApp_;
    }

    sptr<DefaultAppMock> defaultApp_ = new (std::nothrow) DefaultAppMock();
    ErrCode queryModuleRet = ERR_OK;
};

class DefaultApplicationPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void)
    {
        Utils::SetEdmInitialEnv();
    }

    static void TearDownTestSuite(void)
    {
        Utils::ResetTokenTypeAndUid();
        ASSERT_TRUE(Utils::IsOriginalUTEnv());
    }

    void ExpectAccountCheck(std::shared_ptr<EdmOsAccountManagerImplMock> &accountMock, bool isExist,
        DefaultApplicationPluginMock &plugin)
    {
        auto factory = std::make_shared<ExternalManagerFactoryMock>();
        EXPECT_CALL(*factory, CreateOsAccountManager()).WillRepeatedly(Return(accountMock));
        EXPECT_CALL(*accountMock, IsOsAccountExists(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<1>(isExist), Return(ERR_OK)));
        plugin.externalManagerFactory_ = factory;
    }

    void BuildSetParcel(MessageParcel &data, int32_t type, const std::string &bundleName,
        const std::string &abilityName, int32_t accountId)
    {
        data.WriteInt32(type);
        data.WriteString(bundleName);
        data.WriteString(abilityName);
        data.WriteInt32(accountId);
    }
};

HWTEST_F(DefaultApplicationPluginTest, TestOnHandlePolicyInvalidType, TestSize.Level1)
{
    DefaultApplicationPluginMock plugin;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    BuildSetParcel(data, TYPE_INVALID, BUNDLE_NAME, ABILITY_NAME, ACCOUNT_ID);

    ErrCode ret = plugin.OnHandlePolicy(EdmInterfaceCode::DEFAULT_APPLICATION, data, reply, policyData, ACCOUNT_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    EXPECT_EQ(plugin.defaultApp_->setCallCount, 0);
}

HWTEST_F(DefaultApplicationPluginTest, TestOnHandlePolicyEmptyBundleName, TestSize.Level1)
{
    DefaultApplicationPluginMock plugin;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    auto accountMock = std::make_shared<EdmOsAccountManagerImplMock>();
    ExpectAccountCheck(accountMock, true, plugin);
    BuildSetParcel(data, TYPE_BROWSER, "", ABILITY_NAME, ACCOUNT_ID);

    ErrCode ret = plugin.OnHandlePolicy(EdmInterfaceCode::DEFAULT_APPLICATION, data, reply, policyData, ACCOUNT_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

HWTEST_F(DefaultApplicationPluginTest, TestOnHandlePolicyEmptyAbilityName, TestSize.Level1)
{
    DefaultApplicationPluginMock plugin;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    auto accountMock = std::make_shared<EdmOsAccountManagerImplMock>();
    ExpectAccountCheck(accountMock, true, plugin);
    BuildSetParcel(data, TYPE_BROWSER, BUNDLE_NAME, "", ACCOUNT_ID);

    ErrCode ret = plugin.OnHandlePolicy(EdmInterfaceCode::DEFAULT_APPLICATION, data, reply, policyData, ACCOUNT_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

HWTEST_F(DefaultApplicationPluginTest, TestOnHandlePolicyNegativeAccountId, TestSize.Level1)
{
    DefaultApplicationPluginMock plugin;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    BuildSetParcel(data, TYPE_BROWSER, BUNDLE_NAME, ABILITY_NAME, ACCOUNT_ID_INVALID);

    ErrCode ret = plugin.OnHandlePolicy(EdmInterfaceCode::DEFAULT_APPLICATION, data, reply, policyData, ACCOUNT_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

HWTEST_F(DefaultApplicationPluginTest, TestOnHandlePolicyAccountNotExist, TestSize.Level1)
{
    DefaultApplicationPluginMock plugin;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    auto accountMock = std::make_shared<EdmOsAccountManagerImplMock>();
    ExpectAccountCheck(accountMock, false, plugin);
    BuildSetParcel(data, TYPE_BROWSER, BUNDLE_NAME, ABILITY_NAME, ACCOUNT_ID);

    ErrCode ret = plugin.OnHandlePolicy(EdmInterfaceCode::DEFAULT_APPLICATION, data, reply, policyData, ACCOUNT_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    EXPECT_EQ(plugin.defaultApp_->setCallCount, 0);
}

HWTEST_F(DefaultApplicationPluginTest, TestOnHandlePolicyQueryModuleNameFailed, TestSize.Level1)
{
    DefaultApplicationPluginMock plugin;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    auto accountMock = std::make_shared<EdmOsAccountManagerImplMock>();
    ExpectAccountCheck(accountMock, true, plugin);
    plugin.queryModuleRet = EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    BuildSetParcel(data, TYPE_BROWSER, BUNDLE_NAME, ABILITY_NAME, ACCOUNT_ID);

    ErrCode ret = plugin.OnHandlePolicy(EdmInterfaceCode::DEFAULT_APPLICATION, data, reply, policyData, ACCOUNT_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    EXPECT_EQ(plugin.defaultApp_->setCallCount, 0);
}

HWTEST_F(DefaultApplicationPluginTest, TestOnHandlePolicyDefaultAppProxyNull, TestSize.Level1)
{
    DefaultApplicationPluginMock plugin;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    auto accountMock = std::make_shared<EdmOsAccountManagerImplMock>();
    ExpectAccountCheck(accountMock, true, plugin);
    plugin.defaultApp_ = nullptr;
    BuildSetParcel(data, TYPE_BROWSER, BUNDLE_NAME, ABILITY_NAME, ACCOUNT_ID);

    ErrCode ret = plugin.OnHandlePolicy(EdmInterfaceCode::DEFAULT_APPLICATION, data, reply, policyData, ACCOUNT_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
}

HWTEST_F(DefaultApplicationPluginTest, TestOnHandlePolicySetByBmsFailed, TestSize.Level1)
{
    DefaultApplicationPluginMock plugin;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    auto accountMock = std::make_shared<EdmOsAccountManagerImplMock>();
    ExpectAccountCheck(accountMock, true, plugin);
    plugin.defaultApp_->setRet = ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    BuildSetParcel(data, TYPE_BROWSER, BUNDLE_NAME, ABILITY_NAME, ACCOUNT_ID);

    ErrCode ret = plugin.OnHandlePolicy(EdmInterfaceCode::DEFAULT_APPLICATION, data, reply, policyData, ACCOUNT_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
    EXPECT_EQ(plugin.defaultApp_->getCallCount, 0);
}

HWTEST_F(DefaultApplicationPluginTest, TestOnHandlePolicyReadBackMismatch, TestSize.Level1)
{
    DefaultApplicationPluginMock plugin;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    auto accountMock = std::make_shared<EdmOsAccountManagerImplMock>();
    ExpectAccountCheck(accountMock, true, plugin);
    plugin.defaultApp_->readBackBundleName = "com.example.another";
    BuildSetParcel(data, TYPE_BROWSER, BUNDLE_NAME, ABILITY_NAME, ACCOUNT_ID);

    ErrCode ret = plugin.OnHandlePolicy(EdmInterfaceCode::DEFAULT_APPLICATION, data, reply, policyData, ACCOUNT_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    EXPECT_EQ(plugin.defaultApp_->setCallCount, 1);
    EXPECT_EQ(plugin.defaultApp_->getCallCount, 1);
    EXPECT_EQ(plugin.defaultApp_->lastType, APP_TYPE);
}

HWTEST_F(DefaultApplicationPluginTest, TestOnHandlePolicyReadBackEmptyMeansNotSet, TestSize.Level1)
{
    DefaultApplicationPluginMock plugin;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    auto accountMock = std::make_shared<EdmOsAccountManagerImplMock>();
    ExpectAccountCheck(accountMock, true, plugin);
    plugin.defaultApp_->getRet = ERR_BUNDLE_MANAGER_DEFAULT_APP_NOT_EXIST;
    BuildSetParcel(data, TYPE_BROWSER, BUNDLE_NAME, ABILITY_NAME, ACCOUNT_ID);

    ErrCode ret = plugin.OnHandlePolicy(EdmInterfaceCode::DEFAULT_APPLICATION, data, reply, policyData, ACCOUNT_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

HWTEST_F(DefaultApplicationPluginTest, TestOnHandlePolicyReadBackFailed, TestSize.Level1)
{
    DefaultApplicationPluginMock plugin;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    auto accountMock = std::make_shared<EdmOsAccountManagerImplMock>();
    ExpectAccountCheck(accountMock, true, plugin);
    plugin.defaultApp_->getRet = ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    BuildSetParcel(data, TYPE_BROWSER, BUNDLE_NAME, ABILITY_NAME, ACCOUNT_ID);

    ErrCode ret = plugin.OnHandlePolicy(EdmInterfaceCode::DEFAULT_APPLICATION, data, reply, policyData, ACCOUNT_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
}

HWTEST_F(DefaultApplicationPluginTest, TestOnHandlePolicySuccess, TestSize.Level1)
{
    DefaultApplicationPluginMock plugin;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    auto accountMock = std::make_shared<EdmOsAccountManagerImplMock>();
    ExpectAccountCheck(accountMock, true, plugin);
    plugin.defaultApp_->readBackBundleName = BUNDLE_NAME;
    BuildSetParcel(data, TYPE_BROWSER, BUNDLE_NAME, ABILITY_NAME, ACCOUNT_ID);

    ErrCode ret = plugin.OnHandlePolicy(EdmInterfaceCode::DEFAULT_APPLICATION, data, reply, policyData, ACCOUNT_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(plugin.defaultApp_->setCallCount, 1);
    EXPECT_EQ(plugin.defaultApp_->getCallCount, 1);
    EXPECT_EQ(plugin.defaultApp_->lastUserId, ACCOUNT_ID);
}

HWTEST_F(DefaultApplicationPluginTest, TestOnGetPolicyInvalidType, TestSize.Level1)
{
    DefaultApplicationPluginMock plugin;
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(TYPE_INVALID);
    data.WriteInt32(ACCOUNT_ID);

    std::string policyData;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, ACCOUNT_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    int32_t replyCode = 0;
    EXPECT_TRUE(reply.ReadInt32(replyCode));
    EXPECT_EQ(replyCode, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

HWTEST_F(DefaultApplicationPluginTest, TestOnGetPolicyAccountNotExist, TestSize.Level1)
{
    DefaultApplicationPluginMock plugin;
    MessageParcel data;
    MessageParcel reply;
    auto accountMock = std::make_shared<EdmOsAccountManagerImplMock>();
    ExpectAccountCheck(accountMock, false, plugin);
    data.WriteInt32(TYPE_BROWSER);
    data.WriteInt32(ACCOUNT_ID);

    std::string policyData;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, ACCOUNT_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    EXPECT_EQ(plugin.defaultApp_->getCallCount, 0);
}

HWTEST_F(DefaultApplicationPluginTest, TestOnGetPolicyDefaultAppProxyNull, TestSize.Level1)
{
    DefaultApplicationPluginMock plugin;
    MessageParcel data;
    MessageParcel reply;
    auto accountMock = std::make_shared<EdmOsAccountManagerImplMock>();
    ExpectAccountCheck(accountMock, true, plugin);
    plugin.defaultApp_ = nullptr;
    data.WriteInt32(TYPE_BROWSER);
    data.WriteInt32(ACCOUNT_ID);

    std::string policyData;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, ACCOUNT_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
}

HWTEST_F(DefaultApplicationPluginTest, TestOnGetPolicyNotSetReturnsEmptyName, TestSize.Level1)
{
    DefaultApplicationPluginMock plugin;
    MessageParcel data;
    MessageParcel reply;
    auto accountMock = std::make_shared<EdmOsAccountManagerImplMock>();
    ExpectAccountCheck(accountMock, true, plugin);
    plugin.defaultApp_->getRet = ERR_BUNDLE_MANAGER_DEFAULT_APP_NOT_EXIST;
    data.WriteInt32(TYPE_BROWSER);
    data.WriteInt32(ACCOUNT_ID);

    std::string policyData;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, ACCOUNT_ID);
    EXPECT_EQ(ret, ERR_OK);
    int32_t replyCode = 0;
    EXPECT_TRUE(reply.ReadInt32(replyCode));
    EXPECT_EQ(replyCode, ERR_OK);
    std::string bundleName = reply.ReadString();
    EXPECT_TRUE(bundleName.empty());
}

HWTEST_F(DefaultApplicationPluginTest, TestOnGetPolicyFailedByBms, TestSize.Level1)
{
    DefaultApplicationPluginMock plugin;
    MessageParcel data;
    MessageParcel reply;
    auto accountMock = std::make_shared<EdmOsAccountManagerImplMock>();
    ExpectAccountCheck(accountMock, true, plugin);
    plugin.defaultApp_->getRet = ERR_BUNDLE_MANAGER_INVALID_TYPE;
    data.WriteInt32(TYPE_BROWSER);
    data.WriteInt32(ACCOUNT_ID);

    std::string policyData;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, ACCOUNT_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
}

HWTEST_F(DefaultApplicationPluginTest, TestOnGetPolicySuccess, TestSize.Level1)
{
    DefaultApplicationPluginMock plugin;
    MessageParcel data;
    MessageParcel reply;
    auto accountMock = std::make_shared<EdmOsAccountManagerImplMock>();
    ExpectAccountCheck(accountMock, true, plugin);
    plugin.defaultApp_->readBackBundleName = BUNDLE_NAME;
    data.WriteInt32(TYPE_BROWSER);
    data.WriteInt32(ACCOUNT_ID);

    std::string policyData;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, ACCOUNT_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(plugin.defaultApp_->lastType, APP_TYPE);
    int32_t replyCode = 0;
    EXPECT_TRUE(reply.ReadInt32(replyCode));
    EXPECT_EQ(replyCode, ERR_OK);
    std::string bundleName = reply.ReadString();
    EXPECT_EQ(bundleName, BUNDLE_NAME);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
