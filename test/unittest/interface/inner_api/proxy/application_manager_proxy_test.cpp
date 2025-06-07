/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include <vector>

#include "application_manager_proxy.h"
#include "edm_sys_manager_mock.h"
#include "enterprise_device_mgr_stub_mock.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string ADMIN_PACKAGENAME = "com.edm.test.demo";
class ApplicationManagerProxyTest : public testing::Test {
protected:
    void SetUp() override;

    void TearDown() override;

    static void TearDownTestSuite(void);
    std::shared_ptr<ApplicationManagerProxy> applicationManagerProxy_ = nullptr;
    std::shared_ptr<EdmSysManager> edmSysManager_ = nullptr;
    sptr<EnterpriseDeviceMgrStubMock> object_ = nullptr;
};

void ApplicationManagerProxyTest::SetUp()
{
    applicationManagerProxy_ = ApplicationManagerProxy::GetApplicationManagerProxy();
    edmSysManager_ = std::make_shared<EdmSysManager>();
    object_ = new (std::nothrow) EnterpriseDeviceMgrStubMock();
    edmSysManager_->RegisterSystemAbilityOfRemoteObject(ENTERPRISE_DEVICE_MANAGER_SA_ID, object_);
    Utils::SetEdmServiceEnable();
}

void ApplicationManagerProxyTest::TearDown()
{
    applicationManagerProxy_.reset();
    edmSysManager_->UnregisterSystemAbilityOfRemoteObject(ENTERPRISE_DEVICE_MANAGER_SA_ID);
    object_ = nullptr;
    Utils::SetEdmServiceDisable();
}

void ApplicationManagerProxyTest::TearDownTestSuite()
{
    ASSERT_FALSE(Utils::GetEdmServiceState());
    std::cout << "EdmServiceState : " << Utils::GetEdmServiceState() << std::endl;
}

/**
 * @tc.name: TestAddDisallowedRunningBundlesSuc
 * @tc.desc: Test AddDisallowedRunningBundles success func.
 * @tc.type: FUNC
 */
HWTEST_F(ApplicationManagerProxyTest, AddDisallowedRunningBundlesSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    std::vector<std::string> bundles = {ADMIN_PACKAGENAME};
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    ErrCode ret = applicationManagerProxy_->AddDisallowedRunningBundles(admin, bundles, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestAddDisallowedRunningBundlesFail
 * @tc.desc: Test AddDisallowedRunningBundles without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(ApplicationManagerProxyTest, AddDisallowedRunningBundles, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    std::vector<std::string> bundles = {ADMIN_PACKAGENAME};
    ErrCode ret = applicationManagerProxy_->AddDisallowedRunningBundles(admin, bundles, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestRemoveDisallowedRunningBundlesSuc
 * @tc.desc: Test RemoveDisallowedRunningBundles success func.
 * @tc.type: FUNC
 */
HWTEST_F(ApplicationManagerProxyTest, RemoveDisallowedRunningBundlesSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    std::vector<std::string> bundles = {ADMIN_PACKAGENAME};
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    ErrCode ret = applicationManagerProxy_->RemoveDisallowedRunningBundles(admin, bundles, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestRemoveDisallowedRunningBundlesFail
 * @tc.desc: Test RemoveDisallowedRunningBundles without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(ApplicationManagerProxyTest, RemoveDisallowedRunningBundlesFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    std::vector<std::string> bundles = {ADMIN_PACKAGENAME};
    ErrCode ret = applicationManagerProxy_->RemoveDisallowedRunningBundles(admin, bundles, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetDisallowedRunningBundlesSuc
 * @tc.desc: Test GetDisallowedRunningBundles success func.
 * @tc.type: FUNC
 */
HWTEST_F(ApplicationManagerProxyTest, GetDisallowedRunningBundlesSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    std::vector<std::string> bundles = {ADMIN_PACKAGENAME};
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeArrayStringSendRequestGetPolicy));
    ErrCode ret = applicationManagerProxy_->GetDisallowedRunningBundles(admin, DEFAULT_USER_ID, bundles);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(bundles.size() == 1);
    ASSERT_TRUE(bundles[0] == RETURN_STRING);
}

/**
 * @tc.name: TestGetDisallowedRunningBundlesFail
 * @tc.desc: Test GetDisallowedRunningBundles without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(ApplicationManagerProxyTest, GetDisallowedRunningBundlesFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    std::vector<std::string> bundles = {ADMIN_PACKAGENAME};
    ErrCode ret = applicationManagerProxy_->GetDisallowedRunningBundles(admin, DEFAULT_USER_ID, bundles);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestAddAutoStartAppsFail
 * @tc.desc: Test AddAutoStartApps without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(ApplicationManagerProxyTest, TestAddAutoStartAppsFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    std::vector<std::string> apps;
    data.WriteParcelable(&admin);
    data.WriteStringVector(apps);

    ErrCode ret = applicationManagerProxy_->AddOrRemoveAutoStartApps(data, true);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestAddAutoStartAppsSuc
 * @tc.desc: Test AddAutoStartApps success func.
 * @tc.type: FUNC
 */
HWTEST_F(ApplicationManagerProxyTest, AddAutoStartAppsSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    std::vector<std::string> apps;
    data.WriteParcelable(&admin);
    data.WriteStringVector(apps);

    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    ErrCode ret = applicationManagerProxy_->AddOrRemoveAutoStartApps(data, true);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestRemoveAutoStartAppsFail
 * @tc.desc: Test RemoveAutoStartApps without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(ApplicationManagerProxyTest, TestRemoveAutoStartAppsFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    std::vector<std::string> apps;
    data.WriteParcelable(&admin);
    data.WriteStringVector(apps);

    ErrCode ret = applicationManagerProxy_->AddOrRemoveAutoStartApps(data, false);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestRemoveAutoStartAppsSuc
 * @tc.desc: Test RemoveAutoStartApps success func.
 * @tc.type: FUNC
 */
HWTEST_F(ApplicationManagerProxyTest, TestRemoveAutoStartAppsSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    std::vector<std::string> apps;
    data.WriteParcelable(&admin);
    data.WriteStringVector(apps);
    
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    ErrCode ret = applicationManagerProxy_->AddOrRemoveAutoStartApps(data, false);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestGetAutoStartAppsSuc
 * @tc.desc: Test GetAutoStartApps success func.
 * @tc.type: FUNC
 */
HWTEST_F(ApplicationManagerProxyTest, TestGetAutoStartAppsSuc, TestSize.Level1)
{
    MessageParcel data;
    std::vector<OHOS::AppExecFwk::ElementName> apps;
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeArrayElementSendRequestGetPolicy));
    ErrCode ret = applicationManagerProxy_->GetAutoStartApps(data, apps);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(apps.size() == 1);
}

/**
 * @tc.name: TestGetAutoStartAppsFail
 * @tc.desc: Test GetAutoStartApps without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(ApplicationManagerProxyTest, TestGetAutoStartAppsFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    std::vector<OHOS::AppExecFwk::ElementName> apps;
    ErrCode ret = applicationManagerProxy_->GetAutoStartApps(data, apps);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestAddKeepAliveAppsFail
 * @tc.desc: Test AddKeepAliveApps without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(ApplicationManagerProxyTest, TestAddKeepAliveAppsFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    std::vector<std::string> keepAliveApps;
    std::string retMessage;
    ErrCode ret = applicationManagerProxy_->AddKeepAliveApps(admin, keepAliveApps, DEFAULT_USER_ID, retMessage);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestAddKeepAliveAppsSuc
 * @tc.desc: Test AddKeepAliveApps success func.
 * @tc.type: FUNC
 */
HWTEST_F(ApplicationManagerProxyTest, TestAddKeepAliveAppsSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    std::vector<std::string> keepAliveApps;
    std::string retMessage;
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    ErrCode ret = applicationManagerProxy_->AddKeepAliveApps(admin, keepAliveApps, DEFAULT_USER_ID, retMessage);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestRemoveKeepAliveAppsFail
 * @tc.desc: Test RemoveKeepAliveApps without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(ApplicationManagerProxyTest, TestRemoveKeepAliveAppsFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    std::vector<std::string> keepAliveApps;
    ErrCode ret = applicationManagerProxy_->RemoveKeepAliveApps(admin, keepAliveApps, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestRemoveKeepAliveAppsSuc
 * @tc.desc: Test RemoveKeepAliveApps success func.
 * @tc.type: FUNC
 */
HWTEST_F(ApplicationManagerProxyTest, TestRemoveKeepAliveAppsSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    std::vector<std::string> keepAliveApps;
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    ErrCode ret = applicationManagerProxy_->RemoveKeepAliveApps(admin, keepAliveApps, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestGetKeepAliveAppsFail
 * @tc.desc: Test GetKeepAliveApps without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(ApplicationManagerProxyTest, TestGetKeepAliveAppsFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    std::vector<std::string> keepAliveApps;
    ErrCode ret = applicationManagerProxy_->GetKeepAliveApps(admin, keepAliveApps, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetKeepAliveAppsSuc
 * @tc.desc: Test GetKeepAliveApps success func.
 * @tc.type: FUNC
 */
HWTEST_F(ApplicationManagerProxyTest, TestGetKeepAliveAppsSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    std::vector<std::string> keepAliveApps;
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeArrayStringSendRequestGetPolicy));
    ErrCode ret = applicationManagerProxy_->GetKeepAliveApps(admin, keepAliveApps, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(keepAliveApps.size() == 1);
}

/**
 * @tc.name: TestClearUpApplicationDataFail
 * @tc.desc: Test ClearUpApplicationData without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(ApplicationManagerProxyTest, TestClearUpApplicationDataFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    ClearUpApplicationDataParam param { ADMIN_PACKAGENAME, 0, 0 };
    int32_t ret = applicationManagerProxy_->ClearUpApplicationData(admin, param);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestSetKioskFeaturesFail
 * @tc.desc: Test SetKioskFeatures without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(ApplicationManagerProxyTest, TestSetKioskFeaturesFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    std::vector<int32_t> apps;
    data.WriteParcelable(&admin);
    data.WriteInt32Vector(apps);

    ErrCode ret = applicationManagerProxy_->SetKioskFeatures(data);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestSetKioskFeaturesSuc
 * @tc.desc: Test SetKioskFeatures success func.
 * @tc.type: FUNC
 */
HWTEST_F(ApplicationManagerProxyTest, TestSetKioskFeaturesSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    std::vector<int32_t> apps;
    data.WriteParcelable(&admin);
    data.WriteInt32Vector(apps);

    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    ErrCode ret = applicationManagerProxy_->SetKioskFeatures(data);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestClearUpApplicationDataSuc
 * @tc.desc: Test ClearUpApplicationData success func.
 * @tc.type: FUNC
 */
HWTEST_F(ApplicationManagerProxyTest, TestClearUpApplicationDataSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    ClearUpApplicationDataParam param { ADMIN_PACKAGENAME, 0, 0 };
    int32_t ret = applicationManagerProxy_->ClearUpApplicationData(admin, param);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestSetAllowedKioskAppsFail
 * @tc.desc: Test SetAllowedKioskApps without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(ApplicationManagerProxyTest, TestSetAllowedKioskAppsFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    std::vector<std::string> bundleNames;
    int32_t ret = applicationManagerProxy_->SetAllowedKioskApps(admin, bundleNames);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestSetAllowedKioskAppsSuc
 * @tc.desc: Test SetAllowedKioskApps success func.
 * @tc.type: FUNC
 */
HWTEST_F(ApplicationManagerProxyTest, TestSetAllowedKioskAppsSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    std::vector<std::string> bundleNames;
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    int32_t ret = applicationManagerProxy_->SetAllowedKioskApps(admin, bundleNames);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestGetAllowedKioskAppsFail
 * @tc.desc: Test GetAllowedKioskApps without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(ApplicationManagerProxyTest, TestGetAllowedKioskAppsFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    std::vector<std::string> bundleNames;
    int32_t ret = applicationManagerProxy_->GetAllowedKioskApps(admin, bundleNames);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetAllowedKioskAppsSuc
 * @tc.desc: Test GetAllowedKioskApps success func.
 * @tc.type: FUNC
 */
HWTEST_F(ApplicationManagerProxyTest, TestGetAllowedKioskAppsSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    std::vector<std::string> bundleNames;
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    int32_t ret = applicationManagerProxy_->GetAllowedKioskApps(admin, bundleNames);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestIsAppKioskAllowedFail
 * @tc.desc: Test IsAppKioskAllowed without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(ApplicationManagerProxyTest, TestIsAppKioskAllowedFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    std::string bundleName;
    bool isAllowed = false;
    int32_t ret = applicationManagerProxy_->IsAppKioskAllowed(bundleName, isAllowed);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(!isAllowed);
}

/**
 * @tc.name: TestIsAppKioskAllowedSuc
 * @tc.desc: Test IsAppKioskAllowed success func.
 * @tc.type: FUNC
 */
HWTEST_F(ApplicationManagerProxyTest, TestIsAppKioskAllowedSuc, TestSize.Level1)
{
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    std::string bundleName;
    bool isAllowed = false;
    int32_t ret = applicationManagerProxy_->IsAppKioskAllowed(bundleName, isAllowed);
    ASSERT_TRUE(ret == ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
