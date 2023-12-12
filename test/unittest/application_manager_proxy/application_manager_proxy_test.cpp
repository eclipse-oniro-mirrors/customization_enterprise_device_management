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
    OHOS::AppExecFwk::ElementName admin;
    std::vector<OHOS::AppExecFwk::ElementName> apps;
    ErrCode ret = applicationManagerProxy_->AddAutoStartApps(admin, apps);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestAddAutoStartAppsSuc
 * @tc.desc: Test AddAutoStartApps success func.
 * @tc.type: FUNC
 */
HWTEST_F(ApplicationManagerProxyTest, AddAutoStartAppsSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    std::vector<OHOS::AppExecFwk::ElementName> apps;
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    ErrCode ret = applicationManagerProxy_->AddAutoStartApps(admin, apps);
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
    OHOS::AppExecFwk::ElementName admin;
    std::vector<OHOS::AppExecFwk::ElementName> apps;
    ErrCode ret = applicationManagerProxy_->RemoveAutoStartApps(admin, apps);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestRemoveAutoStartAppsSuc
 * @tc.desc: Test RemoveAutoStartApps success func.
 * @tc.type: FUNC
 */
HWTEST_F(ApplicationManagerProxyTest, TestRemoveAutoStartAppsSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    std::vector<OHOS::AppExecFwk::ElementName> apps;
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    ErrCode ret = applicationManagerProxy_->RemoveAutoStartApps(admin, apps);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestGetAutoStartAppsSuc
 * @tc.desc: Test GetAutoStartApps success func.
 * @tc.type: FUNC
 */
HWTEST_F(ApplicationManagerProxyTest, TestGetAutoStartAppsSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    std::vector<OHOS::AppExecFwk::ElementName> apps;
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeArrayElementSendRequestGetPolicy));
    ErrCode ret = applicationManagerProxy_->GetAutoStartApps(admin, apps);
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
    OHOS::AppExecFwk::ElementName admin;
    std::vector<OHOS::AppExecFwk::ElementName> apps;
    ErrCode ret = applicationManagerProxy_->GetAutoStartApps(admin, apps);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
