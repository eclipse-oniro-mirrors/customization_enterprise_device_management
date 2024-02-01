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

#include "browser_proxy.h"
#include "bundle_mgr_host.h"
#include "edm_sys_manager_mock.h"
#include "enterprise_device_mgr_stub_mock.h"
#include "iservice_registry.h"
#include "utils.h"
#include "edm_log.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string TEST_APP_ID = "test_app_id";
const std::string TEST_POLICIES = "test_policies";
class BrowserProxyTest : public testing::Test {
protected:
    void SetUp() override;

    void TearDown() override;

    static void TearDownTestSuite(void);
    std::shared_ptr<BrowserProxy> browserProxy_ = nullptr;
    std::shared_ptr<EdmSysManager> edmSysManager_ = nullptr;
    sptr<EnterpriseDeviceMgrStubMock> object_ = nullptr;
    sptr<AppExecFwk::BundleMgrHost> bundleManager_ = nullptr;
};

void BrowserProxyTest::SetUp()
{
    browserProxy_ = BrowserProxy::GetBrowserProxy();
    edmSysManager_ = std::make_shared<EdmSysManager>();
    object_ = new (std::nothrow) EnterpriseDeviceMgrStubMock();
    edmSysManager_->RegisterSystemAbilityOfRemoteObject(ENTERPRISE_DEVICE_MANAGER_SA_ID, object_);

    bundleManager_ = new (std::nothrow) AppExecFwk::BundleMgrHost();
    edmSysManager_->RegisterSystemAbilityOfRemoteObject(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID, bundleManager_);
    Utils::SetEdmServiceEnable();
}

void BrowserProxyTest::TearDown()
{
    browserProxy_.reset();
    edmSysManager_->UnregisterSystemAbilityOfRemoteObject(ENTERPRISE_DEVICE_MANAGER_SA_ID);
    edmSysManager_->UnregisterSystemAbilityOfRemoteObject(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    object_ = nullptr;
    bundleManager_ = nullptr;
    Utils::SetEdmServiceDisable();
}

void BrowserProxyTest::TearDownTestSuite()
{
    ASSERT_FALSE(Utils::GetEdmServiceState());
    std::cout << "EdmServiceState : " << Utils::GetEdmServiceState() << std::endl;
}

/**
 * @tc.name: TestSetPoliciesSuc
 * @tc.desc: Test SetPolicies success func.
 * @tc.type: FUNC
 */
HWTEST_F(BrowserProxyTest, TestSetPoliciesSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    ErrCode ret = browserProxy_->SetPolicies(admin, TEST_APP_ID, TEST_POLICIES);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestSetPoliciesFail
 * @tc.desc: Test SetPolicies without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(BrowserProxyTest, TestSetPoliciesFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    ErrCode ret = browserProxy_->SetPolicies(admin, TEST_APP_ID, TEST_POLICIES);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestSetPoliciesParamError
 * @tc.desc: Test SetPolicies with empty appId.
 * @tc.type: FUNC
 */
HWTEST_F(BrowserProxyTest, TestSetPoliciesParamError, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    ErrCode ret = browserProxy_->SetPolicies(admin, "", TEST_POLICIES);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestGetPoliciesWithThreeParamsSuc
 * @tc.desc: Test GetPolicies with three parameters success func.
 * @tc.type: FUNC
 */
HWTEST_F(BrowserProxyTest, TestGetPoliciesWithThreeParamsSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestGetPolicy));
    std::string policies;
    ErrCode ret = browserProxy_->GetPolicies(admin, TEST_APP_ID, policies);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(policies == RETURN_STRING);
}

/**
 * @tc.name: TestGetPoliciesWithThreeParamsFail
 * @tc.desc: Test GetPolicies with three parameters without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(BrowserProxyTest, TestGetPoliciesWithThreeParamsFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    std::string policies;
    ErrCode ret = browserProxy_->GetPolicies(admin, TEST_APP_ID, policies);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetPoliciesWithTwoParamsSuc
 * @tc.desc: Test GetPolicies with two parameters success func.
 * @tc.type: FUNC
 */
HWTEST_F(BrowserProxyTest, TestGetPoliciesWithTwoParamSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestGetPolicy));
    std::string policies;
    ErrCode ret = browserProxy_->GetPolicies(policies);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(policies == RETURN_STRING);
}

/**
 * @tc.name: TestGetPoliciesWithTwoParamsFail
 * @tc.desc: Test GetPolicies with two parameters without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(BrowserProxyTest, TestGetPoliciesWithTwoParamsFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    std::string policies;
    ErrCode ret = browserProxy_->GetPolicies(policies);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(policies.empty());
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
