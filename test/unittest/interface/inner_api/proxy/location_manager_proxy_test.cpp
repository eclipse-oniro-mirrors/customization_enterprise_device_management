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

#include "edm_sys_manager_mock.h"
#include "enterprise_device_mgr_stub_mock.h"
#include "location_manager_proxy.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string ADMIN_PACKAGENAME = "com.edm.test.demo";
class LocationManagerProxyTest : public testing::Test {
protected:
    void SetUp() override;

    void TearDown() override;

    static void TearDownTestSuite(void);
    std::shared_ptr<LocationManagerProxy> proxy_ = nullptr;
    std::shared_ptr<EdmSysManager> edmSysManager_ = nullptr;
    sptr<EnterpriseDeviceMgrStubMock> object_ = nullptr;
};

void LocationManagerProxyTest::SetUp()
{
    proxy_ = LocationManagerProxy::GetLocationManagerProxy();
    edmSysManager_ = std::make_shared<EdmSysManager>();
    object_ = new (std::nothrow) EnterpriseDeviceMgrStubMock();
    edmSysManager_->RegisterSystemAbilityOfRemoteObject(ENTERPRISE_DEVICE_MANAGER_SA_ID, object_);
    Utils::SetEdmServiceEnable();
}

void LocationManagerProxyTest::TearDown()
{
    proxy_.reset();
    edmSysManager_->UnregisterSystemAbilityOfRemoteObject(ENTERPRISE_DEVICE_MANAGER_SA_ID);
    object_ = nullptr;
    Utils::SetEdmServiceDisable();
}

void LocationManagerProxyTest::TearDownTestSuite()
{
    ASSERT_FALSE(Utils::GetEdmServiceState());
    std::cout << "EdmServiceState : " << Utils::GetEdmServiceState() << std::endl;
}

/**
 * @tc.name: TestSetLocationPolicySuc
 * @tc.desc: Test SetLocationPolicy func.
 * @tc.type: FUNC
 */
HWTEST_F(LocationManagerProxyTest, TestSetLocationPolicySuc, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    LocationPolicy locationPolicy = LocationPolicy::DISALLOW_LOCATION_SERVICE;
    int32_t ret = proxy_->SetLocationPolicy(admin, locationPolicy);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestSetLocationPolicyFail
 * @tc.desc: Test SetLocationPolicy func.
 * @tc.type: FUNC
 */
HWTEST_F(LocationManagerProxyTest, TestSetLocationPolicyFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    LocationPolicy locationPolicy = LocationPolicy::DISALLOW_LOCATION_SERVICE;
    int32_t ret = proxy_->SetLocationPolicy(admin, locationPolicy);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetLocationPolicySuc
 * @tc.desc: Test GetLocationPolicy success func.
 * @tc.type: FUNC
 */
HWTEST_F(LocationManagerProxyTest, TestGetLocationPolicySuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeIntSendRequestGetPolicy));
    LocationPolicy locationPolicy;
    int32_t ret = proxy_->GetLocationPolicy(&admin, locationPolicy);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(locationPolicy == LocationPolicy::DEFAULT_LOCATION_SERVICE);
}

/**
 * @tc.name: TestGetLocationPolicyFail
 * @tc.desc: Test GetLocationPolicy without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(LocationManagerProxyTest, TestGetLocationPolicyFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    LocationPolicy locationPolicy;
    int32_t ret = proxy_->GetLocationPolicy(&admin, locationPolicy);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
