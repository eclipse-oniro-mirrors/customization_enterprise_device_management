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

#include "restrictions_proxy.h"
#include "edm_sys_manager_mock.h"
#include "enterprise_device_mgr_stub_mock.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string ADMIN_PACKAGENAME = "com.edm.test.demo";
class RestrictionsProxyTest : public testing::Test {
protected:
    void SetUp() override;

    void TearDown() override;

    static void TearDownTestSuite(void);
    std::shared_ptr<RestrictionsProxy> proxy_ = nullptr;
    std::shared_ptr<EdmSysManager> edmSysManager_ = nullptr;
    sptr<EnterpriseDeviceMgrStubMock> object_ = nullptr;
};

void RestrictionsProxyTest::SetUp()
{
    proxy_ = RestrictionsProxy::GetRestrictionsProxy();
    edmSysManager_ = std::make_shared<EdmSysManager>();
    object_ = new (std::nothrow) EnterpriseDeviceMgrStubMock();
    edmSysManager_->RegisterSystemAbilityOfRemoteObject(ENTERPRISE_DEVICE_MANAGER_SA_ID, object_);
    Utils::SetEdmServiceEnable();
}

void RestrictionsProxyTest::TearDown()
{
    proxy_.reset();
    edmSysManager_->UnregisterSystemAbilityOfRemoteObject(ENTERPRISE_DEVICE_MANAGER_SA_ID);
    object_ = nullptr;
    Utils::SetEdmServiceDisable();
}

void RestrictionsProxyTest::TearDownTestSuite()
{
    ASSERT_FALSE(Utils::GetEdmServiceState());
    std::cout << "EdmServiceState : " << Utils::GetEdmServiceState() << std::endl;
}

/**
 * @tc.name: TestSetDisallowedPolicySuc
 * @tc.desc: Test SetDisallowedPolicy success func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestSetDisallowedPolicySuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    int32_t ret = proxy_->SetDisallowedPolicy(admin, true, EdmInterfaceCode::DISABLED_HDC);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestSetDisallowedPolicyFail
 * @tc.desc: Test SetDisallowedPolicy without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestSetDisallowedPolicyFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    int32_t ret = proxy_->SetDisallowedPolicy(admin, true, EdmInterfaceCode::DISABLED_HDC);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetDisallowedPolicySuc
 * @tc.desc: Test GetDisallowedPolicy func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestGetDisallowedPolicySuc, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeBoolSendRequestGetPolicy));
    bool result = false;
    int32_t ret = proxy_->GetDisallowedPolicy(&admin, EdmInterfaceCode::DISABLED_HDC, result);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(result);
}

/**
 * @tc.name: TestGetDisallowedPolicyFail
 * @tc.desc: Test GetDisallowedPolicy func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestGetDisallowedPolicyFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    bool result = false;
    int32_t ret = proxy_->GetDisallowedPolicy(&admin, EdmInterfaceCode::DISABLED_HDC, result);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetDisallowedPolicyNullptr
 * @tc.desc: Test GetDisallowedPolicy func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestGetDisallowedPolicyNullptr, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    bool result = false;
    int32_t ret = proxy_->GetDisallowedPolicy(nullptr, EdmInterfaceCode::DISABLED_HDC, result);
    ASSERT_TRUE(ret == ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
