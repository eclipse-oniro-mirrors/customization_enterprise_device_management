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

#include "bundle_manager_proxy.h"
#include "edm_sys_manager_mock.h"
#include "enterprise_device_mgr_stub_mock.h"
#include "policy_type.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string ADMIN_PACKAGENAME = "com.edm.test.demo";
class BundleManagerProxyTest : public testing::Test {
protected:
    void SetUp() override;

    void TearDown() override;

    static void TearDownTestSuite(void);
    std::shared_ptr<BundleManagerProxy> bundleManagerProxy = nullptr;
    std::shared_ptr<EdmSysManager> edmSysManager_ = nullptr;
    sptr<EnterpriseDeviceMgrStubMock> object_ = nullptr;
};

void BundleManagerProxyTest::SetUp()
{
    bundleManagerProxy = BundleManagerProxy::GetBundleManagerProxy();
    edmSysManager_ = std::make_shared<EdmSysManager>();
    object_ = new (std::nothrow) EnterpriseDeviceMgrStubMock();
    edmSysManager_->RegisterSystemAbilityOfRemoteObject(ENTERPRISE_DEVICE_MANAGER_SA_ID, object_);
    Utils::SetEdmServiceEnable();
}

void BundleManagerProxyTest::TearDown()
{
    bundleManagerProxy.reset();
    edmSysManager_->UnregisterSystemAbilityOfRemoteObject(ENTERPRISE_DEVICE_MANAGER_SA_ID);
    object_ = nullptr;
    Utils::SetEdmServiceDisable();
}

void BundleManagerProxyTest::TearDownTestSuite()
{
    ASSERT_FALSE(Utils::GetEdmServiceState());
    std::cout << "EdmServiceState : " << Utils::GetEdmServiceState() << std::endl;
}

/**
 * @tc.name: TestAddAllowedInstallBundlesSuc
 * @tc.desc: Test AddAllowedInstallBundles success func.
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerProxyTest, AddAllowedInstallBundlesSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    std::vector<std::string> bundles = {ADMIN_PACKAGENAME};
    int32_t policyType = static_cast<int32_t>(PolicyType::ALLOW_INSTALL);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    ErrCode ret = bundleManagerProxy->AddBundlesByPolicyType(admin, bundles, DEFAULT_USER_ID, policyType);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestAddAllowedInstallBundlesFail
 * @tc.desc: Test AddAllowedInstallBundles without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerProxyTest, AddAllowedInstallBundlesFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    std::vector<std::string> bundles = {ADMIN_PACKAGENAME};
    int32_t policyType = static_cast<int32_t>(PolicyType::ALLOW_INSTALL);
    ErrCode ret = bundleManagerProxy->AddBundlesByPolicyType(admin, bundles, DEFAULT_USER_ID, policyType);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestRemoveAllowedInstallBundlesSuc
 * @tc.desc: Test RemoveAllowedInstallBundles success func.
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerProxyTest, RemoveAllowedInstallBundlesSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    std::vector<std::string> bundles = {ADMIN_PACKAGENAME};
    int32_t policyType = static_cast<int32_t>(PolicyType::ALLOW_INSTALL);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    ErrCode ret = bundleManagerProxy->RemoveBundlesByPolicyType(admin, bundles, DEFAULT_USER_ID, policyType);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestRemoveAllowedInstallBundlesFail
 * @tc.desc: Test RemoveAllowedInstallBundles without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerProxyTest, RemoveAllowedInstallBundlesFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    std::vector<std::string> bundles = {ADMIN_PACKAGENAME};
    int32_t policyType = static_cast<int32_t>(PolicyType::ALLOW_INSTALL);
    ErrCode ret = bundleManagerProxy->RemoveBundlesByPolicyType(admin, bundles, DEFAULT_USER_ID, policyType);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetAllowedInstallBundlesSuc
 * @tc.desc: Test GetAllowedInstallBundles success func.
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerProxyTest, GetAllowedInstallBundlesSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    std::vector<std::string> bundles = {ADMIN_PACKAGENAME};
    int32_t policyType = static_cast<int32_t>(PolicyType::ALLOW_INSTALL);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeArrayStringSendRequestGetPolicy));
    ErrCode ret = bundleManagerProxy->GetBundlesByPolicyType(admin, DEFAULT_USER_ID, bundles, policyType);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(bundles.size() == 1);
    ASSERT_TRUE(bundles[0] == RETURN_STRING);
}

/**
 * @tc.name: TestGetAllowedInstallBundlesFail
 * @tc.desc: Test GetAllowedInstallBundles without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerProxyTest, GetAllowedInstallBundlesFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    std::vector<std::string> bundles = {ADMIN_PACKAGENAME};
    int32_t policyType = static_cast<int32_t>(PolicyType::ALLOW_INSTALL);
    ErrCode ret = bundleManagerProxy->GetBundlesByPolicyType(admin, DEFAULT_USER_ID, bundles, policyType);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestAddDisallowedInstallBundlesSuc
 * @tc.desc: Test AddDisallowedInstallBundles success func.
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerProxyTest, AddDisallowedInstallBundlesSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    std::vector<std::string> bundles = {ADMIN_PACKAGENAME};
    int32_t policyType = static_cast<int32_t>(PolicyType::DISALLOW_INSTALL);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    ErrCode ret = bundleManagerProxy->AddBundlesByPolicyType(admin, bundles, DEFAULT_USER_ID, policyType);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestAddDisallowedInstallBundlesFail
 * @tc.desc: Test AddDisallowedInstallBundles without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerProxyTest, AddDisallowedInstallBundlesFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    std::vector<std::string> bundles = {ADMIN_PACKAGENAME};
    int32_t policyType = static_cast<int32_t>(PolicyType::DISALLOW_INSTALL);
    ErrCode ret = bundleManagerProxy->AddBundlesByPolicyType(admin, bundles, DEFAULT_USER_ID, policyType);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestRemoveDisallowedInstallBundlesSuc
 * @tc.desc: Test RemoveDisallowedInstallBundles success func.
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerProxyTest, RemoveDisallowedInstallBundlesSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    std::vector<std::string> bundles = {ADMIN_PACKAGENAME};
    int32_t policyType = static_cast<int32_t>(PolicyType::DISALLOW_INSTALL);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    ErrCode ret = bundleManagerProxy->RemoveBundlesByPolicyType(admin, bundles, DEFAULT_USER_ID, policyType);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestRemoveDisallowedInstallBundlesFail
 * @tc.desc: Test RemoveDisallowedInstallBundles without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerProxyTest, RemoveDisallowedInstallBundlesFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    std::vector<std::string> bundles = {ADMIN_PACKAGENAME};
    int32_t policyType = static_cast<int32_t>(PolicyType::DISALLOW_INSTALL);
    ErrCode ret = bundleManagerProxy->RemoveBundlesByPolicyType(admin, bundles, DEFAULT_USER_ID, policyType);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetDisallowedInstallBundlesSuc
 * @tc.desc: Test GetDisallowedInstallBundles success func.
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerProxyTest, GetDisallowedInstallBundlesSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    std::vector<std::string> bundles = {ADMIN_PACKAGENAME};
    int32_t policyType = static_cast<int32_t>(PolicyType::DISALLOW_INSTALL);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeArrayStringSendRequestGetPolicy));
    ErrCode ret = bundleManagerProxy->GetBundlesByPolicyType(admin, DEFAULT_USER_ID, bundles, policyType);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(bundles.size() == 1);
    ASSERT_TRUE(bundles[0] == RETURN_STRING);
}

/**
 * @tc.name: TestGetDisallowedInstallBundlesFail
 * @tc.desc: Test GetDisallowedInstallBundles without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerProxyTest, GetDisallowedInstallBundlesFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    std::vector<std::string> bundles = {ADMIN_PACKAGENAME};
    int32_t policyType = static_cast<int32_t>(PolicyType::DISALLOW_INSTALL);
    ErrCode ret = bundleManagerProxy->GetBundlesByPolicyType(admin, DEFAULT_USER_ID, bundles, policyType);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
