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
#include <vector>

#include "bundle_manager_proxy.h"
#include "policy_type.h"

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

    std::shared_ptr<BundleManagerProxy> bundleManagerProxy = nullptr;
};

void BundleManagerProxyTest::SetUp()
{
    bundleManagerProxy = BundleManagerProxy::GetBundleManagerProxy();
}

void BundleManagerProxyTest::TearDown()
{
    bundleManagerProxy.reset();
}

/**
 * @tc.name: TestAddAllowedInstallBundles
 * @tc.desc: Test AddAllowedInstallBundles func.
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerProxyTest, AddAllowedInstallBundles, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    std::vector<std::string> bundles = {ADMIN_PACKAGENAME};
    int32_t policyType = static_cast<int32_t>(PolicyType::ALLOW_INSTALL);
    ErrCode ret = bundleManagerProxy->AddBundlesByPolicyType(admin, bundles, DEFAULT_USER_ID, policyType);
    ASSERT_TRUE(ret != ERR_OK);
}

/**
 * @tc.name: TestRemoveAllowedInstallBundles
 * @tc.desc: Test RemoveAllowedInstallBundles func.
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerProxyTest, RemoveAllowedInstallBundles, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    std::vector<std::string> bundles = {ADMIN_PACKAGENAME};
    int32_t policyType = static_cast<int32_t>(PolicyType::ALLOW_INSTALL);
    ErrCode ret = bundleManagerProxy->RemoveBundlesByPolicyType(admin, bundles, DEFAULT_USER_ID, policyType);
    ASSERT_TRUE(ret != ERR_OK);
}

/**
 * @tc.name: TestGetAllowedInstallBundles
 * @tc.desc: Test GetAllowedInstallBundles func.
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerProxyTest, GetAllowedInstallBundles, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    std::vector<std::string> bundles = {ADMIN_PACKAGENAME};
    int32_t policyType = static_cast<int32_t>(PolicyType::ALLOW_INSTALL);
    ErrCode ret = bundleManagerProxy->GetBundlesByPolicyType(admin, DEFAULT_USER_ID, bundles, policyType);
    ASSERT_TRUE(ret != ERR_OK);
}

/**
 * @tc.name: TestAddDisallowedInstallBundles
 * @tc.desc: Test AddDisallowedInstallBundles func.
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerProxyTest, AddDisallowedInstallBundles, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    std::vector<std::string> bundles = {ADMIN_PACKAGENAME};
    int32_t policyType = static_cast<int32_t>(PolicyType::DISALLOW_INSTALL);
    ErrCode ret = bundleManagerProxy->AddBundlesByPolicyType(admin, bundles, DEFAULT_USER_ID, policyType);
    ASSERT_TRUE(ret != ERR_OK);
}

/**
 * @tc.name: TestRemoveDisallowedInstallBundles
 * @tc.desc: Test RemoveDisallowedInstallBundles func.
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerProxyTest, RemoveDisallowedInstallBundles, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    std::vector<std::string> bundles = {ADMIN_PACKAGENAME};
    int32_t policyType = static_cast<int32_t>(PolicyType::DISALLOW_INSTALL);
    ErrCode ret = bundleManagerProxy->RemoveBundlesByPolicyType(admin, bundles, DEFAULT_USER_ID, policyType);
    ASSERT_TRUE(ret != ERR_OK);
}

/**
 * @tc.name: TestGetDisallowedInstallBundles
 * @tc.desc: Test GetDisallowedInstallBundles func.
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerProxyTest, GetDisallowedInstallBundles, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    std::vector<std::string> bundles = {ADMIN_PACKAGENAME};
    int32_t policyType = static_cast<int32_t>(PolicyType::DISALLOW_INSTALL);
    ErrCode ret = bundleManagerProxy->GetBundlesByPolicyType(admin, DEFAULT_USER_ID, bundles, policyType);
    ASSERT_TRUE(ret != ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
