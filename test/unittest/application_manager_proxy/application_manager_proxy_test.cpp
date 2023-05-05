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
#include "application_manager_proxy.h"
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

    std::shared_ptr<ApplicationManagerProxy> applicationManagerProxy_ = nullptr;
};

void ApplicationManagerProxyTest::SetUp()
{
    applicationManagerProxy_ = ApplicationManagerProxy::GetApplicationManagerProxy();
    Utils::SetEdmServiceEnable();
}

void ApplicationManagerProxyTest::TearDown()
{
    applicationManagerProxy_.reset();
    Utils::SetEdmServiceDisable();
}

/**
 * @tc.name: TestAddDisallowedRunningBundles
 * @tc.desc: Test AddDisallowedRunningBundles func.
 * @tc.type: FUNC
 */
HWTEST_F(ApplicationManagerProxyTest, AddDisallowedRunningBundles, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    std::vector<std::string> bundles = {ADMIN_PACKAGENAME};
    ErrCode ret = applicationManagerProxy_->AddDisallowedRunningBundles(admin, bundles, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestRemoveDisallowedRunningBundles
 * @tc.desc: Test RemoveDisallowedRunningBundles func.
 * @tc.type: FUNC
 */
HWTEST_F(ApplicationManagerProxyTest, RemoveDisallowedRunningBundles, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    std::vector<std::string> bundles = {ADMIN_PACKAGENAME};
    ErrCode ret = applicationManagerProxy_->RemoveDisallowedRunningBundles(admin, bundles, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetDisallowedRunningBundles
 * @tc.desc: Test GetDisallowedRunningBundles func.
 * @tc.type: FUNC
 */
HWTEST_F(ApplicationManagerProxyTest, GetDisallowedRunningBundles, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    std::vector<std::string> bundles = {ADMIN_PACKAGENAME};
    ErrCode ret = applicationManagerProxy_->GetDisallowedRunningBundles(admin, DEFAULT_USER_ID, bundles);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
