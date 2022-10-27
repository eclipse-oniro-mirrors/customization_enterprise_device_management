/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "cmd_utils.h"
#include "func_code.h"
#include "managed_event.h"
#include "policy_info.h"
#define private public
#include "enterprise_conn_manager.h"
#undef private

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
constexpr int32_t DEFAULT_USERID = 100;
class EnterpriseConnManagerTest : public testing::Test {
protected:
    void SetUp() override;

    void TearDown() override;

    std::shared_ptr<EnterpriseConnManager> enterpriseConnManagerTest {nullptr};
};

void EnterpriseConnManagerTest::SetUp()
{
    enterpriseConnManagerTest = std::make_shared<EnterpriseConnManager>();
}

void EnterpriseConnManagerTest::TearDown()
{
    if (enterpriseConnManagerTest) {
        enterpriseConnManagerTest.reset();
    }
}

/**
 * @tc.name: TestAdminConnectAbility
 * @tc.desc: Test EnterpriseConnManager::CreateAdminConnection func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseConnManagerTest, TestAdminConnectAbility, TestSize.Level1)
{
    std::string bundleName{"com.edm.test.demo"};
    std::string abilityName{"com.edm.test.demo.Ability"};
    AAFwk::Want connectWant;
    connectWant.SetElementName(bundleName, abilityName);
    std::shared_ptr<EnterpriseConnManager> manager = DelayedSingleton<EnterpriseConnManager>::GetInstance();
    sptr<IEnterpriseConnection> connection = manager->CreateAdminConnection(connectWant,
        IEnterpriseAdmin::COMMAND_ON_ADMIN_ENABLED, DEFAULT_USERID);
    bool ret = manager->ConnectAbility(connection);
    EXPECT_TRUE(!ret);

    enterpriseConnManagerTest->Clear();
    EXPECT_TRUE(enterpriseConnManagerTest->abilityMgr_ == nullptr);
}

/**
 * @tc.name: TestBundleConnectAbility
 * @tc.desc: Test EnterpriseConnManager::CreateBundleConnection func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseConnManagerTest, TestBundleConnectAbility, TestSize.Level1)
{
    std::string bundleName{"com.edm.test.demo"};
    std::string abilityName{"com.edm.test.demo.Ability"};
    AAFwk::Want connectWant;
    connectWant.SetElementName(bundleName, abilityName);
    std::shared_ptr<EnterpriseConnManager> manager = DelayedSingleton<EnterpriseConnManager>::GetInstance();
    sptr<IEnterpriseConnection> connection = manager->CreateBundleConnection(connectWant,
        static_cast<uint32_t>(ManagedEvent::BUNDLE_ADDED), DEFAULT_USERID, "com.edm.test.bundle");
    bool ret = manager->ConnectAbility(connection);
    EXPECT_TRUE(!ret);

    ret = manager->ConnectAbility(nullptr);
    EXPECT_TRUE(!ret);

    enterpriseConnManagerTest->Clear();
    EXPECT_TRUE(enterpriseConnManagerTest->abilityMgr_ == nullptr);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS