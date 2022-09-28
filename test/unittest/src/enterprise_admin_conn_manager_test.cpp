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
#define private public
#include "enterprise_admin_conn_manager.h"
#undef private
#include "func_code.h"
#include "policy_info.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
constexpr int32_t DEFAULT_USERID = 100;
class EnterpriseAdminConnManagerTest : public testing::Test {
protected:
    void SetUp() override;

    void TearDown() override;

    std::shared_ptr<EnterpriseAdminConnManager> enterpriseAdminConnManagerTest {nullptr};
};

void EnterpriseAdminConnManagerTest::SetUp()
{
    enterpriseAdminConnManagerTest = std::make_shared<EnterpriseAdminConnManager>();
}
void EnterpriseAdminConnManagerTest::TearDown()
{
}

/**
 * @tc.name: TestConnectAbility
 * @tc.desc: Test ConnectAbility func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseAdminConnManagerTest, TestConnectAbility, TestSize.Level1)
{
    std::string bundleName = "com.edm.test.demo";
    std::string abilityName = "com.edm.test.demo.Ability";

    bool ret = enterpriseAdminConnManagerTest->ConnectAbility(
        bundleName, abilityName, IEnterpriseAdmin::COMMAND_ON_ADMIN_ENABLED, DEFAULT_USERID);
    EXPECT_TRUE(!ret);

    enterpriseAdminConnManagerTest->Clear();
    EXPECT_TRUE(enterpriseAdminConnManagerTest->abilityMgr_ == nullptr);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS