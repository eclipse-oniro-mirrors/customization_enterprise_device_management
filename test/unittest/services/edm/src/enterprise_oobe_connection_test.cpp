/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "enterprise_admin_stub_mock.h"
#include "enterprise_oobe_connection.h"
#include "func_code.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string TEST_BUNDLE_NAME = "com.edm.test.demo";
const std::string TEST_ABILITY_NAME = "com.edm.test.demo.Ability";
constexpr int32_t DEFAULT_USER_ID = 100;
class EnterpriseOobeConnectionTest : public testing::Test {
protected:
    void SetUp() override;

    std::shared_ptr<EnterpriseOobeConnection> enterpriseOobeConnection {nullptr};
    sptr<EnterpriseAdminStubMock> remoteObject {nullptr};
};

void EnterpriseOobeConnectionTest::SetUp()
{
    remoteObject = new (std::nothrow) EnterpriseAdminStubMock();
}

/**
 * @tc.name: TestOnAbilityConnectDone
 * @tc.desc: Test EnterpriseOobeConnection::OnAbilityConnectDone func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseOobeConnectionTest, TestOnAbilityConnectDone_001, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(TEST_BUNDLE_NAME);
    admin.SetAbilityName(TEST_ABILITY_NAME);
    AAFwk::Want connectWant;
    connectWant.SetElementName(TEST_BUNDLE_NAME, TEST_ABILITY_NAME);
    int32_t resultCode = 0;
    enterpriseOobeConnection =
        std::make_shared<EnterpriseOobeConnection>(connectWant,
        IEnterpriseAdmin::COMMAND_ON_STARTUP_GUIDE_COMPLETED, DEFAULT_USER_ID, 0);
    EXPECT_CALL(*remoteObject, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(remoteObject.GetRefPtr(), &EnterpriseAdminStubMock::InvokeSendRequest));
    enterpriseOobeConnection->OnAbilityConnectDone(admin, remoteObject, resultCode);
    enterpriseOobeConnection->OnAbilityDisconnectDone(admin, resultCode);

    EXPECT_TRUE(resultCode == 0);
}

/**
 * @tc.name: TestOnAbilityConnectDone
 * @tc.desc: Test EnterpriseOobeConnection::OnAbilityConnectDone func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseOobeConnectionTest, TestOnAbilityConnectDone_002, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(TEST_BUNDLE_NAME);
    admin.SetAbilityName(TEST_ABILITY_NAME);
    AAFwk::Want connectWant;
    connectWant.SetElementName(TEST_BUNDLE_NAME, TEST_ABILITY_NAME);
    int32_t resultCode = 0;
    enterpriseOobeConnection =
        std::make_shared<EnterpriseOobeConnection>(connectWant,
        IEnterpriseAdmin::COMMAND_ON_DEVICE_BOOT_COMPLETED, DEFAULT_USER_ID, -1);
    EXPECT_CALL(*remoteObject, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(remoteObject.GetRefPtr(), &EnterpriseAdminStubMock::InvokeSendRequest));
    enterpriseOobeConnection->OnAbilityConnectDone(admin, remoteObject, resultCode);
    enterpriseOobeConnection->OnAbilityDisconnectDone(admin, resultCode);

    EXPECT_TRUE(resultCode == 0);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
