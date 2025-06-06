/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "admin_manager.h"
#include "enterprise_kiosk_connection.h"
#include "enterprise_admin_stub_mock.h"
#include "func_code.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
constexpr int32_t DEFAULT_USER_ID = 100;
class EnterpriseKioskConnectionTest : public testing::Test {
protected:
    void SetUp() override;

    void TearDown() override {}

    std::shared_ptr<EnterpriseKioskConnection> enterpriseKioskConnection {nullptr};
    sptr<EnterpriseAdminStubMock> remoteObject {nullptr};
};

void EnterpriseKioskConnectionTest::SetUp()
{
    remoteObject = new (std::nothrow) EnterpriseAdminStubMock();
}

/**
 * @tc.name: TestOnAbilityConnectDone01
 * @tc.desc: Test EnterpriseKioskConnectionTest::OnAbilityConnectDone func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseKioskConnectionTest, TestOnAbilityConnectDone01, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo");
    admin.SetAbilityName("com.edm.test.demo.Ability");
    AAFwk::Want connectWant;
    connectWant.SetElementName("com.edm.test.demo", "com.edm.test.demo.Ability");
    int32_t resultCode = 0;
    enterpriseKioskConnection =
        std::make_shared<EnterpriseKioskConnection>(connectWant,
        IEnterpriseAdmin::COMMAND_ON_KIOSK_MODE_ENTERING, DEFAULT_USER_ID, "com.edm.test.demo", DEFAULT_USER_ID);
    EXPECT_CALL(*remoteObject, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(remoteObject.GetRefPtr(), &EnterpriseAdminStubMock::InvokeSendRequest));
    enterpriseKioskConnection->OnAbilityConnectDone(admin, remoteObject, resultCode);
    enterpriseKioskConnection->OnAbilityDisconnectDone(admin, resultCode);

    EXPECT_TRUE(remoteObject->code_ == IEnterpriseAdmin::COMMAND_ON_KIOSK_MODE_ENTERING);
}

/**
 * @tc.name: TestOnAbilityConnectDone02
 * @tc.desc: Test EnterpriseKioskConnectionTest::OnAbilityConnectDone func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseKioskConnectionTest, TestOnAbilityConnectDone02, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo");
    admin.SetAbilityName("com.edm.test.demo.Ability");
    AAFwk::Want connectWant;
    connectWant.SetElementName("com.edm.test.demo", "com.edm.test.demo.Ability");
    int32_t resultCode = 0;
    enterpriseKioskConnection =
    std::make_shared<EnterpriseKioskConnection>(connectWant,
        IEnterpriseAdmin::COMMAND_ON_KIOSK_MODE_EXITING, DEFAULT_USER_ID, "com.edm.test.demo", DEFAULT_USER_ID);
    EXPECT_CALL(*remoteObject, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(remoteObject.GetRefPtr(), &EnterpriseAdminStubMock::InvokeSendRequest));
    enterpriseKioskConnection->OnAbilityConnectDone(admin, remoteObject, resultCode);
    enterpriseKioskConnection->OnAbilityDisconnectDone(admin, resultCode);

    EXPECT_TRUE(remoteObject->code_ == IEnterpriseAdmin::COMMAND_ON_KIOSK_MODE_EXITING);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS