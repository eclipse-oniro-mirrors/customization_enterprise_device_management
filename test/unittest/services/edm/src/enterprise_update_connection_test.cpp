/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "enterprise_update_connection.h"
#include "func_code.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string TEST_BUNDLE_NAME = "com.edm.test.demo";
const std::string TEST_ABILITY_NAME = "com.edm.test.demo.Ability";
constexpr int32_t DEFAULT_USER_ID = 100;
class EnterpriseUpdateConnectionTest : public testing::Test {
protected:
    void SetUp() override;

    void TearDown() override;

    std::shared_ptr<EnterpriseUpdateConnection> enterpriseUpdateConnection {nullptr};
    sptr<EnterpriseAdminStubMock> remoteObject {nullptr};
};

void EnterpriseUpdateConnectionTest::SetUp()
{
    remoteObject = new (std::nothrow) EnterpriseAdminStubMock();
}

void EnterpriseUpdateConnectionTest::TearDown()
{
    if (remoteObject != nullptr) {
        delete remoteObject;
        remoteObject = nullptr;
    }
}

/**
 * @tc.name: TestOnAbilityConnectDone
 * @tc.desc: Test EnterpriseUpdateConnection::OnAbilityConnectDone func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseUpdateConnectionTest, TestOnAbilityConnectDone, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(TEST_BUNDLE_NAME);
    admin.SetAbilityName(TEST_ABILITY_NAME);
    UpdateInfo updateInfo;
    AAFwk::Want connectWant;
    connectWant.SetElementName(TEST_BUNDLE_NAME, TEST_ABILITY_NAME);
    int32_t resultCode = 0;
    enterpriseUpdateConnection =
        std::make_shared<EnterpriseUpdateConnection>(connectWant,
        IEnterpriseAdmin::COMMAND_ON_SYSTEM_UPDATE, DEFAULT_USER_ID, updateInfo);
    EXPECT_CALL(*remoteObject, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(remoteObject.GetRefPtr(), &EnterpriseAdminStubMock::InvokeSendRequest));
    enterpriseUpdateConnection->OnAbilityConnectDone(admin, remoteObject, resultCode);
    enterpriseUpdateConnection->OnAbilityDisconnectDone(admin, resultCode);

    EXPECT_TRUE(true);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
