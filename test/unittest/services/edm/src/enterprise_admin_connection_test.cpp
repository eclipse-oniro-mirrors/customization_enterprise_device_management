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
#include "enterprise_admin_connection.h"
#include "enterprise_admin_stub_mock.h"
#include "func_code.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
constexpr uint32_t COMMAND_ON_ADMIN_CODE = 3;
constexpr int32_t DEFAULT_USER_ID = 100;

class EnterpriseAdminConnectionTest : public testing::Test {
protected:
    void SetUp() override;

    void TearDown() override {}

    std::shared_ptr<EnterpriseAdminConnection> enterpriseAdminConnectionTest {nullptr};
    sptr<EnterpriseAdminStubMock> remoteObject {nullptr};
};

void EnterpriseAdminConnectionTest::SetUp()
{
    remoteObject = new (std::nothrow) EnterpriseAdminStubMock();
}

/**
 * @tc.name: TestOnAbilityConnectDone01
 * @tc.desc: Test EnterpriseAdminConnection::OnAbilityConnectDone func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseAdminConnectionTest, TestOnAbilityConnectDone01, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo");
    admin.SetAbilityName("com.edm.test.demo.Ability");
    AAFwk::Want connectWant;
    connectWant.SetElementName("com.edm.test.demo", "com.edm.test.demo.Ability");
    int32_t resultCode = 0;
    enterpriseAdminConnectionTest =
        std::make_shared<EnterpriseAdminConnection>(connectWant,
        IEnterpriseAdmin::COMMAND_ON_ADMIN_ENABLED, DEFAULT_USER_ID, true);
    EXPECT_CALL(*remoteObject, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(remoteObject.GetRefPtr(), &EnterpriseAdminStubMock::InvokeSendRequest));
    enterpriseAdminConnectionTest->OnAbilityConnectDone(admin, remoteObject, resultCode);
    enterpriseAdminConnectionTest->OnAbilityDisconnectDone(admin, resultCode);

    EXPECT_TRUE(remoteObject->code_ == IEnterpriseAdmin::COMMAND_ON_ADMIN_ENABLED);
}

/**
 * @tc.name: TestOnAbilityConnectDone02
 * @tc.desc: Test EnterpriseAdminConnection::OnAbilityConnectDone func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseAdminConnectionTest, TestOnAbilityConnectDone02, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo");
    admin.SetAbilityName("com.edm.test.demo.Ability");
    AAFwk::Want connectWant;
    connectWant.SetElementName("com.edm.test.demo", "com.edm.test.demo.Ability");
    int32_t resultCode = 0;
    enterpriseAdminConnectionTest =
        std::make_shared<EnterpriseAdminConnection>(connectWant,
        IEnterpriseAdmin::COMMAND_ON_ADMIN_DISABLED, DEFAULT_USER_ID, true);
    EXPECT_CALL(*remoteObject, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(remoteObject.GetRefPtr(), &EnterpriseAdminStubMock::InvokeSendRequest));
    enterpriseAdminConnectionTest->OnAbilityConnectDone(admin, remoteObject, resultCode);
    enterpriseAdminConnectionTest->OnAbilityDisconnectDone(admin, resultCode);

    EXPECT_TRUE(remoteObject->code_ == IEnterpriseAdmin::COMMAND_ON_ADMIN_DISABLED);
}


/**
 * @tc.name: TestOnAbilityConnectDone03
 * @tc.desc: Test EnterpriseAdminConnection::OnAbilityConnectDone func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseAdminConnectionTest, TestOnAbilityConnectDone03, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo");
    admin.SetAbilityName("com.edm.test.demo.Ability");
    AAFwk::Want connectWant;
    connectWant.SetElementName("com.edm.test.demo", "com.edm.test.demo.Ability");
    int32_t resultCode = 0;
    enterpriseAdminConnectionTest = std::make_shared<EnterpriseAdminConnection>(connectWant,
        COMMAND_ON_ADMIN_CODE, DEFAULT_USER_ID, true);
    enterpriseAdminConnectionTest->OnAbilityConnectDone(admin, remoteObject, resultCode);
    enterpriseAdminConnectionTest->OnAbilityDisconnectDone(admin, resultCode);

    EXPECT_TRUE(remoteObject->code_ != IEnterpriseAdmin::COMMAND_ON_ADMIN_DISABLED);
}

/**
 * @tc.name: TestOnAbilityConnectDoneWithoutAdminEnabled
 * @tc.desc: Test EnterpriseAdminConnection::OnAbilityConnectDone func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseAdminConnectionTest, TestOnAbilityConnectDoneWithoutAdminEnabled, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo");
    admin.SetAbilityName("com.edm.test.demo.Ability");
    AAFwk::Want connectWant;
    connectWant.SetElementName("com.edm.test.demo", "com.edm.test.demo.Ability");
    int32_t resultCode = 0;
    enterpriseAdminConnectionTest = std::make_shared<EnterpriseAdminConnection>(connectWant,
        IEnterpriseAdmin::COMMAND_ON_ADMIN_ENABLED, DEFAULT_USER_ID, true);
    enterpriseAdminConnectionTest->SetIsOnAdminEnabled(false);
    enterpriseAdminConnectionTest->OnAbilityConnectDone(admin, remoteObject, resultCode);

    EXPECT_TRUE(remoteObject->code_ != IEnterpriseAdmin::COMMAND_ON_ADMIN_ENABLED);
}

/**
 * @tc.name: TestOnAbilityDisconnectDoneWithSuperAdmin
 * @tc.desc: Test EnterpriseAdminConnection::OnAbilityDisconnectDone func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseAdminConnectionTest, TestOnAbilityDisconnectDoneWithSuperAdmin, TestSize.Level1)
{
    AppExecFwk::ExtensionAbilityInfo abilityInfo;
    abilityInfo.bundleName = "com.edm.test.demo";
    abilityInfo.name = "com.edm.test.demo.Ability";
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "technology company in wuhan";
    std::vector<std::string> permissions = {"ohos.permission.EDM_TEST_PERMISSION"};
    Admin edmAdmin(abilityInfo, AdminType::ENT, entInfo, permissions, false);
    AdminManager::GetInstance()->SetAdminValue(DEFAULT_USER_ID, edmAdmin);

    AAFwk::Want connectWant;
    connectWant.SetElementName(abilityInfo.bundleName, abilityInfo.name);
    enterpriseAdminConnectionTest = std::make_shared<EnterpriseAdminConnection>(connectWant,
        IEnterpriseAdmin::COMMAND_ON_ADMIN_ENABLED, DEFAULT_USER_ID, true);
    AppExecFwk::ElementName admin;
    admin.SetBundleName(abilityInfo.bundleName);
    admin.SetAbilityName(abilityInfo.name);
    int32_t resultCode = 0;
    enterpriseAdminConnectionTest->OnAbilityDisconnectDone(admin, resultCode);
    EXPECT_TRUE(AdminManager::GetInstance()->IsSuperAdmin(abilityInfo.bundleName));

    AdminManager::GetInstance()->DeleteAdmin(admin.GetBundleName(), DEFAULT_USER_ID);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS