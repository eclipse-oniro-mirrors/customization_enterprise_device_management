/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#define private public
#include <gtest/gtest.h>
#include "enterprise_device_mgr_ability.h"
#include "admin_manager.h"
#include "app_service_connection_manager.h"
#include "edm_errors.h"
#include "i_edm_connection_callback.h"
#include "iremote_stub.h"
#include "permission_checker.h"
#undef private

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class AbilityTestCallback : public IRemoteStub<IEdmConnectionCallback> {
public:
    void OnConnect(const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remote) override {}
    void OnDisconnect(const AppExecFwk::ElementName &element) override {}
    void OnFailed(int32_t code) override {}
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option) override { return ERR_OK; }
};

class EdmAbilityConnectionTest : public Test {
public:
    void SetUp() override
    {
        AppServiceConnectionManager::GetInstance().OnAdminRemoved("__test_cleanup__");
    }
};

HWTEST_F(EdmAbilityConnectionTest, DisconnectAppServiceExtensionAbility_DelegatesToManager, TestSize.Level1)
{
    auto ret = EnterpriseDeviceMgrAbility::GetInstance()->DisconnectAppServiceExtensionAbility(99999);
    EXPECT_EQ(ret, EdmReturnErrCode::UID_INVALID);
}

HWTEST_F(EdmAbilityConnectionTest, ConnectAppServiceExtensionAbilityByOsAccount_NullCallback_ReturnsError, TestSize.Level1)
{
    AAFwk::Want want;
    want.SetElementName("com.test", "TestAbility");
    int32_t connectionId = -1;
    sptr<IRemoteObject> nullCallback = nullptr;
    auto ret = EnterpriseDeviceMgrAbility::GetInstance()->ConnectAppServiceExtensionAbilityByOsAccount(
        want, 101, nullCallback, connectionId);
    EXPECT_NE(ret, ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
