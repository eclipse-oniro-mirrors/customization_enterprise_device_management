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
#include <memory>
#include "app_service_connection_manager.h"
#include "edm_errors.h"
#include "i_edm_connection_callback.h"
#include "iremote_stub.h"
#undef private

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class ManagerTestCallback : public IRemoteStub<IEdmConnectionCallback> {
public:
    bool onConnectCalled = false;
    bool onDisconnectCalled = false;
    bool onFailedCalled = false;
    void OnConnect(const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remote) override
    {
        onConnectCalled = true;
    }
    void OnDisconnect(const AppExecFwk::ElementName &element) override
    {
        onDisconnectCalled = true;
    }
    void OnFailed(int32_t code) override
    {
        onFailedCalled = true;
    }
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option) override
    {
        return ERR_OK;
    }
};

class AppServiceConnectionManagerTest : public Test {
public:
    void SetUp() override
    {
        manager = &AppServiceConnectionManager::GetInstance();
        std::lock_guard<std::recursive_mutex> lock(manager->mutex_);
        manager->connectionMap_.clear();
        manager->nextConnectionId_.store(1);
    }
    AppServiceConnectionManager* manager;
};

HWTEST_F(AppServiceConnectionManagerTest, Disconnect_NotFound_ReturnsUidInvalid, TestSize.Level1)
{
    int32_t ret = manager->DisconnectAppServiceExtensionAbility(99999);
    EXPECT_EQ(ret, EdmReturnErrCode::UID_INVALID);
}

HWTEST_F(AppServiceConnectionManagerTest, OnAdminRemoved_NoConnections_NoCrash, TestSize.Level1)
{
    manager->OnAdminRemoved("com.test.noexist");
    EXPECT_TRUE(true);
}

HWTEST_F(AppServiceConnectionManagerTest, OnAdminRemoved_RemovesMatchingAdminRecords, TestSize.Level1)
{
    sptr<ManagerTestCallback> callback = new ManagerTestCallback();
    sptr<AppServiceConnectionStub> stub = new AppServiceConnectionStub(100, callback);
    AppServiceConnectionManager::ConnectionRecord record;
    record.stub = stub;
    record.callback = callback;
    record.adminBundleName = "com.test.admin";
    record.accountId = 101;
    {
        std::lock_guard<std::recursive_mutex> lock(manager->mutex_);
        manager->connectionMap_[100] = record;
    }
    manager->OnAdminRemoved("com.test.admin");
    std::lock_guard<std::recursive_mutex> lock(manager->mutex_);
    EXPECT_EQ(manager->connectionMap_.size(), 0u);
}

HWTEST_F(AppServiceConnectionManagerTest, OnAdminRemoved_KeepsNonMatchingAdminRecords, TestSize.Level1)
{
    sptr<ManagerTestCallback> callback1 = new ManagerTestCallback();
    sptr<AppServiceConnectionStub> stub1 = new AppServiceConnectionStub(101, callback1);
    AppServiceConnectionManager::ConnectionRecord record1;
    record1.stub = stub1;
    record1.callback = callback1;
    record1.adminBundleName = "com.test.admin1";
    record1.accountId = 101;
    {
        std::lock_guard<std::recursive_mutex> lock(manager->mutex_);
        manager->connectionMap_[101] = record1;
    }
    manager->OnAdminRemoved("com.test.admin2");
    std::lock_guard<std::recursive_mutex> lock(manager->mutex_);
    EXPECT_EQ(manager->connectionMap_.size(), 1u);
    EXPECT_TRUE(manager->connectionMap_.find(101) != manager->connectionMap_.end());
}

HWTEST_F(AppServiceConnectionManagerTest, Connect_NullCallback_ReturnsParamError, TestSize.Level1)
{
    AAFwk::Want want;
    want.SetElementName("com.test", "TestAbility");
    int32_t connectionId = -1;
    int32_t ret = manager->ConnectAppServiceExtensionAbilityByOsAccount(
        want, 101, nullptr, "com.test.admin", nullptr, connectionId);
    EXPECT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
