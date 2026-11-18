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

#include <gtest/gtest.h>
#include <memory>
#include "app_service_connection_stub.h"
#include "edm_errors.h"
#include "element_name.h"
#include "i_edm_connection_callback.h"
#include "iremote_object.h"
#include "iremote_stub.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class MockEdmConnectionCallback : public IRemoteStub<IEdmConnectionCallback> {
public:
    bool onConnectCalled = false;
    bool onDisconnectCalled = false;
    bool onFailedCalled = false;
    int32_t lastFailedCode = 0;
    AppExecFwk::ElementName lastElement;
    sptr<IRemoteObject> lastRemote;

    void OnConnect(const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remote) override
    {
        onConnectCalled = true;
        lastElement = element;
        lastRemote = remote;
    }
    void OnDisconnect(const AppExecFwk::ElementName &element) override
    {
        onDisconnectCalled = true;
        lastElement = element;
    }
    void OnFailed(int32_t code) override
    {
        onFailedCalled = true;
        lastFailedCode = code;
    }
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option) override
    {
        return ERR_OK;
    }
};

class AppServiceConnectionStubTest : public Test {
public:
    void SetUp() override
    {
        callback = new MockEdmConnectionCallback();
        stub = new AppServiceConnectionStub(1, callback);
    }
    sptr<MockEdmConnectionCallback> callback;
    sptr<AppServiceConnectionStub> stub;
};

HWTEST_F(AppServiceConnectionStubTest, OnAbilityConnectDone_Success_ForwardsOnConnect, TestSize.Level1)
{
    AppExecFwk::ElementName element("deviceId", "com.test.bundle", "TestAbility");
    sptr<IRemoteObject> remote = new IPCObjectStub(u"test.remote");
    stub->OnAbilityConnectDone(element, remote, 0);
    EXPECT_TRUE(callback->onConnectCalled);
    EXPECT_EQ(callback->lastElement.GetBundleName(), "com.test.bundle");
    EXPECT_EQ(callback->lastRemote, remote);
}

HWTEST_F(AppServiceConnectionStubTest, OnAbilityConnectDone_Failure_ForwardsOnFailedWithMappedCode, TestSize.Level1)
{
    AppExecFwk::ElementName element("deviceId", "com.test.bundle", "TestAbility");
    stub->OnAbilityConnectDone(element, nullptr, 16000001);
    EXPECT_TRUE(callback->onFailedCalled);
    EXPECT_EQ(callback->lastFailedCode, EdmReturnErrCode::ABILITY_NOT_EXIST);
}

HWTEST_F(AppServiceConnectionStubTest, OnAbilityConnectDone_InvalidType_ForwardsInvalidType, TestSize.Level1)
{
    AppExecFwk::ElementName element("deviceId", "com.test.bundle", "TestAbility");
    stub->OnAbilityConnectDone(element, nullptr, 16000002);
    EXPECT_TRUE(callback->onFailedCalled);
    EXPECT_EQ(callback->lastFailedCode, EdmReturnErrCode::CONNECT_APP_SERVICE_EXTENSION_INVALID_TYPE);
}

HWTEST_F(AppServiceConnectionStubTest, OnAbilityConnectDone_NotVisible_ForwardsNotVisible, TestSize.Level1)
{
    AppExecFwk::ElementName element("deviceId", "com.test.bundle", "TestAbility");
    stub->OnAbilityConnectDone(element, nullptr, 16000004);
    EXPECT_TRUE(callback->onFailedCalled);
    EXPECT_EQ(callback->lastFailedCode, EdmReturnErrCode::CONNECT_APP_SERVICE_EXTENSION_NOT_VISIBLE);
}

HWTEST_F(AppServiceConnectionStubTest, OnAbilityConnectDone_CrossUserCode_ForwardsGenericFailed, TestSize.Level1)
{
    AppExecFwk::ElementName element("deviceId", "com.test.bundle", "TestAbility");
    stub->OnAbilityConnectDone(element, nullptr, 16000006);
    EXPECT_TRUE(callback->onFailedCalled);
    EXPECT_EQ(callback->lastFailedCode, EdmReturnErrCode::CONNECT_APP_SERVICE_EXTENSION_FAILED);
}

HWTEST_F(AppServiceConnectionStubTest, OnAbilityConnectDone_OtherError_ForwardsGenericFailed, TestSize.Level1)
{
    AppExecFwk::ElementName element("deviceId", "com.test.bundle", "TestAbility");
    stub->OnAbilityConnectDone(element, nullptr, 99999);
    EXPECT_TRUE(callback->onFailedCalled);
    EXPECT_EQ(callback->lastFailedCode, EdmReturnErrCode::CONNECT_APP_SERVICE_EXTENSION_FAILED);
}

HWTEST_F(AppServiceConnectionStubTest, OnAbilityDisconnectDone_ForwardsOnDisconnect, TestSize.Level1)
{
    AppExecFwk::ElementName element("deviceId", "com.test.bundle", "TestAbility");
    stub->OnAbilityDisconnectDone(element, 0);
    EXPECT_TRUE(callback->onDisconnectCalled);
    EXPECT_EQ(callback->lastElement.GetBundleName(), "com.test.bundle");
}

HWTEST_F(AppServiceConnectionStubTest, OnAbilityConnectDone_NullCallback_NoCrash, TestSize.Level1)
{
    sptr<AppServiceConnectionStub> nullStub = new AppServiceConnectionStub(2, nullptr);
    AppExecFwk::ElementName element("deviceId", "com.test.bundle", "TestAbility");
    sptr<IRemoteObject> remote = new IPCObjectStub(u"test.remote");
    nullStub->OnAbilityConnectDone(element, remote, 0);
    EXPECT_TRUE(true);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
