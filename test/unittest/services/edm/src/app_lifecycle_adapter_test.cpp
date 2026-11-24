/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "app_lifecycle_adapter.h"
#include "event_subscription_manager.h"
#undef private

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>

#include "edm_app_manager_impl_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {

class AppLifecycleAdapterTest : public testing::Test {
protected:
    void SetUp() override
    {
        manager_ = &EventSubscriptionManager::GetInstance();
    }

    EventSubscriptionManager *manager_;
};

/**
 * @tc.name: Test_ConstructorCreatesObserver
 * @tc.desc: Test AppLifecycleAdapter constructor creates an EdmAppStateSubscriber.
 * @tc.type: FUNC
 */
HWTEST_F(AppLifecycleAdapterTest, Constructor_CreatesObserver, TestSize.Level1)
{
    AppLifecycleAdapter adapter(*manager_);
    EXPECT_NE(adapter.subscriber_, nullptr);
}

/**
 * @tc.name: Test_SubscribeEventNullSubscriber
 * @tc.desc: Test SubscribeEvent returns false when subscriber is null.
 * @tc.type: FUNC
 */
HWTEST_F(AppLifecycleAdapterTest, SubscribeEvent_NullSubscriber_ReturnsFalse, TestSize.Level1)
{
    AppLifecycleAdapter adapter(*manager_);
    adapter.subscriber_ = nullptr;
    EXPECT_FALSE(adapter.SubscribeEvent());
}

/**
 * @tc.name: Test_SubscribeEventRegisterFails
 * @tc.desc: Test SubscribeEvent returns false when RegisterApplicationStateObserver fails.
 * @tc.type: FUNC
 */
HWTEST_F(AppLifecycleAdapterTest, SubscribeEvent_RegisterFails_ReturnsFalse, TestSize.Level1)
{
    AppLifecycleAdapter adapter(*manager_);
    auto mockAppMgr = std::make_shared<EdmAppManagerImplMock>();
    adapter.edmAppManager_ = mockAppMgr;
    EXPECT_CALL(*mockAppMgr, RegisterApplicationStateObserver(_))
        .WillOnce(Return(1));
    EXPECT_FALSE(adapter.SubscribeEvent());
}

/**
 * @tc.name: Test_SubscribeEventRegisterSucceeds
 * @tc.desc: Test SubscribeEvent returns true when RegisterApplicationStateObserver succeeds.
 * @tc.type: FUNC
 */
HWTEST_F(AppLifecycleAdapterTest, SubscribeEvent_RegisterSucceeds_ReturnsTrue, TestSize.Level1)
{
    AppLifecycleAdapter adapter(*manager_);
    auto mockAppMgr = std::make_shared<EdmAppManagerImplMock>();
    adapter.edmAppManager_ = mockAppMgr;
    EXPECT_CALL(*mockAppMgr, RegisterApplicationStateObserver(_))
        .WillOnce(Return(0));
    EXPECT_TRUE(adapter.SubscribeEvent());
}

/**
 * @tc.name: Test_UnsubscribeEventNullSubscriber
 * @tc.desc: Test UnsubscribeEvent returns false when subscriber is null.
 * @tc.type: FUNC
 */
HWTEST_F(AppLifecycleAdapterTest, UnsubscribeEvent_NullSubscriber_ReturnsFalse, TestSize.Level1)
{
    AppLifecycleAdapter adapter(*manager_);
    adapter.subscriber_ = nullptr;
    EXPECT_FALSE(adapter.UnsubscribeEvent());
}

/**
 * @tc.name: Test_UnsubscribeEventUnregisterFails
 * @tc.desc: Test UnsubscribeEvent returns false when UnregisterApplicationStateObserver fails.
 * @tc.type: FUNC
 */
HWTEST_F(AppLifecycleAdapterTest, UnsubscribeEvent_UnregisterFails_ReturnsFalse, TestSize.Level1)
{
    AppLifecycleAdapter adapter(*manager_);
    auto mockAppMgr = std::make_shared<EdmAppManagerImplMock>();
    adapter.edmAppManager_ = mockAppMgr;
    EXPECT_CALL(*mockAppMgr, UnregisterApplicationStateObserver(_))
        .WillOnce(Return(1));
    EXPECT_FALSE(adapter.UnsubscribeEvent());
}

/**
 * @tc.name: Test_UnsubscribeEventUnregisterSucceeds
 * @tc.desc: Test UnsubscribeEvent returns true when UnregisterApplicationStateObserver succeeds.
 * @tc.type: FUNC
 */
HWTEST_F(AppLifecycleAdapterTest, UnsubscribeEvent_UnregisterSucceeds_ReturnsTrue, TestSize.Level1)
{
    AppLifecycleAdapter adapter(*manager_);
    auto mockAppMgr = std::make_shared<EdmAppManagerImplMock>();
    adapter.edmAppManager_ = mockAppMgr;
    EXPECT_CALL(*mockAppMgr, UnregisterApplicationStateObserver(_))
        .WillOnce(Return(0));
    EXPECT_TRUE(adapter.UnsubscribeEvent());
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
