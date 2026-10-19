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

#include "user_auth_event_adapter.h"

#include <gtest/gtest.h>
#include <memory>

#include "edm_event_data.h"
#include "event_subscription_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
namespace {
constexpr int32_t REGISTER_FAIL_RET = 9;
}

class MockUserAuthEventAdapter : public UserAuthEventAdapter {
public:
    explicit MockUserAuthEventAdapter(EventSubscriptionManager &manager) : UserAuthEventAdapter(manager) {}

    int32_t DoRegisterIamListener() override
    {
        registerCalls_++;
        return registerResult_;
    }

    int32_t DoUnregisterIamListener() override
    {
        unregisterCalls_++;
        return unregisterResult_;
    }

    int32_t registerResult_ = 0;
    int32_t unregisterResult_ = 0;
    int32_t registerCalls_ = 0;
    int32_t unregisterCalls_ = 0;
};

class UserAuthEventAdapterTest : public testing::Test {
protected:
    EventSubscriptionManager &manager_ = EventSubscriptionManager::GetInstance();
};

/**
 * @tc.name: TestSubscribeEventSuccess
 * @tc.desc: Test SubscribeEvent returns true when DoRegister succeeds.
 * @tc.type: FUNC
 */
HWTEST_F(UserAuthEventAdapterTest, SubscribeEvent_Success, TestSize.Level1)
{
    MockUserAuthEventAdapter adapter(manager_);
    adapter.registerResult_ = 0;
    EXPECT_TRUE(adapter.SubscribeEvent());
    EXPECT_EQ(adapter.registerCalls_, 1);
}

/**
 * @tc.name: TestSubscribeEventFailure
 * @tc.desc: Test SubscribeEvent returns false when DoRegister fails.
 * @tc.type: FUNC
 */
HWTEST_F(UserAuthEventAdapterTest, SubscribeEvent_Failure, TestSize.Level1)
{
    MockUserAuthEventAdapter adapter(manager_);
    adapter.registerResult_ = REGISTER_FAIL_RET;
    EXPECT_FALSE(adapter.SubscribeEvent());
    EXPECT_EQ(adapter.registerCalls_, 1);
}

/**
 * @tc.name: TestSubscribeEventListenerReuse
 * @tc.desc: Test repeated SubscribeEvent reuses listener and registers each time.
 * @tc.type: FUNC
 */
HWTEST_F(UserAuthEventAdapterTest, SubscribeEvent_ListenerLazyReuse, TestSize.Level1)
{
    MockUserAuthEventAdapter adapter(manager_);
    adapter.registerResult_ = 0;
    ASSERT_TRUE(adapter.SubscribeEvent());
    ASSERT_TRUE(adapter.SubscribeEvent());
    EXPECT_EQ(adapter.registerCalls_, 2);
}

/**
 * @tc.name: TestUnsubscribeEventWithoutRegister
 * @tc.desc: Test UnsubscribeEvent skips IAM unregister when never registered.
 * @tc.type: FUNC
 */
HWTEST_F(UserAuthEventAdapterTest, UnsubscribeEvent_NeverRegistered_SkipIam, TestSize.Level1)
{
    MockUserAuthEventAdapter adapter(manager_);
    EXPECT_TRUE(adapter.UnsubscribeEvent());
    EXPECT_EQ(adapter.unregisterCalls_, 0);
}

/**
 * @tc.name: TestUnsubscribeEventAfterRegister
 * @tc.desc: Test UnsubscribeEvent calls IAM unregister when registered.
 * @tc.type: FUNC
 */
HWTEST_F(UserAuthEventAdapterTest, UnsubscribeEvent_Registered_CallsIam, TestSize.Level1)
{
    MockUserAuthEventAdapter adapter(manager_);
    adapter.registerResult_ = 0;
    ASSERT_TRUE(adapter.SubscribeEvent());

    EXPECT_TRUE(adapter.UnsubscribeEvent());
    EXPECT_EQ(adapter.unregisterCalls_, 1);
}

/**
 * @tc.name: TestUnsubscribeEventWithIamFailure
 * @tc.desc: Test UnsubscribeEvent still returns true when IAM unregister fails.
 * @tc.type: FUNC
 */
HWTEST_F(UserAuthEventAdapterTest, UnsubscribeEvent_WithIamFailure, TestSize.Level1)
{
    MockUserAuthEventAdapter adapter(manager_);
    adapter.registerResult_ = 0;
    ASSERT_TRUE(adapter.SubscribeEvent());
    adapter.unregisterResult_ = REGISTER_FAIL_RET;

    EXPECT_TRUE(adapter.UnsubscribeEvent());
    EXPECT_EQ(adapter.unregisterCalls_, 1);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
