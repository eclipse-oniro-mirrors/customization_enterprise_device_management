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

#include <gtest/gtest.h>
#include <memory>
#include <string>

#include "edm_event_data.h"
#include "edm_user_auth_listener.h"
#include "event_subscription_manager.h"
#include "managed_event.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
namespace {
constexpr int32_t TEST_USER_ID = 100;
constexpr int32_t TEST_FAIL_COUNT = 3;
}

class EdmUserAuthListenerTest : public testing::Test {
protected:
    void TearDown() override
    {
        if (handle_ != nullptr) {
            handle_->Release();
            handle_ = nullptr;
        }
    }

    std::shared_ptr<SubscriptionHandle> handle_;
};

/**
 * @tc.name: TestOnAuthFailureCountChangedDispatch
 * @tc.desc: Test OnAuthFailureCountChanged dispatches event with userId and failCount.
 * @tc.type: FUNC
 */
HWTEST_F(EdmUserAuthListenerTest, OnAuthFailureCountChanged_ValidParams_Dispatched, TestSize.Level1)
{
    int callCount = 0;
    int32_t receivedCount = -1;
    int32_t receivedUserId = -1;
    handle_ = EventSubscriptionManager::GetInstance().Subscribe("test_listener_valid",
        SubscriberType::MDM_RELAY, EventId{static_cast<uint32_t>(ManagedEvent::PASSWORD_FAILED)},
        [&callCount, &receivedCount, &receivedUserId](const EdmEventData &data) {
            callCount++;
            receivedCount = data.passwordFailedCount;
            receivedUserId = data.userId;
        });
    ASSERT_NE(handle_, nullptr);

    EdmUserAuthListener listener(EventSubscriptionManager::GetInstance());
    listener.OnAuthFailureCountChanged(TEST_USER_ID, TEST_FAIL_COUNT);

    EXPECT_EQ(callCount, 1);
    EXPECT_EQ(receivedCount, TEST_FAIL_COUNT);
    EXPECT_EQ(receivedUserId, TEST_USER_ID);
}

/**
 * @tc.name: TestOnAuthFailureCountChangedInvalidUserId
 * @tc.desc: Test OnAuthFailureCountChanged does not dispatch when userId is negative.
 * @tc.type: FUNC
 */
HWTEST_F(EdmUserAuthListenerTest, OnAuthFailureCountChanged_InvalidUserId_NotDispatched, TestSize.Level1)
{
    int callCount = 0;
    handle_ = EventSubscriptionManager::GetInstance().Subscribe("test_listener_invalid_user",
        SubscriberType::MDM_RELAY, EventId{static_cast<uint32_t>(ManagedEvent::PASSWORD_FAILED)},
        [&callCount](const EdmEventData &) {
            callCount++;
        });
    ASSERT_NE(handle_, nullptr);

    EdmUserAuthListener listener(EventSubscriptionManager::GetInstance());
    listener.OnAuthFailureCountChanged(-1, TEST_FAIL_COUNT);

    EXPECT_EQ(callCount, 0);
}

/**
 * @tc.name: TestOnAuthFailureCountChangedInvalidFailCount
 * @tc.desc: Test OnAuthFailureCountChanged does not dispatch when failCount is negative.
 * @tc.type: FUNC
 */
HWTEST_F(EdmUserAuthListenerTest, OnAuthFailureCountChanged_InvalidFailCount_NotDispatched, TestSize.Level1)
{
    int callCount = 0;
    handle_ = EventSubscriptionManager::GetInstance().Subscribe("test_listener_invalid_count",
        SubscriberType::MDM_RELAY, EventId{static_cast<uint32_t>(ManagedEvent::PASSWORD_FAILED)},
        [&callCount](const EdmEventData &) {
            callCount++;
        });
    ASSERT_NE(handle_, nullptr);

    EdmUserAuthListener listener(EventSubscriptionManager::GetInstance());
    listener.OnAuthFailureCountChanged(TEST_USER_ID, -1);

    EXPECT_EQ(callCount, 0);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
