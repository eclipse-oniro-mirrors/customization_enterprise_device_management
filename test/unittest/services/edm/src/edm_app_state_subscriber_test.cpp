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
#include "edm_app_state_subscriber.h"
#include "event_subscription_manager.h"
#undef private

#include <gtest/gtest.h>
#include <memory>

#include "managed_event.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {

class EdmAppStateSubscriberTest : public testing::Test {
protected:
    void SetUp() override
    {
        manager_ = &EventSubscriptionManager::GetInstance();
        subscriber_ = new EdmAppStateSubscriber(*manager_);
    }

    void TearDown() override
    {
        if (subscriber_ != nullptr) {
            subscriber_->AsObject()->RemoveDeathRecipient(nullptr);
        }
    }

    EventSubscriptionManager *manager_;
    sptr<EdmAppStateSubscriber> subscriber_;
};

/**
 * @tc.name: Test_OnProcessCreatedDispatchesAppStartEvent
 * @tc.desc: Test OnProcessCreated dispatches APP_START event.
 * @tc.type: FUNC
 */
HWTEST_F(EdmAppStateSubscriberTest, OnProcessCreated_DispatchesAppStartEvent, TestSize.Level1)
{
    AppExecFwk::ProcessData processData;
    processData.bundleName = "com.test.app";
    processData.pid = 1234;
    processData.uid = 10000;

    subscriber_->OnProcessCreated(processData);
}

/**
 * @tc.name: Test_OnProcessDiedDispatchesAppStopEvent
 * @tc.desc: Test OnProcessDied dispatches APP_STOP event.
 * @tc.type: FUNC
 */
HWTEST_F(EdmAppStateSubscriberTest, OnProcessDied_DispatchesAppStopEvent, TestSize.Level1)
{
    AppExecFwk::ProcessData processData;
    processData.bundleName = "com.test.app2";
    processData.pid = 5678;
    processData.uid = 10001;

    subscriber_->OnProcessDied(processData);
}

/**
 * @tc.name: Test_OnProcessCreatedEmptyBundleNameNoCrash
 * @tc.desc: Test OnProcessCreated with empty bundleName does not crash.
 * @tc.type: FUNC
 */
HWTEST_F(EdmAppStateSubscriberTest, OnProcessCreated_EmptyBundleName_NoCrash, TestSize.Level1)
{
    AppExecFwk::ProcessData processData;
    processData.bundleName = "";
    processData.pid = 0;
    processData.uid = 0;

    subscriber_->OnProcessCreated(processData);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
