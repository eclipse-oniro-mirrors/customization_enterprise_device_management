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
#include "common_event_support.h"
#include "edm_common_event_subscriber.h"
#include "event_subscription_manager.h"
#undef private

#include <gtest/gtest.h>
#include <memory>
#include <string>

#include "managed_event.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {

class EdmCommonEventSubscriberTest : public testing::Test {
protected:
    void SetUp() override
    {
        manager_ = &EventSubscriptionManager::GetInstance();
        EventId eventId{static_cast<uint32_t>(ManagedEvent::BUNDLE_ADDED)};
        EventFwk::MatchingSkills skill;
        skill.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
        EventFwk::CommonEventSubscribeInfo info(skill);
        subscriber_ = std::make_shared<EdmCommonEventSubscriber>(info, *manager_, eventId);
    }

    EventSubscriptionManager *manager_;
    std::shared_ptr<EdmCommonEventSubscriber> subscriber_;
};

/**
 * @tc.name: Test_OnReceiveEventDispatchesEvent
 * @tc.desc: Test OnReceiveEvent dispatches the event to the manager.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCommonEventSubscriberTest, OnReceiveEvent_DispatchesEvent, TestSize.Level1)
{
    AAFwk::Want want;
    want.SetElement(AppExecFwk::ElementName("", "com.test.bundle", ""));
    EventFwk::CommonEventData data(want, 0, "");
    subscriber_->OnReceiveEvent(data);
}

/**
 * @tc.name: Test_OnReceiveEventWithCode
 * @tc.desc: Test OnReceiveEvent dispatches event with a code value.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCommonEventSubscriberTest, OnReceiveEvent_WithCode_DispatchesEvent, TestSize.Level1)
{
    AAFwk::Want want;
    EventFwk::CommonEventData data(want, 100, "");
    subscriber_->OnReceiveEvent(data);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
