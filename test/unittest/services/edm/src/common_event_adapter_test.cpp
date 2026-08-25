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
#include "adapter_factory.h"
#include "common_event_adapter.h"
#include "common_event_support.h"
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

class CommonEventAdapterTest : public testing::Test {
protected:
    void SetUp() override
    {
        manager_ = &EventSubscriptionManager::GetInstance();
    }

    EventSubscriptionManager *manager_;
};

/**
 * @tc.name: Test_ConstructorCreatesSubscriber
 * @tc.desc: Test CommonEventAdapter constructor creates a subscriber.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventAdapterTest, Constructor_CreatesSubscriber, TestSize.Level1)
{
    EventFwk::MatchingSkills skill;
    skill.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    EventFwk::CommonEventSubscribeInfo info(skill);
    EventId eventId{static_cast<uint32_t>(ManagedEvent::BUNDLE_ADDED)};

    CommonEventAdapter adapter(info, *manager_, eventId);
}

/**
 * @tc.name: Test_ConstructorWithPermission
 * @tc.desc: Test CommonEventAdapter constructor with permission set.
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventAdapterTest, Constructor_WithPermission_CreatesSubscriber, TestSize.Level1)
{
    EventFwk::MatchingSkills skill;
    skill.AddEvent(EDM_SYSTEM_UPDATE_FOR_POLICY);
    EventFwk::CommonEventSubscribeInfo info(skill);
    info.SetPermission(EDM_SYSTEM_UPDATE_PERMISSION);
    EventId eventId{static_cast<uint32_t>(ManagedEvent::SYSTEM_UPDATE)};

    CommonEventAdapter adapter(info, *manager_, eventId);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
