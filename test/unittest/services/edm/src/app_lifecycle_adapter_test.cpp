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

#include <gtest/gtest.h>
#include <memory>

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
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
