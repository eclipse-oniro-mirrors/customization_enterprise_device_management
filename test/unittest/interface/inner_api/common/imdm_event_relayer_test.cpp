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

#include "imdm_event_relayer.h"

#include <gtest/gtest.h>

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class IMdmEventRelayerTest : public testing::Test {};

/**
 * @tc.name: TestGetInstance
 * @tc.desc: Test IMdmEventRelayer::GetInstance returns one and the same instance.
 * @tc.type: FUNC
 */
HWTEST_F(IMdmEventRelayerTest, TestGetInstance, TestSize.Level1)
{
    auto *first = IMdmEventRelayer::GetInstance();
    ASSERT_NE(first, nullptr);
    auto *second = IMdmEventRelayer::GetInstance();
    ASSERT_NE(second, nullptr);
    EXPECT_EQ(first, second);
}

/**
 * @tc.name: TestDefaultSubscribeAndUnsubscribe
 * @tc.desc: Test the base IMdmEventRelayer subscribe calls are safe no-ops.
 * @tc.type: FUNC
 */
HWTEST_F(IMdmEventRelayerTest, TestDefaultSubscribeAndUnsubscribe, TestSize.Level1)
{
    auto *relayer = IMdmEventRelayer::GetInstance();
    ASSERT_NE(relayer, nullptr);
    relayer->OnAdminSubscribe("com.test.admin", 100, ManagedEvent::BOOT_COMPLETED);
    relayer->OnAdminUnsubscribe("com.test.admin", 100, ManagedEvent::BOOT_COMPLETED);
    EXPECT_EQ(IMdmEventRelayer::GetInstance(), relayer);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
