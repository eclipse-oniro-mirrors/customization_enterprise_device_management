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

#include <atomic>
#include <functional>

#define private public
#define protected public
#include "edm_timer_info.h"
#undef protected
#undef private

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {

class EdmTimerInfoTest : public testing::Test {
public:
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: EdmTimerInfo_Constructor_WithNullCallbacks_CallbacksNull
 * @tc.desc: Test EdmTimerInfo constructor sets callbacks to nullptr when nullptr is passed.
 * @tc.type: FUNC
 */
HWTEST_F(EdmTimerInfoTest, Constructor_WithNullCallbacks_CallbacksNull, TestSize.Level1)
{
    EdmTimerInfo timerInfo(nullptr, nullptr);
    EXPECT_TRUE(timerInfo.callback_ == nullptr);
    EXPECT_TRUE(timerInfo.cleanupCallback_ == nullptr);
    timerInfo.OnTrigger();
    EXPECT_TRUE(true);
}

/**
 * @tc.name: EdmTimerInfo_OnTrigger_BothCallbacksSet_BothCalled
 * @tc.desc: Test OnTrigger invokes both callback and cleanupCallback when both are set.
 * @tc.type: FUNC
 */
HWTEST_F(EdmTimerInfoTest, OnTrigger_BothCallbacksSet_BothCalled, TestSize.Level1)
{
    std::atomic<bool> callbackCalled{false};
    std::atomic<bool> cleanupCalled{false};
    auto callback = [&callbackCalled]() { callbackCalled.store(true); };
    auto cleanupCallback = [&cleanupCalled]() { cleanupCalled.store(true); };

    EdmTimerInfo timerInfo(callback, cleanupCallback);
    EXPECT_TRUE(timerInfo.callback_ != nullptr);
    EXPECT_TRUE(timerInfo.cleanupCallback_ != nullptr);
    timerInfo.OnTrigger();
    EXPECT_TRUE(callbackCalled.load());
    EXPECT_TRUE(cleanupCalled.load());
}

/**
 * @tc.name: EdmTimerInfo_OnTrigger_CallbackNull_CleanupCalledOnly
 * @tc.desc: Test OnTrigger only invokes cleanupCallback when callback is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(EdmTimerInfoTest, OnTrigger_CallbackNull_CleanupCalledOnly, TestSize.Level1)
{
    std::atomic<bool> cleanupCalled{false};
    auto cleanupCallback = [&cleanupCalled]() { cleanupCalled.store(true); };

    EdmTimerInfo timerInfo(nullptr, cleanupCallback);
    timerInfo.OnTrigger();
    EXPECT_TRUE(cleanupCalled.load());
}

/**
 * @tc.name: EdmTimerInfo_OnTrigger_CleanupNull_CallbackCalledOnly
 * @tc.desc: Test OnTrigger only invokes callback when cleanupCallback is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(EdmTimerInfoTest, OnTrigger_CleanupNull_CallbackCalledOnly, TestSize.Level1)
{
    std::atomic<bool> callbackCalled{false};
    auto callback = [&callbackCalled]() { callbackCalled.store(true); };

    EdmTimerInfo timerInfo(callback, nullptr);
    timerInfo.OnTrigger();
    EXPECT_TRUE(callbackCalled.load());
}

/**
 * @tc.name: EdmTimerInfo_SetType_ValidValue_TypeSet
 * @tc.desc: Test SetType correctly sets the type member to a valid value.
 * @tc.type: FUNC
 */
HWTEST_F(EdmTimerInfoTest, SetType_ValidValue_TypeSet, TestSize.Level1)
{
    std::atomic<bool> callbackCalled{false};
    auto callback = [&callbackCalled]() { callbackCalled.store(true); };

    EdmTimerInfo timerInfo(callback, nullptr);
    int32_t typeValue = 0;
    timerInfo.SetType(typeValue);
    EXPECT_EQ(timerInfo.type, typeValue);
}

/**
 * @tc.name: EdmTimerInfo_SetRepeat_TrueValue_RepeatSet
 * @tc.desc: Test SetRepeat correctly sets repeat to true.
 * @tc.type: FUNC
 */
HWTEST_F(EdmTimerInfoTest, SetRepeat_TrueValue_RepeatSet, TestSize.Level1)
{
    std::atomic<bool> callbackCalled{false};
    auto callback = [&callbackCalled]() { callbackCalled.store(true); };

    EdmTimerInfo timerInfo(callback, nullptr);
    timerInfo.SetRepeat(true);
    EXPECT_TRUE(timerInfo.repeat);
}

/**
 * @tc.name: EdmTimerInfo_SetInterval_ValidValue_IntervalSet
 * @tc.desc: Test SetInterval correctly sets the interval member to a valid value.
 * @tc.type: FUNC
 */
HWTEST_F(EdmTimerInfoTest, SetInterval_ValidValue_IntervalSet, TestSize.Level1)
{
    std::atomic<bool> callbackCalled{false};
    auto callback = [&callbackCalled]() { callbackCalled.store(true); };

    EdmTimerInfo timerInfo(callback, nullptr);
    uint64_t intervalValue = 5000;
    timerInfo.SetInterval(intervalValue);
    EXPECT_EQ(timerInfo.interval, intervalValue);
}

/**
 * @tc.name: EdmTimerInfo_SetWantAgent_NullPointer_WantAgentSet
 * @tc.desc: Test SetWantAgent correctly sets wantAgent to nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(EdmTimerInfoTest, SetWantAgent_NullPointer_WantAgentSet, TestSize.Level1)
{
    std::atomic<bool> callbackCalled{false};
    auto callback = [&callbackCalled]() { callbackCalled.store(true); };

    EdmTimerInfo timerInfo(callback, nullptr);
    std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> wantAgent = nullptr;
    timerInfo.SetWantAgent(wantAgent);
    EXPECT_TRUE(timerInfo.wantAgent == nullptr);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
