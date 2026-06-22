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

#ifndef EDM_UNIT_TEST_EDM_TIMER_MANAGER_H
#define EDM_UNIT_TEST_EDM_TIMER_MANAGER_H

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <functional>

#include "iedm_timer_manager.h"

namespace OHOS {
namespace EDM {
namespace TEST {
class MockEdmTimerManager : public IEdmTimerManager {
public:
    MOCK_METHOD(bool, SetTimer, (EdmTimerTask timerTask, uint64_t delayMs,
        const std::function<void()> &callback), (override));
    MOCK_METHOD(void, CancelTimer, (EdmTimerTask timerTask), (override));
    MOCK_METHOD(bool, IsTimerRunning, (EdmTimerTask timerTask), (override));
};
} // namespace TEST
} // namespace EDM
} // namespace OHOS
#endif // EDM_UNIT_TEST_EDM_TIMER_MANAGER_H
