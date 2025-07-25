/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef EDM_UNIT_TEST_DISALLOWED_AIRPLANE_MODE_PLUGIIN_TEST_H
#define EDM_UNIT_TEST_DISALLOWED_AIRPLANE_MODE_PLUGIIN_TEST_H
   
#include <gtest/gtest.h>

namespace OHOS {
namespace EDM {
namespace TEST {
class DisallowedAirplaneModeTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};
} // namespace TEST
} // namespace EDM
} // namespace OHOS

#endif // EDM_UNIT_TEST_DISALLOWED_AIRPLANE_MODE_PLUGIIN_TEST_H
