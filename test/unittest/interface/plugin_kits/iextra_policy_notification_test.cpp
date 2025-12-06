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

#include <gtest/gtest.h>
#include <string>
#include "iextra_policy_notification.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string TEST_ADMIN_NAME = "com.edm.test.demo";
class IExtraPolicyNotificationTest : public testing::Test {};

/**
 * @tc.name: TestNotify
 * @tc.desc: Test Notify func.
 * @tc.type: FUNC
 */
HWTEST_F(IExtraPolicyNotificationTest, TestNotify, TestSize.Level1)
{
    ErrCode res;
    auto iExtraPolicyNotification = IExtraPolicyNotification::GetInstance();
    std::string policyValue = "";
    res = iExtraPolicyNotification->Notify(TEST_ADMIN_NAME, 100, true);
    ASSERT_TRUE(res == ERR_OK);
    res = iExtraPolicyNotification->Notify("", 100, true);
    ASSERT_TRUE(res == ERR_OK);

    res = iExtraPolicyNotification->Notify(TEST_ADMIN_NAME, 101, true);
    ASSERT_TRUE(res == ERR_OK);
    res = iExtraPolicyNotification->Notify(TEST_ADMIN_NAME, 100, false);
    ASSERT_TRUE(res == ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS