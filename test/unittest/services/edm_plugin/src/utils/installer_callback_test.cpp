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

#include "installer_callback.h"

#include <gtest/gtest.h>

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
namespace {
constexpr int32_t TEST_RESULT_CODE = 5;
const std::string TEST_RESULT_MSG = "install finished";
}

class InstallerCallbackTest : public testing::Test {};

/**
 * @tc.name: TestOnFinishedThenGetResult
 * @tc.desc: Test InstallerCallback publishes the code and message to its futures.
 * @tc.type: FUNC
 */
HWTEST_F(InstallerCallbackTest, TestOnFinishedThenGetResult, TestSize.Level1)
{
    InstallerCallback callback;
    callback.OnStatusNotify(50);
    callback.OnFinished(TEST_RESULT_CODE, TEST_RESULT_MSG);
    EXPECT_EQ(callback.GetResultCode(), TEST_RESULT_CODE);
    EXPECT_EQ(callback.GetResultMsg(), TEST_RESULT_MSG);
}

/**
 * @tc.name: TestOnFinishedWithZeroCode
 * @tc.desc: Test InstallerCallback also publishes a success code and an empty message.
 * @tc.type: FUNC
 */
HWTEST_F(InstallerCallbackTest, TestOnFinishedWithZeroCode, TestSize.Level1)
{
    InstallerCallback callback;
    callback.OnFinished(0, "");
    EXPECT_EQ(callback.GetResultCode(), 0);
    EXPECT_TRUE(callback.GetResultMsg().empty());
}

/**
 * @tc.name: TestSeparateCallbacksKeepOwnResults
 * @tc.desc: Test two callbacks publish their own code and message independently.
 * @tc.type: FUNC
 */
HWTEST_F(InstallerCallbackTest, TestSeparateCallbacksKeepOwnResults, TestSize.Level1)
{
    InstallerCallback first;
    InstallerCallback second;
    first.OnFinished(-1, "failed");
    second.OnFinished(TEST_RESULT_CODE, TEST_RESULT_MSG);
    EXPECT_EQ(first.GetResultCode(), -1);
    EXPECT_EQ(second.GetResultCode(), TEST_RESULT_CODE);
    EXPECT_EQ(first.GetResultMsg(), "failed");
    EXPECT_EQ(second.GetResultMsg(), TEST_RESULT_MSG);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
