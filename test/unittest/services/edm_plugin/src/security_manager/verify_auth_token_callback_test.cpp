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

#include "security_manager/verify_auth_token_callback_test.h"
#include <thread>

#include "attributes.h"
#include "iam_common_defines.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {

constexpr uint64_t CREDENTIAL_ID = 1234567890123456789ULL;
constexpr int64_t SHORT_TIMEOUT_MS = 100;
constexpr int64_t LONG_TIMEOUT_MS = 5000;

void VerifyAuthTokenCallbackTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void VerifyAuthTokenCallbackTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestWaitResultTimeout
 * @tc.desc: Test WaitResult returns -1 when the identity authentication service does not respond
 *     within the given timeout.
 * @tc.type: FUNC
 */
HWTEST_F(VerifyAuthTokenCallbackTest, TestWaitResultTimeout, TestSize.Level1)
{
    VerifyAuthTokenCallback callback;
    EXPECT_EQ(callback.WaitResult(SHORT_TIMEOUT_MS), -1);
}

/**
 * @tc.name: TestOnResultSuccess
 * @tc.desc: Test OnResult reports the success result and carries the credential id when the
 *     verification succeeds.
 * @tc.type: FUNC
 */
HWTEST_F(VerifyAuthTokenCallbackTest, TestOnResultSuccess, TestSize.Level1)
{
    VerifyAuthTokenCallback callback;
    UserIam::UserAuth::Attributes extraInfo;
    ASSERT_TRUE(extraInfo.SetUint64Value(UserIam::UserAuth::Attributes::ATTR_CREDENTIAL_ID, CREDENTIAL_ID));

    callback.OnResult(static_cast<int32_t>(UserIam::UserAuth::SUCCESS), extraInfo);

    EXPECT_EQ(callback.WaitResult(LONG_TIMEOUT_MS), static_cast<int32_t>(UserIam::UserAuth::SUCCESS));
    EXPECT_EQ(callback.GetCredentialId(), CREDENTIAL_ID);
}

/**
 * @tc.name: TestOnResultSuccessWithoutCredentialId
 * @tc.desc: Test OnResult converts a success result without a credential id into a general error,
 *     and the credential id stays zero.
 * @tc.type: FUNC
 */
HWTEST_F(VerifyAuthTokenCallbackTest, TestOnResultSuccessWithoutCredentialId, TestSize.Level1)
{
    VerifyAuthTokenCallback callback;
    UserIam::UserAuth::Attributes extraInfo;
    // The extra information carries no credential id, so the success result cannot be trusted.
    uint64_t absentCredentialId = 0;
    ASSERT_FALSE(extraInfo.GetUint64Value(UserIam::UserAuth::Attributes::ATTR_CREDENTIAL_ID, absentCredentialId));

    callback.OnResult(static_cast<int32_t>(UserIam::UserAuth::SUCCESS), extraInfo);

    EXPECT_EQ(callback.WaitResult(LONG_TIMEOUT_MS), static_cast<int32_t>(UserIam::UserAuth::GENERAL_ERROR));
    EXPECT_EQ(callback.GetCredentialId(), 0);
}

/**
 * @tc.name: TestOnResultFailure
 * @tc.desc: Test OnResult reports the failure result reported by the identity authentication
 *     service, and the credential id stays zero.
 * @tc.type: FUNC
 */
HWTEST_F(VerifyAuthTokenCallbackTest, TestOnResultFailure, TestSize.Level1)
{
    VerifyAuthTokenCallback callback;
    UserIam::UserAuth::Attributes extraInfo;
    ASSERT_TRUE(extraInfo.SetUint64Value(UserIam::UserAuth::Attributes::ATTR_CREDENTIAL_ID, CREDENTIAL_ID));

    callback.OnResult(static_cast<int32_t>(UserIam::UserAuth::INVALID_PARAMETERS), extraInfo);

    EXPECT_EQ(callback.WaitResult(LONG_TIMEOUT_MS), static_cast<int32_t>(UserIam::UserAuth::INVALID_PARAMETERS));
    EXPECT_EQ(callback.GetCredentialId(), 0);
}

/**
 * @tc.name: TestOnResultCalledTwice
 * @tc.desc: Test OnResult only takes the first result into account when the identity
 *     authentication service reports the result more than once.
 * @tc.type: FUNC
 */
HWTEST_F(VerifyAuthTokenCallbackTest, TestOnResultCalledTwice, TestSize.Level1)
{
    VerifyAuthTokenCallback callback;
    UserIam::UserAuth::Attributes extraInfo;
    ASSERT_TRUE(extraInfo.SetUint64Value(UserIam::UserAuth::Attributes::ATTR_CREDENTIAL_ID, CREDENTIAL_ID));

    callback.OnResult(static_cast<int32_t>(UserIam::UserAuth::SUCCESS), extraInfo);
    callback.OnResult(static_cast<int32_t>(UserIam::UserAuth::GENERAL_ERROR), extraInfo);

    EXPECT_EQ(callback.WaitResult(LONG_TIMEOUT_MS), static_cast<int32_t>(UserIam::UserAuth::SUCCESS));
    EXPECT_EQ(callback.GetCredentialId(), CREDENTIAL_ID);
}

/**
 * @tc.name: TestWaitResultAfterResult
 * @tc.desc: Test WaitResult returns immediately without blocking when the result has already
 *     arrived.
 * @tc.type: FUNC
 */
HWTEST_F(VerifyAuthTokenCallbackTest, TestWaitResultAfterResult, TestSize.Level1)
{
    VerifyAuthTokenCallback callback;
    UserIam::UserAuth::Attributes extraInfo;
    ASSERT_TRUE(extraInfo.SetUint64Value(UserIam::UserAuth::Attributes::ATTR_CREDENTIAL_ID, CREDENTIAL_ID));

    callback.OnResult(static_cast<int32_t>(UserIam::UserAuth::SUCCESS), extraInfo);

    EXPECT_EQ(callback.WaitResult(LONG_TIMEOUT_MS), static_cast<int32_t>(UserIam::UserAuth::SUCCESS));
    EXPECT_EQ(callback.GetCredentialId(), CREDENTIAL_ID);
}

/**
 * @tc.name: TestOnResultFromOtherThread
 * @tc.desc: Test the waiting side is woken up when the result is reported from another thread,
 *     which is the real callback scenario of the identity authentication framework.
 * @tc.type: FUNC
 */
HWTEST_F(VerifyAuthTokenCallbackTest, TestOnResultFromOtherThread, TestSize.Level1)
{
    VerifyAuthTokenCallback callback;
    UserIam::UserAuth::Attributes extraInfo;
    ASSERT_TRUE(extraInfo.SetUint64Value(UserIam::UserAuth::Attributes::ATTR_CREDENTIAL_ID, CREDENTIAL_ID));

    std::thread notifier([&callback, &extraInfo]() {
        callback.OnResult(static_cast<int32_t>(UserIam::UserAuth::SUCCESS), extraInfo);
    });

    EXPECT_EQ(callback.WaitResult(LONG_TIMEOUT_MS), static_cast<int32_t>(UserIam::UserAuth::SUCCESS));
    EXPECT_EQ(callback.GetCredentialId(), CREDENTIAL_ID);
    notifier.join();
}

/**
 * @tc.name: TestGetCredentialIdBeforeResult
 * @tc.desc: Test GetCredentialId returns zero before any result is reported.
 * @tc.type: FUNC
 */
HWTEST_F(VerifyAuthTokenCallbackTest, TestGetCredentialIdBeforeResult, TestSize.Level1)
{
    VerifyAuthTokenCallback callback;
    EXPECT_EQ(callback.GetCredentialId(), 0);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
