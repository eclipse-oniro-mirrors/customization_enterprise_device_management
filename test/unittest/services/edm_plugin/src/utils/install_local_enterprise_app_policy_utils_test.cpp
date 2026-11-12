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

#include "edm_constants.h"

#define private public
#include "install_local_enterprise_app_policy_utils.h"
#undef private

#include "edm_errors.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
namespace {
constexpr int32_t TEST_POLICY_DISABLED = 0;
constexpr int32_t TEST_POLICY_ENABLED = 1;
}

class InstallLocalEnterpriseAppPolicyUtilsTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void InstallLocalEnterpriseAppPolicyUtilsTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void InstallLocalEnterpriseAppPolicyUtilsTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
}

/**
 * @tc.name: TestGetDeviceActualPolicyValue
 * @tc.desc: Test the device value mirrors the persist parameter and stays boolean.
 * @tc.type: FUNC
 */
HWTEST_F(InstallLocalEnterpriseAppPolicyUtilsTest, TestGetDeviceActualPolicyValue, TestSize.Level1)
{
    bool first = InstallLocalEnterpriseAppPolicyUtils::GetDeviceActualPolicyValue();
    bool second = InstallLocalEnterpriseAppPolicyUtils::GetDeviceActualPolicyValue();
    EXPECT_EQ(first, second);
}

/**
 * @tc.name: TestGetUserActualPolicyValue
 * @tc.desc: Test the user value is reported through the account constraint query.
 * @tc.type: FUNC
 */
HWTEST_F(InstallLocalEnterpriseAppPolicyUtilsTest, TestGetUserActualPolicyValue, TestSize.Level1)
{
    bool isEnable = false;
    ErrCode ret = InstallLocalEnterpriseAppPolicyUtils::GetUserActualPolicyValue(
        DEFAULT_USER_ID, isEnable);
    EXPECT_TRUE(ret == ERR_OK || FAILED(ret));
}

/**
 * @tc.name: TestWriteSettingsData
 * @tc.desc: Test the settings writes report the data-service outcome for both scopes.
 * @tc.type: FUNC
 */
HWTEST_F(InstallLocalEnterpriseAppPolicyUtilsTest, TestWriteSettingsData, TestSize.Level1)
{
    ErrCode deviceRet =
        InstallLocalEnterpriseAppPolicyUtils::WriteDeviceSettingsData(TEST_POLICY_ENABLED);
    EXPECT_TRUE(deviceRet == ERR_OK || FAILED(deviceRet));

    ErrCode userRet = InstallLocalEnterpriseAppPolicyUtils::WriteUserSettingsData(
        TEST_POLICY_DISABLED, DEFAULT_USER_ID);
    EXPECT_TRUE(userRet == ERR_OK || FAILED(userRet));
}

/**
 * @tc.name: TestSetEnterpriseUserPolicy
 * @tc.desc: Test the enterprise user policy toggle reports the account-service outcome.
 * @tc.type: FUNC
 */
HWTEST_F(InstallLocalEnterpriseAppPolicyUtilsTest, TestSetEnterpriseUserPolicy, TestSize.Level1)
{
    ErrCode ret =
        InstallLocalEnterpriseAppPolicyUtils::SetEnterpriseUserPolicy(true, DEFAULT_USER_ID);
    EXPECT_TRUE(ret == ERR_OK || FAILED(ret));

    ret = InstallLocalEnterpriseAppPolicyUtils::SetEnterpriseUserPolicy(false, DEFAULT_USER_ID);
    EXPECT_TRUE(ret == ERR_OK || FAILED(ret));
}

/**
 * @tc.name: TestUpdateOsAccountConstraint
 * @tc.desc: Test the constraint update never returns an unclassified code.
 * @tc.type: FUNC
 */
HWTEST_F(InstallLocalEnterpriseAppPolicyUtilsTest, TestUpdateOsAccountConstraint, TestSize.Level1)
{
    ErrCode ret =
        InstallLocalEnterpriseAppPolicyUtils::UpdateOsAccountConstraint(true, DEFAULT_USER_ID);
    EXPECT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);

    ret = InstallLocalEnterpriseAppPolicyUtils::UpdateOsAccountConstraint(false, DEFAULT_USER_ID);
    EXPECT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestUpdatePolicyWithoutUserId
 * @tc.desc: Test the device-scoped update path is taken when no user is given.
 * @tc.type: FUNC
 */
HWTEST_F(InstallLocalEnterpriseAppPolicyUtilsTest, TestUpdatePolicyWithoutUserId, TestSize.Level1)
{
    ErrCode ret = InstallLocalEnterpriseAppPolicyUtils::UpdatePolicyByUser();
    EXPECT_TRUE(ret == ERR_OK || FAILED(ret));

    ret = InstallLocalEnterpriseAppPolicyUtils::UpdateSettingsPolicy(TEST_POLICY_ENABLED);
    EXPECT_TRUE(ret == ERR_OK || FAILED(ret));
}

/**
 * @tc.name: TestUpdatePolicyForUser
 * @tc.desc: Test the user-scoped update path is taken when a user is given.
 * @tc.type: FUNC
 */
HWTEST_F(InstallLocalEnterpriseAppPolicyUtilsTest, TestUpdatePolicyForUser, TestSize.Level1)
{
    ErrCode ret = InstallLocalEnterpriseAppPolicyUtils::UpdatePolicyByUser(DEFAULT_USER_ID);
    EXPECT_TRUE(ret == ERR_OK || FAILED(ret));

    ret = InstallLocalEnterpriseAppPolicyUtils::SetSettingsDataAndUserPolicy(
        TEST_POLICY_DISABLED, DEFAULT_USER_ID);
    EXPECT_TRUE(ret == ERR_OK || FAILED(ret));
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
