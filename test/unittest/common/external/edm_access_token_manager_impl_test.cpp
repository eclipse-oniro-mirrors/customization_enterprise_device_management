/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "parameters.h"
#include "edm_access_token_manager_impl.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string EDM_TEST_PERMISSION_FAIL = "ohos.permission.EDM_TEST_PERMISSION_FAIL";
const std::string EDM_TEST_PERMISSION = "ohos.permission.EDM_TEST_PERMISSION";
const std::string DEVELOP_MODE_STATE = "const.security.developermode.state";
class EdmAccessTokenManagerImplTest : public testing::Test {};
/**
 * @tc.name: TestIsDebug
 * @tc.desc: Test IsDebug function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmAccessTokenManagerImplTest, TestIsDebug, TestSize.Level1)
{
    EdmAccessTokenManagerImpl edmAccessTokenManagerImpl;
    ASSERT_TRUE(system::GetBoolParameter(DEVELOP_MODE_STATE, false) == edmAccessTokenManagerImpl.IsDebug());
}

/**
 * @tc.name: TestIsSystemAppOrNative
 * @tc.desc: Test IsSystemAppOrNative function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmAccessTokenManagerImplTest, TestIsSystemAppOrNative, TestSize.Level1)
{
    EdmAccessTokenManagerImpl edmAccessTokenManagerImpl;
    ASSERT_TRUE(edmAccessTokenManagerImpl.IsSystemAppOrNative());
}

/**
 * @tc.name: TestVerifyCallingPermission01
 * @tc.desc: Test VerifyCallingPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmAccessTokenManagerImplTest, TestVerifyCallingPermission01, TestSize.Level1)
{
    EdmAccessTokenManagerImpl edmAccessTokenManagerImpl;
    std::string permissionName;
    ASSERT_FALSE(edmAccessTokenManagerImpl.VerifyCallingPermission(permissionName));
}

/**
 * @tc.name: TestVerifyCallingPermission02
 * @tc.desc: Test VerifyCallingPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmAccessTokenManagerImplTest, TestVerifyCallingPermission02, TestSize.Level1)
{
    EdmAccessTokenManagerImpl edmAccessTokenManagerImpl;
    ASSERT_FALSE(edmAccessTokenManagerImpl.VerifyCallingPermission(EDM_TEST_PERMISSION_FAIL));
}

/**
 * @tc.name: TestVerifyCallingPermission03
 * @tc.desc: Test VerifyCallingPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmAccessTokenManagerImplTest, TestVerifyCallingPermission03, TestSize.Level1)
{
    EdmAccessTokenManagerImpl edmAccessTokenManagerImpl;
    ASSERT_FALSE(edmAccessTokenManagerImpl.VerifyCallingPermission(EDM_TEST_PERMISSION));
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS