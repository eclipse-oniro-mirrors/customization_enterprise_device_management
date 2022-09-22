/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include <vector>
#include "permission_manager.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class PermissionManagerTest : public testing::Test {
protected:
    // Sets up the test fixture.
    void SetUp() override;

    // Tears down the test fixture.
    void TearDown() override;
};

void PermissionManagerTest::SetUp()
{
}

void PermissionManagerTest::TearDown()
{
    PermissionManager::DestroyInstance();
}

/**
 * @tc.name: TestAddPermission
 * @tc.desc: Test PermissionManager AddPermission func.
 * @tc.type: FUNC
 */
HWTEST_F(PermissionManagerTest, TestAddPermission, TestSize.Level1)
{
    ASSERT_NE(PermissionManager::GetInstance()->AddPermission(
        std::string("ohos.permission.EMD_TEST_PERMISSION_FAIL")),
        ERR_OK);
    ASSERT_EQ(PermissionManager::GetInstance()->AddPermission(
        std::string("ohos.permission.EDM_TEST_PERMISSION")),
        ERR_OK);
}

/**
 * @tc.name: GetReqPermission01
 * @tc.desc: Test PermissionManager ReqPermission func.
 * @tc.type: FUNC
 */
HWTEST_F(PermissionManagerTest, GetReqPermission01, TestSize.Level1)
{
    PermissionManager::GetInstance()->AddPermission(
        std::string("ohos.permission.EDM_TEST_PERMISSION"));
    std::vector<std::string> permission = {
        "ohos.permission.EDM_TEST_PERMISSION", "ohos.permission.EMD_TEST_PERMISSION_FAIL" };
    std::vector<AdminPermission> reqPermission;
    PermissionManager::GetInstance()->GetReqPermission(permission, reqPermission);
    ASSERT_TRUE(reqPermission.size() == 1);
}

/**
 * @tc.name: GetReqPermission02
 * @tc.desc: Test PermissionManager ReqPermission func.
 * @tc.type: FUNC
 */
HWTEST_F(PermissionManagerTest, GetReqPermission02, TestSize.Level1)
{
    PermissionManager::GetInstance()->AddPermission(
        std::string("ohos.permission.EDM_TEST_ENT_PERMISSION"));
    std::vector<std::string> permission = {
        "ohos.permission.EDM_TEST_ENT_PERMISSION", "ohos.permission.EMD_TEST_PERMISSION_FAIL" };
    std::vector<EdmPermission> reqPermission;
    PermissionManager::GetInstance()->GetReqPermission(permission, reqPermission);
    ASSERT_TRUE(reqPermission.size() == 1);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
