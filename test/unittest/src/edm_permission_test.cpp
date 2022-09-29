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
#include "cmd_utils.h"
#include "edm_permission.h"
#include "func_code.h"
#include "policy_info.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class EdmPermissionTest : public testing::Test {
protected:
    void SetUp() override {}

    void TearDown() override {}
};

/**
 * @tc.name: TestEdmPermissionEqual
 * @tc.desc: Test EdmPermission Equal func.
 * @tc.type: FUNC
 */
HWTEST_F(EdmPermissionTest, TestEdmPermissionEqual, TestSize.Level1)
{
    EdmPermission permission1;
    EdmPermission permission2;
    permission1.setAdminType(AdminType::NORMAL);
    permission1.setPermissionName("ohos.permission.EDM_TEST_PERMISSION");
    permission2.setAdminType(AdminType::NORMAL);
    permission2.setPermissionName("ohos.permission.EDM_TEST_PERMISSION");
    EXPECT_TRUE(permission1 == permission2);
    permission2.setPermissionName("ohos.permission.EDM_TEST_PERMISSION_FAIL");
    EXPECT_FALSE(permission1 == permission2);
}

/**
 * @tc.name: TestMarshalling
 * @tc.desc: Test Marshalling func.
 * @tc.type: FUNC
 */
HWTEST_F(EdmPermissionTest, TestMarshalling, TestSize.Level1)
{
    EdmPermission permission1("ohos.permission.EDM_TEST_PERMISSION", AdminType::NORMAL);
    Parcel parcel;
    permission1.Marshalling(parcel);
    EdmPermission *permission2 = permission1.Unmarshalling(parcel);
    EXPECT_TRUE(permission2 != nullptr);
    EXPECT_TRUE(permission1 == *permission2);
    if (permission2) {
        delete permission2;
    }
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS