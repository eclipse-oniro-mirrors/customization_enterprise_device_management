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

#include "iadmin_manager.h"

#include <gtest/gtest.h>

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class IAdminManagerTest : public testing::Test {};

/**
 * @tc.name: TestGetInstance
 * @tc.desc: Test IAdminManager::GetInstance returns one and the same instance.
 * @tc.type: FUNC
 */
HWTEST_F(IAdminManagerTest, TestGetInstance, TestSize.Level1)
{
    auto *first = IAdminManager::GetInstance();
    ASSERT_NE(first, nullptr);
    auto *second = IAdminManager::GetInstance();
    ASSERT_NE(second, nullptr);
    EXPECT_EQ(first, second);
}

/**
 * @tc.name: TestGetAdminTypeByName
 * @tc.desc: Test the base IAdminManager reports UNKNOWN for any admin name.
 * @tc.type: FUNC
 */
HWTEST_F(IAdminManagerTest, TestGetAdminTypeByName, TestSize.Level1)
{
    auto *manager = IAdminManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    EXPECT_EQ(manager->GetAdminTypeByName("com.test.admin", 100), AdminType::UNKNOWN);
    EXPECT_EQ(manager->GetAdminTypeByName("", 100), AdminType::UNKNOWN);
}

/**
 * @tc.name: TestDefaultVirtualImplementations
 * @tc.desc: Test the base IAdminManager virtuals keep their default no-op behaviour.
 * @tc.type: FUNC
 */
HWTEST_F(IAdminManagerTest, TestDefaultVirtualImplementations, TestSize.Level1)
{
    auto *manager = IAdminManager::GetInstance();
    ASSERT_NE(manager, nullptr);

    std::vector<std::string> packageNames = { "com.test.keep" };
    manager->GetAdminPackageNames(packageNames, 100);
    ASSERT_EQ(packageNames.size(), 1);
    EXPECT_EQ(packageNames.front(), "com.test.keep");

    std::vector<uint32_t> events = { 1, 2 };
    EXPECT_EQ(manager->SaveSubscribeEvents(events, "com.test.admin", 100), ERR_OK);
    EXPECT_EQ(manager->RemoveSubscribeEvents(events, "com.test.admin", 100), ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
