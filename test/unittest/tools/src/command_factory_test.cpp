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

#include "command_factory.h"
#include "edm_log.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {

class CommandFactoryTest : public testing::Test {};

/**
 * @tc.name: CommandFactoryTest
 * @tc.desc: Test CommandFactory: create help command.
 * @tc.type: FUNC
 */
HWTEST_F(CommandFactoryTest, CreateHelpCommand, TestSize.Level1)
{
    auto command = CommandFactory::createCommand("help", 0, nullptr);
    ASSERT_NE(command, nullptr);
    EXPECT_EQ(command->GetName(), "help");
}

/**
 * @tc.name: CommandFactoryTest
 * @tc.desc: Test CommandFactory: create help command.
 * @tc.type: FUNC
 */
HWTEST_F(CommandFactoryTest, CreateEnableAdminCommand, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("enable-admin"),
        const_cast<char*>("-n"),
        const_cast<char*>("com.test.app"),
        const_cast<char*>("-a"),
        const_cast<char*>("MainAbility")
    };
    auto command = CommandFactory::createCommand("enable-admin", 5, argv);
    ASSERT_NE(command, nullptr);
    EXPECT_EQ(command->GetName(), "enable-admin");
}

/**
 * @tc.name: CommandFactoryTest
 * @tc.desc: Test CommandFactory: create disable-admin command.
 * @tc.type: FUNC
 */
HWTEST_F(CommandFactoryTest, CreateDisableAdminCommand, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("disable-admin"),
        const_cast<char*>("-n"),
        const_cast<char*>("com.test.app"),
    };
    auto command = CommandFactory::createCommand("disable-admin", 4, argv);
    ASSERT_NE(command, nullptr);
    EXPECT_EQ(command->GetName(), "disable-admin");
}

/**
 * @tc.name: CommandFactoryTest
 * @tc.desc: Test CommandFactory: create error command.
 * @tc.type: FUNC
 */
HWTEST_F(CommandFactoryTest, CreateUnknownCommand, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("xxxx-admin"),
        const_cast<char*>("-n"),
        const_cast<char*>("com.test.app"),
    };
    auto command = CommandFactory::createCommand("xxxx-admin", 4, argv);
    ASSERT_EQ(command, nullptr);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS