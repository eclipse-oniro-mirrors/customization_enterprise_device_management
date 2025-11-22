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

#include "command_parser.h"
#include "edm_log.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {

class CommandParserTest : public ::testing::Test {
protected:
    void SetUp() override
    {}
};

HWTEST_F(CommandParserTest, ParseHelpCommand, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("help"),
    };
    auto command = CommandParser::parse(2, argv);
    EXPECT_EQ(command->GetName(), "help");
}

HWTEST_F(CommandParserTest, ParseHelpCommandWithErrorParam, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        nullptr,
    };
    auto command = CommandParser::parse(2, argv);
    EXPECT_EQ(command->GetName(), "help");
}

HWTEST_F(CommandParserTest, ParseEnableAdminWithRequiredParams, TestSize.Level1)
{
    char* argv[] = { const_cast<char*>("edm"), const_cast<char*>("enable-admin"),
                     const_cast<char*>("-n"),  const_cast<char*>("com.test.app"),
                     const_cast<char*>("-a"),  const_cast<char*>("MainAbility") };

    auto command = CommandParser::parse(6, argv);
    EXPECT_TRUE(command->GetName() == "enable-admin");
}

HWTEST_F(CommandParserTest, ParseDisableAdminWithRequiredParam, TestSize.Level1)
{
    char* argv[] = { const_cast<char*>("edm"), const_cast<char*>("disable-admin"), const_cast<char*>("-n"),
                     const_cast<char*>("com.test.app") };
    auto command = CommandParser::parse(4, argv);
    EXPECT_TRUE(command->GetName() == "disable-admin");
}

HWTEST_F(CommandParserTest, ParseNullCommandWithErrorParam, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("xxxx-admin"),
    };
    auto command = CommandParser::parse(2, argv);
    EXPECT_EQ(command, nullptr);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS