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

#define private public
#include "help_command.h"
#undef private

#include <getopt.h>

#include "edm_log.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {

const std::string HELP_USAGE = "usage: edm <command> [<options>]\n"
                             "These are common edm commands list:\n"
                             "  help                      list available commands\n"
                             "  enable-admin              enable an admin with options\n"
                             "  disable-admin             disable an admin with options\n";

class HelpCommandTest : public testing::Test {
};

/**
 * @tc.name: HelpCommandTest
 * @tc.desc: Test HelpCommand: test execute.
 * @tc.type: FUNC
 */
HWTEST_F(HelpCommandTest, TestExecute, TestSize.Level1)
{
    auto command = std::make_unique<HelpCommand>();
    ErrCode result = command->Execute();
    EXPECT_EQ(result, ERR_EDM_TOOLS_COMMAND_HELP);
}

/**
 * @tc.name: HelpCommandTest
 * @tc.desc: Test HelpCommand: test getName.
 * @tc.type: FUNC
 */
HWTEST_F(HelpCommandTest, TestGetName, TestSize.Level1)
{
    auto command = std::make_unique<HelpCommand>();
    auto result = command->GetName();
    EXPECT_EQ(result, "help");
}

/**
 * @tc.name: HelpCommandTest
 * @tc.desc: Test HelpCommand: test getUsage.
 * @tc.type: FUNC
 */
HWTEST_F(HelpCommandTest, TestGetUsage, TestSize.Level1)
{
    auto command = std::make_unique<HelpCommand>();
    auto result = command->GetUsage();
    EXPECT_EQ(result, HELP_USAGE);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
