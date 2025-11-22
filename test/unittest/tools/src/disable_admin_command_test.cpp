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
#include "disable_admin_command.h"
#undef private

#include <getopt.h>

#include "edm_log.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {

const std::string HELP_USAGE_DISABLE_ADMIN =
    "usage: edm disable-admin <options>\n"
    "eg:edm disable-admin -n <bundle-name>\n"
    "options list:\n"
    "  -h, --help                                  list available commands\n"
    "  -n, --bundle-name <bundle-name>             disable an admin with bundle name\n";

class DisableAdminCommandTest : public testing::TestWithParam<std::tuple<std::string, ErrCode>> {};

/**
 * @tc.name: TestGetName
 * @tc.desc: Test EnableAdminCommand: test getName.
 * @tc.type: FUNC
 */
HWTEST_F(DisableAdminCommandTest, TestGetName, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("disable-admin"),
        const_cast<char*>("-h"),
    };
    auto command = std::make_unique<DisableAdminCommand>(3, argv);
    auto result = command->GetName();
    EXPECT_EQ(result, "disable-admin");
}

/**
 * @tc.name: TestGetUsage
 * @tc.desc: Test EnableAdminCommand: test getUsage.
 * @tc.type: FUNC
 */
HWTEST_F(DisableAdminCommandTest, TestGetUsage, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("disable-admin"),
        const_cast<char*>("-h"),
    };
    auto command = std::make_unique<DisableAdminCommand>(3, argv);
    auto result = command->GetUsage();
    EXPECT_EQ(result, HELP_USAGE_DISABLE_ADMIN);
}

/**
 * @tc.name: TestFullHelpOption
 * @tc.desc: Test EnableAdminCommand: test full help option.
 * @tc.type: FUNC
 */
HWTEST_F(DisableAdminCommandTest, TestFullHelpOption, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("disable-admin"),
        const_cast<char*>("--help"),
    };
    auto command = std::make_unique<DisableAdminCommand>(3, argv);
    ErrCode result = command->Execute();
    EXPECT_EQ(result, ERR_EDM_TOOLS_COMMAND_HELP);

    auto name = command->GetName();
    EXPECT_EQ(name, "disable-admin");

    auto usage = command->GetUsage();
    EXPECT_EQ(usage, HELP_USAGE_DISABLE_ADMIN);
}

/**
 * @brief Creates test data for validating shell command execution behavior.
 *
 * This function provides a comprehensive set of test cases covering various scenarios:
 * - Normal successful command execution
 * - Expected failure conditions (invalid commands)
 *
 * Each test case pairs a shell command with its anticipated result code, enabling
 * systematic testing of command execution wrappers or shell interaction modules.
 *
 * @return std::vector<std::tuple<std::string, ErrCode>> Vector of test pairs where:
 *         - First element: Shell command as string
 *         - Second element: Expected error/result code after execution
 *
 * @usage This test data is primarily intended for unit testing frameworks to verify
 *        that command execution functions handle various scenarios correctly.
 */
std::vector<std::tuple<std::string, ErrCode>> GenerateDisableCommandTestData()
{
    return {
        { "edm disable-admin -h", ERR_EDM_TOOLS_COMMAND_HELP },
        { "edm disable-admin --help", ERR_EDM_TOOLS_COMMAND_HELP },
        { "edm disable-admin -n", ERR_EDM_TOOLS_COMMAND_N_OPTION_REQUIRES_AN_ARGUMENT },
        { "edm disable-admin --bundle-name", ERR_EDM_TOOLS_COMMAND_N_OPTION_REQUIRES_AN_ARGUMENT },
        { "edm disable-admin", ERR_EDM_TOOLS_COMMAND_NO_OPTION },
        { "edm disable-admin xxx", ERR_EDM_TOOLS_COMMAND_NO_OPTION },
        { "edm disable-admin xxx -xxxx", ERR_EDM_TOOLS_COMMAND_UNKNOWN_OPTION },
        { "edm disable-admin -a", ERR_EDM_TOOLS_COMMAND_UNKNOWN_OPTION },
        { "edm disable-admin --xxx", ERR_EDM_TOOLS_COMMAND_UNKNOWN_OPTION },
        { "edm disable-admin -n super.bundle", ERR_OK },
        { "edm disable-admin --bundle-name super.bundle", ERR_OK },
        { "edm disable-admin xxx -xxxx -n super.bundle", ERR_EDM_TOOLS_COMMAND_UNKNOWN_OPTION },
        { "edm disable-admin -n super.bundle xxx -xxxx", ERR_EDM_TOOLS_COMMAND_UNKNOWN_OPTION },
        { "edm enable-admin -n xxx -n xxx", ERR_EDM_TOOLS_COMMAND_OPTION_REQUIRES_ONE_ARGUMENT },
        { "edm enable-admin -n xxx --bundle-name xxx", ERR_EDM_TOOLS_COMMAND_OPTION_REQUIRES_ONE_ARGUMENT },
    };
}

/**
 * @tc.name: DisableAdminCommandTest
 * @tc.desc: Test DisableAdminCommandTest: test execute with dynamic addition.
 * @tc.type: FUNC
 */
HWTEST_P(DisableAdminCommandTest, TestExecuteWithDynamicAddition, TestSize.Level1)
{
    auto [commandStr, expected] = GetParam();

    std::vector<std::string> tokens;
    std::stringstream ss(commandStr);
    std::string token;

    while (ss >> token) {
        tokens.push_back(token);
    }

    std::vector<std::vector<char>> stringStorage;
    std::vector<char*> argv;

    stringStorage.reserve(tokens.size());
    argv.reserve(tokens.size() + 1);

    for (const auto& token : tokens) {
        stringStorage.emplace_back(token.begin(), token.end());
        stringStorage.back().push_back('\0');
        argv.push_back(stringStorage.back().data());
    }

    argv.push_back(nullptr);

    auto command = std::make_unique<DisableAdminCommand>(argv.size() - 1, argv.data());
    ErrCode result = command->Execute();
    EXPECT_EQ(result, expected);
}

INSTANTIATE_TEST_SUITE_P(DynamicTests, DisableAdminCommandTest, testing::ValuesIn(GenerateDisableCommandTestData()));

} // namespace TEST
} // namespace EDM
} // namespace OHOS
