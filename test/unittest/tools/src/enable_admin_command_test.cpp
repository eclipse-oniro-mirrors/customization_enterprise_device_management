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
#include "enable_admin_command.h"
#undef private

#include <getopt.h>

#include "edm_log.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {

const std::string HELP_MSG_ENABLE_ADMIN =
    "usage: edm enable-admin <options>\n"
    "eg:edm enable-admin -n <bundle-name> -a <ability-name> -t <admin-type>\n"
    "options list:\n"
    "  -h, --help                                  list available commands\n"
    "  -n, --bundle-name <bundle-name>             enable an admin with bundle name\n"
    "  -a, --ability-name <ability-name>           enable an admin with ability name\n"
    "  -t, --admin-type <admin-type>               enable an admin with admin type,"
#ifdef FEATURE_PC_ONLY
    "<admin-type>: super, byod, da.\n";
#else
    "<admin-type>: super, byod.\n";
#endif

class EnableAdminCommandTest : public testing::TestWithParam<std::tuple<std::string, ErrCode>> {};

/**
 * @tc.name: TestGetName
 * @tc.desc: Test EnableAdminCommand: test getName.
 * @tc.type: FUNC
 */
HWTEST_F(EnableAdminCommandTest, TestGetName, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("enable-admin"),
        const_cast<char*>("-h"),
    };
    auto command = std::make_unique<EnableAdminCommand>(3, argv);
    auto result = command->GetName();
    EXPECT_EQ(result, "enable-admin");
}

/**
 * @tc.name: TestGetUsage
 * @tc.desc: Test EnableAdminCommand: test getUsage.
 * @tc.type: FUNC
 */
HWTEST_F(EnableAdminCommandTest, TestGetUsage, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("enable-admin"),
        const_cast<char*>("-h"),
    };
    auto command = std::make_unique<EnableAdminCommand>(3, argv);
    auto result = command->GetUsage();
    EXPECT_EQ(result, HELP_MSG_ENABLE_ADMIN);
}

/**
 * @tc.name: TestFullHelpOption
 * @tc.desc: Test EnableAdminCommand: test full help option.
 * @tc.type: FUNC
 */
HWTEST_F(EnableAdminCommandTest, TestFullHelpOption, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("enable-admin"),
        const_cast<char*>("--help"),
    };
    auto command = std::make_unique<EnableAdminCommand>(3, argv);
    ErrCode result = command->Execute();
    EXPECT_EQ(result, ERR_EDM_TOOLS_COMMAND_HELP);

    auto name = command->GetName();
    EXPECT_EQ(name, "enable-admin");

    auto usage = command->GetUsage();
    EXPECT_EQ(usage, HELP_MSG_ENABLE_ADMIN);
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
std::vector<std::tuple<std::string, ErrCode>> GenerateEnableAdminTestData()
{
    return {
        { "edm enable-admin -h", ERR_EDM_TOOLS_COMMAND_HELP },
        { "edm enable-admin --help", ERR_EDM_TOOLS_COMMAND_HELP },
        { "edm enable-admin -n ohos.test.hap -m MainAbility", ERR_EDM_TOOLS_COMMAND_UNKNOWN_OPTION },
        { "edm enable-admin --bundle-name ohos.test.hap -m MainAbility", ERR_EDM_TOOLS_COMMAND_UNKNOWN_OPTION },
        { "edm enable-admin -m ohos.test.hap --ability-name MainAbility", ERR_EDM_TOOLS_COMMAND_UNKNOWN_OPTION },
        { "edm enable-admin --bundle-name ohos.test.hap", ERR_EDM_TOOLS_COMMAND_NO_ABILITY_NAME_OPTION },
        { "edm enable-admin -n", ERR_EDM_TOOLS_COMMAND_N_OPTION_REQUIRES_AN_ARGUMENT },
        { "edm enable-admin --bundle-name", ERR_EDM_TOOLS_COMMAND_N_OPTION_REQUIRES_AN_ARGUMENT },
        { "edm enable-admin -a MainAbility", ERR_EDM_TOOLS_COMMAND_NO_BUNDLE_NAME_OPTION },
        { "edm enable-admin --ability-name MainAbility", ERR_EDM_TOOLS_COMMAND_NO_BUNDLE_NAME_OPTION },
        { "edm enable-admin -a", ERR_EDM_TOOLS_COMMAND_A_OPTION_REQUIRES_AN_ARGUMENT },
        { "edm enable-admin --ability-name", ERR_EDM_TOOLS_COMMAND_A_OPTION_REQUIRES_AN_ARGUMENT },
        { "edm enable-admin", ERR_EDM_TOOLS_COMMAND_NO_OPTION },
        { "edm enable-admin xxx", ERR_EDM_TOOLS_COMMAND_NO_OPTION },
        { "edm enable-admin --xxx", ERR_EDM_TOOLS_COMMAND_UNKNOWN_OPTION },
        { "edm enable-admin -n ohos.test.hap -a xxx", EdmReturnErrCode::COMPONENT_INVALID },
        { "edm enable-admin --bundle-name ohos.test.hap --ability-name xxx", EdmReturnErrCode::COMPONENT_INVALID },
        { "edm enable-admin -t", ERR_EDM_TOOLS_COMMAND_T_OPTION_REQUIRES_AN_ARGUMENT },
        { "edm enable-admin --admin-type", ERR_EDM_TOOLS_COMMAND_T_OPTION_REQUIRES_AN_ARGUMENT },
        { "edm enable-admin -t super", ERR_EDM_TOOLS_COMMAND_NO_BUNDLE_NAME_OPTION },
        { "edm enable-admin --admin-type super", ERR_EDM_TOOLS_COMMAND_NO_BUNDLE_NAME_OPTION },
        { "edm enable-admin -n super.bundle -a super.ability -t super", ERR_OK },
        { "edm enable-admin --bundle-name super.bundle -a super.ability -t super", ERR_OK },
        { "edm enable-admin -n super.bundle -a super.ability -t super", ERR_OK },
        { "edm enable-admin -n byod.bundle -a byod.ability -t byod", ERR_OK },
        { "edm enable-admin --bundle-name byod.bundle -a byod.ability -t byod", ERR_OK },
        { "edm enable-admin -n byod.bundle --ability-name byod.ability -t byod", ERR_OK },
#ifdef FEATURE_PC_ONLY
        { "edm enable-admin -n da.bundle -a da.ability -t da", ERR_OK },
        { "edm enable-admin --bundle-name da.bundle -a da.ability -t da", ERR_OK },
        { "edm enable-admin -n da.bundle --ability-name da.ability -t da", ERR_OK },
        { "edm enable-admin --ability-name da.ability -n da.bundle -t da", ERR_OK },
        { "edm enable-admin -t da --ability-name da.ability -n da.bundle", ERR_OK },
        { "edm enable-admin -n da.bundle -t da --ability-name da.ability", ERR_OK },
        { "edm enable-admin -t da -t byod", ERR_EDM_TOOLS_COMMAND_OPTION_REQUIRES_ONE_ARGUMENT },
#endif
        { "edm enable-admin -n xxx -n xxx", ERR_EDM_TOOLS_COMMAND_OPTION_REQUIRES_ONE_ARGUMENT },
        { "edm enable-admin -a xxx -a xxx", ERR_EDM_TOOLS_COMMAND_OPTION_REQUIRES_ONE_ARGUMENT },
    };
}

/**
 * @tc.name: EnableAdminCommandTest
 * @tc.desc: Test EnableAdminCommand: test execute with dynamic addition.
 * @tc.type: FUNC
 */
HWTEST_P(EnableAdminCommandTest, TestExecuteWithDynamicAddition, TestSize.Level1)
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

    auto command = std::make_unique<EnableAdminCommand>(argv.size() - 1, argv.data());
    ErrCode result = command->Execute();
    EXPECT_EQ(result, expected);
}

INSTANTIATE_TEST_SUITE_P(DynamicTests, EnableAdminCommandTest, testing::ValuesIn(GenerateEnableAdminTestData()));

} // namespace TEST
} // namespace EDM
} // namespace OHOS
