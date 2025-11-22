/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "edm_command_test.h"

#include <getopt.h>
#include <gtest/gtest.h>

#define private public
#include "edm_command.h"
#undef private

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
    "<admin-type>: super, byod, da.\n";

const std::string HELP_MSG_DISABLE_ADMIN =
    "usage: edm disable-admin <options>\n"
    "eg:edm disable-admin -n <bundle-name>\n"
    "options list:\n"
    "  -h, --help                                  list available commands\n"
    "  -n, --bundle-name <bundle-name>             disable an admin with bundle name\n";

void EdmCommandTest::SetUp()
{
    // reset optind to 0
    optind = 0;
}

/**
 * @tc.name: TestEdmCommandHelp
 * @tc.desc: Test EdmCommand: edm help.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCommandTest, TestEdmCommandHelp, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("help"),
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    EdmCommand cmd(argc, argv);
    std::string result1 = cmd.ExecCommand();
    EXPECT_EQ(result1, HELP_MSG);
}

/**
 * @tc.name: TestEdmCommandHelp
 * @tc.desc: Test EdmCommand: edm help.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCommandTest, TestEdmCommandHelp1, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("help"),
        const_cast<char*>("xxx"),
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    EdmCommand cmd(argc, argv);
    std::string result1 = cmd.ExecCommand();
    EXPECT_EQ(result1, HELP_MSG);
}

/**
 * @tc.name: TestEnableAdminWithoutOption
 * @tc.desc: Test EdmCommand: edm enable-admin.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCommandTest, TestEnableAdminWithoutOption, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("enable-admin"),
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    EdmCommand cmd(argc, argv);
    std::string result1 = cmd.ExecCommand();
    std::string result2 = cmd.GetMessageFromCode(ERR_EDM_TOOLS_COMMAND_NO_OPTION) + HELP_MSG_ENABLE_ADMIN;
    EXPECT_EQ(result1, result2);
}

/**
 * @tc.name: TestEnableAdminWithoutWrongOption
 * @tc.desc: Test EdmCommand: edm enable-admin xxx.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCommandTest, TestEnableAdminWithoutWrongOption, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("enable-admin"),
        const_cast<char*>("xxx"),
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    EdmCommand cmd(argc, argv);
    std::string result1 = cmd.ExecCommand();
    std::string result2 = cmd.GetMessageFromCode(ERR_EDM_TOOLS_COMMAND_NO_OPTION) + HELP_MSG_ENABLE_ADMIN;
    EXPECT_EQ(result1, result2);
}

/**
 * @tc.name: TestEnableAdminHelp
 * @tc.desc: Test EdmCommand: edm enable-admin -h.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCommandTest, TestEnableAdminHelp, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("enable-admin"),
        const_cast<char*>("-h"),
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    EdmCommand cmd(argc, argv);
    std::string result1 = cmd.ExecCommand();
    EXPECT_EQ(result1, HELP_MSG_ENABLE_ADMIN);
}

/**
 * @tc.name: TestEnableAdminHelp
 * @tc.desc: Test EdmCommand: edm enable-admin -h.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCommandTest, TestEnableAdminHelp1, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("enable-admin"),
        const_cast<char*>("-h"),
        const_cast<char*>("xxx"),
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    EdmCommand cmd(argc, argv);
    std::string result1 = cmd.ExecCommand();
    EXPECT_EQ(result1, HELP_MSG_ENABLE_ADMIN);
}

/**
 * @tc.name: TestEnableAdminWithInvalidOption
 * @tc.desc: Test EdmCommand: edm enable-admin -f.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCommandTest, TestEnableAdminWithInvalidOption, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("enable-admin"),
        const_cast<char*>("-f"),
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    EdmCommand cmd(argc, argv);
    std::string result1 = cmd.ExecCommand();
    std::string result2 = cmd.GetMessageFromCode(ERR_EDM_TOOLS_COMMAND_UNKNOWN_OPTION) + HELP_MSG_ENABLE_ADMIN;
    EXPECT_EQ(result1, result2);
}

/**
 * @tc.name: TestEnableAdminWithoutNArgument
 * @tc.desc: Test EdmCommand: edm enable-admin -n.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCommandTest, TestEnableAdminWithoutNArgument, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("enable-admin"),
        const_cast<char*>("-n"),
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    EdmCommand cmd(argc, argv);
    std::string result1 = cmd.ExecCommand();
    std::string result2 =
        cmd.GetMessageFromCode(ERR_EDM_TOOLS_COMMAND_N_OPTION_REQUIRES_AN_ARGUMENT) + HELP_MSG_ENABLE_ADMIN;
    EXPECT_EQ(result1, result2);
}

/**
 * @tc.name: TestEnableAdminWithoutFullNArgument
 * @tc.desc: Test EdmCommand: edm enable-admin -n.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCommandTest, TestEnableAdminWithoutFullNArgument, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("enable-admin"),
        const_cast<char*>("--bundle-name"),
        nullptr,
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;
    EdmCommand cmd(argc, argv);
    std::string result1 = cmd.ExecCommand();
    std::string result2 =
        cmd.GetMessageFromCode(ERR_EDM_TOOLS_COMMAND_N_OPTION_REQUIRES_AN_ARGUMENT) + HELP_MSG_ENABLE_ADMIN;
    EXPECT_EQ(result1, result2);
}

/**
 * @tc.name: TestEnableAdminWithoutAOption
 * @tc.desc: Test EdmCommand: edm enable-admin -n <bundle-name>.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCommandTest, TestEnableAdminWithoutAOption, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("enable-admin"),
        const_cast<char*>("-n"),
        const_cast<char*>("xxx"),
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    EdmCommand cmd(argc, argv);
    std::string result1 = cmd.ExecCommand();
    std::string result2 =
        cmd.GetMessageFromCode(ERR_EDM_TOOLS_COMMAND_NO_ABILITY_NAME_OPTION) + HELP_MSG_ENABLE_ADMIN;
    EXPECT_EQ(result1, result2);
}

/**
 * @tc.name: TestEnableAdminWithoutAArgument
 * @tc.desc: Test EdmCommand: edm enable-admin -a.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCommandTest, TestEnableAdminWithoutAArgument, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("enable-admin"),
        const_cast<char*>("-a"),
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    EdmCommand cmd(argc, argv);
    std::string result1 = cmd.ExecCommand();
    std::string result2 =
        cmd.GetMessageFromCode(ERR_EDM_TOOLS_COMMAND_A_OPTION_REQUIRES_AN_ARGUMENT) + HELP_MSG_ENABLE_ADMIN;
    EXPECT_EQ(result1, result2);
}

/**
 * @tc.name: TestEnableAdminWithoutNOption
 * @tc.desc: Test EdmCommand: edm enable-admin -a <ability-name>.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCommandTest, TestEnableAdminWithoutNOption, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("enable-admin"),
        const_cast<char*>("-a"),
        const_cast<char*>("xxx"),
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    EdmCommand cmd(argc, argv);
    std::string result1 = cmd.ExecCommand();
    std::string result2 = cmd.GetMessageFromCode(ERR_EDM_TOOLS_COMMAND_NO_BUNDLE_NAME_OPTION) + HELP_MSG_ENABLE_ADMIN;
    EXPECT_EQ(result1, result2);
}

/**
 * @tc.name: TestEnableAdminWithoutTArgument
 * @tc.desc: Test EdmCommand: edm enable-admin -t.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCommandTest, TestEnableAdminWithoutTArgument, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("enable-admin"),
        const_cast<char*>("-t"),
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    EdmCommand cmd(argc, argv);
    std::string result1 = cmd.ExecCommand();
    std::string result2 =
        cmd.GetMessageFromCode(ERR_EDM_TOOLS_COMMAND_T_OPTION_REQUIRES_AN_ARGUMENT) + HELP_MSG_ENABLE_ADMIN;
    EXPECT_EQ(result1, result2);
}

/**
 * @tc.name: TestEnableAdminWithTInvalidOption
 * @tc.desc: Test EdmCommand: edm enable-admin -t.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCommandTest, TestEnableAdminWithTInvalidOption, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("enable-admin"),
        const_cast<char*>("-t"),
        const_cast<char*>("XXX"),
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    EdmCommand cmd(argc, argv);
    std::string result1 = cmd.ExecCommand();
    std::string result2 =
        cmd.GetMessageFromCode(ERR_EDM_TOOLS_COMMAND_UNKNOWN_ADMIN_TYPE) + HELP_MSG_ENABLE_ADMIN;
    EXPECT_EQ(result1, result2);
}

/**
 * @tc.name: TestEnableAdminWithSuper
 * @tc.desc: Test EdmCommand: edm enable-admin -t super.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCommandTest, TestEnableAdminWithTSuper, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("enable-admin"),
        const_cast<char*>("-t"),
        const_cast<char*>("super"),
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    EdmCommand cmd(argc, argv);
    std::string result1 = cmd.ExecCommand();
    std::string result2 = cmd.GetMessageFromCode(ERR_EDM_TOOLS_COMMAND_NO_BUNDLE_NAME_OPTION) + HELP_MSG_ENABLE_ADMIN;
    EXPECT_EQ(result1, result2);
}

/**
 * @tc.name: TestEnableAdminWithTByod
 * @tc.desc: Test EdmCommand: edm enable-admin -t byod.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCommandTest, TestEnableAdminWithTByod, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("enable-admin"),
        const_cast<char*>("-t"),
        const_cast<char*>("byod"),
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    EdmCommand cmd(argc, argv);
    std::string result1 = cmd.ExecCommand();
    std::string result2 = cmd.GetMessageFromCode(ERR_EDM_TOOLS_COMMAND_NO_BUNDLE_NAME_OPTION) + HELP_MSG_ENABLE_ADMIN;
    EXPECT_EQ(result1, result2);
}

/**
 * @tc.name: TestEnableAdmin
 * @tc.desc: Test EdmCommand: edm enable-admin -n <bundle-name> -a <ability-name>.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCommandTest, TestEnableAdmin, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("enable-admin"),
        const_cast<char*>("-n"),
        const_cast<char*>("xxx"),
        const_cast<char*>("-a"),
        const_cast<char*>("xxx"),
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    EdmCommand cmd(argc, argv);
    std::string result1 = cmd.ExecCommand();
    std::string result2 = cmd.GetMessageFromCode(EdmReturnErrCode::COMPONENT_INVALID) + "errorCode: 9200003";
    EXPECT_EQ(result1, result2);
}

/**
 * @tc.name: TestEnableAdminWithTsuperSuccess
 * @tc.desc: Test EdmCommand: edm enable-admin -n <bundle-name> -a <ability-name>.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCommandTest, TestEnableAdminWithTsuperSuccess, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("enable-admin"),
        const_cast<char*>("-n"),
        const_cast<char*>("super.bundle"),
        const_cast<char*>("-a"),
        const_cast<char*>("super.ability"),
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    EdmCommand cmd(argc, argv);
    std::string result1 = cmd.ExecCommand();
    EXPECT_EQ(result1, "enable-admin success.\n");
}

/**
 * @tc.name: TestEnableAdminWithTsuper1Success
 * @tc.desc: Test EdmCommand: edm enable-admin -n <bundle-name> -a <ability-name> -t super.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCommandTest, TestEnableAdminWithTsuper1Success, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("enable-admin"),
        const_cast<char*>("-n"),
        const_cast<char*>("super.bundle"),
        const_cast<char*>("-a"),
        const_cast<char*>("super.ability"),
        const_cast<char*>("-t"),
        const_cast<char*>("super"),
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    EdmCommand cmd(argc, argv);
    std::string result1 = cmd.ExecCommand();
    EXPECT_EQ(result1, "enable-admin success.\n");
}

/**
 * @tc.name: TestEnableAdminWithTsuper2Success
 * @tc.desc: Test EdmCommand: edm enable-admin -n <bundle-name> -a <ability-name> -t da.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCommandTest, TestEnableAdminWithTsuper2Success, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("enable-admin"),
        const_cast<char*>("-n"),
        const_cast<char*>("super.bundle"),
        const_cast<char*>("-a"),
        const_cast<char*>("super.ability"),
        const_cast<char*>("-t"),
        const_cast<char*>("da"),
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    EdmCommand cmd(argc, argv);
    std::string result1 = cmd.ExecCommand();
    EXPECT_EQ(result1, "enable-admin success.\n");
}

/**
 * @tc.name: TestEnableAdminWithTbyodSuccess
 * @tc.desc: Test EdmCommand: edm enable-admin -n <bundle-name> -a <ability-name> -t byod.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCommandTest, TestEnableAdminWithTbyodSuccess, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("enable-admin"),
        const_cast<char*>("-n"),
        const_cast<char*>("byod.bundle"),
        const_cast<char*>("-a"),
        const_cast<char*>("byod.ability"),
        const_cast<char*>("-t"),
        const_cast<char*>("byod"),
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    EdmCommand cmd(argc, argv);
    std::string result1 = cmd.ExecCommand();
    EXPECT_EQ(result1, "enable-admin success.\n");
}

/**
 * @tc.name: TestEnableAdminHelpOfLong
 * @tc.desc: Test EdmCommand: edm enable-admin --help.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCommandTest, TestEnableAdminHelpOfLong, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("enable-admin"),
        const_cast<char*>("--help"),
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    EdmCommand cmd(argc, argv);
    std::string result1 = cmd.ExecCommand();
    EXPECT_EQ(result1, HELP_MSG_ENABLE_ADMIN);
}

/**
 * @tc.name: TestEnableAdminWithoutAOptionOfLong
 * @tc.desc: Test EdmCommand: edm enable-admin --bundle-name <bundle-name>.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCommandTest, TestEnableAdminWithoutAOptionOfLong, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("enable-admin"),
        const_cast<char*>("--bundle-name"),
        const_cast<char*>("xxx"),
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    EdmCommand cmd(argc, argv);
    std::string result1 = cmd.ExecCommand();
    EXPECT_EQ(result1,
              cmd.GetMessageFromCode(ERR_EDM_TOOLS_COMMAND_NO_ABILITY_NAME_OPTION) + HELP_MSG_ENABLE_ADMIN);
}

/**
 * @tc.name: TestEnableAdminWithoutNOptionOfLong
 * @tc.desc: Test EdmCommand: edm enable-admin --ability-name <ability-name>.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCommandTest, TestEnableAdminWithoutNOptionOfLong, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("enable-admin"),
        const_cast<char*>("--ability-name"),
        const_cast<char*>("xxx"),
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    EdmCommand cmd(argc, argv);
    std::string result1 = cmd.ExecCommand();
    EXPECT_EQ(result1,
        cmd.GetMessageFromCode(ERR_EDM_TOOLS_COMMAND_NO_BUNDLE_NAME_OPTION) + HELP_MSG_ENABLE_ADMIN);
}

/**
 * @tc.name: TestEnableAdminWithTsuperSuccessOfLong
 * @tc.desc: Test EdmCommand: edm enable-admin --bundle-name <bundle-name> --ability-name <ability-name>.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCommandTest, TestEnableAdminWithTsuperSuccessOfLong, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("enable-admin"),
        const_cast<char*>("--bundle-name"),
        const_cast<char*>("super.bundle"),
        const_cast<char*>("--ability-name"),
        const_cast<char*>("super.ability"),
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    EdmCommand cmd(argc, argv);
    std::string result1 = cmd.ExecCommand();
    EXPECT_EQ(result1, "enable-admin success.\n");
}

/**
 * @tc.name: TestEnableAdminWithTsuper1SuccessOfLong
 * @tc.desc: Test EdmCommand: edm enable-admin --bundle-name <bundle-name>
 *     --ability-name <ability-name> --admin-type super.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCommandTest, TestEnableAdminWithTsuper1SuccessOfLong, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("enable-admin"),
        const_cast<char*>("--bundle-name"),
        const_cast<char*>("super.bundle"),
        const_cast<char*>("--ability-name"),
        const_cast<char*>("super.ability"),
        const_cast<char*>("--admin-type"),
        const_cast<char*>("super"),
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    EdmCommand cmd(argc, argv);
    std::string result1 = cmd.ExecCommand();
    EXPECT_EQ(result1, "enable-admin success.\n");
}

/**
 * @tc.name: TestEnableAdminWithTbyodSuccessOfLong
 * @tc.desc: Test EdmCommand: edm enable-admin --bundle-name <bundle-name>
 *     --ability-name <ability-name> --admin-type byod.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCommandTest, TestEnableAdminWithTbyodSuccessOfLong, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("enable-admin"),
        const_cast<char*>("--bundle-name"),
        const_cast<char*>("byod.bundle"),
        const_cast<char*>("--ability-name"),
        const_cast<char*>("byod.ability"),
        const_cast<char*>("--admin-type"),
        const_cast<char*>("byod"),
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    EdmCommand cmd(argc, argv);
    std::string result1 = cmd.ExecCommand();
    EXPECT_EQ(result1, "enable-admin success.\n");
}

/**
 * @tc.name: TestEnableAdminOfLong
 * @tc.desc: Test EdmCommand: edm enable-admin --bundle-name <bundle-name> --ability-name <ability-name>.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCommandTest, TestEnableAdminOfLong, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("enable-admin"),
        const_cast<char*>("--bundle-name"),
        const_cast<char*>("xxx"),
        const_cast<char*>("--ability-name"),
        const_cast<char*>("xxx"),
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    EdmCommand cmd(argc, argv);
    std::string result1 = cmd.ExecCommand();
    EXPECT_EQ(result1, cmd.GetMessageFromCode(EdmReturnErrCode::COMPONENT_INVALID) + "errorCode: 9200003");
}

/**
 * @tc.name: TestDisableAdminWithoutOption
 * @tc.desc: Test EdmCommand disable admin without option.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCommandTest, TestDisableAdminWithoutOption, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("disable-admin"),
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    EdmCommand cmd(argc, argv);
    std::string result1 = cmd.ExecCommand();
    EXPECT_EQ(result1, cmd.GetMessageFromCode(ERR_EDM_TOOLS_COMMAND_NO_OPTION) + HELP_MSG_DISABLE_ADMIN);
}

/**
 * @tc.name: TestDisableAdminHelp
 * @tc.desc: Test EdmCommand: edm disable-admin -h.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCommandTest, TestDisableAdminHelp, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("disable-admin"),
        const_cast<char*>("-h"),
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    EdmCommand cmd(argc, argv);
    std::string result1 = cmd.ExecCommand();
    EXPECT_EQ(result1, HELP_MSG_DISABLE_ADMIN);
}

/**
 * @tc.name: TestDisableAdminHelp1
 * @tc.desc: Test EdmCommand: edm disable-admin -h xxx.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCommandTest, TestDisableAdminHelp1, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("disable-admin"),
        const_cast<char*>("-h"),
        const_cast<char*>("xxx"),
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    EdmCommand cmd(argc, argv);
    std::string result1 = cmd.ExecCommand();
    EXPECT_EQ(result1, HELP_MSG_DISABLE_ADMIN);
}

/**
 * @tc.name: TestDisableAdminWithInvalidOption
 * @tc.desc: Test EdmCommand: edm disable-admin -f.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCommandTest, TestDisableAdminWithInvalidOption, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("disable-admin"),
        const_cast<char*>("-f"),
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    EdmCommand cmd(argc, argv);
    std::string result1 = cmd.ExecCommand();
    EXPECT_EQ(result1, cmd.GetMessageFromCode(ERR_EDM_TOOLS_COMMAND_UNKNOWN_OPTION) + HELP_MSG_DISABLE_ADMIN);
}

/**
 * @tc.name: TestDisableAdminWithoutNArgument
 * @tc.desc: Test EdmCommand: edm disable-admin -n.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCommandTest, TestDisableAdminWithoutNArgument, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("disable-admin"),
        const_cast<char*>("-n"),
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    EdmCommand cmd(argc, argv);
    std::string result1 = cmd.ExecCommand();
    std::string result2 =
        cmd.GetMessageFromCode(ERR_EDM_TOOLS_COMMAND_N_OPTION_REQUIRES_AN_ARGUMENT) + HELP_MSG_DISABLE_ADMIN;
    EXPECT_EQ(result1, result2);
}

/**
 * @tc.name: TestDisableAdmin
 * @tc.desc: Test EdmCommand: edm disable-admin -n <bundle-name>.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCommandTest, TestDisableAdmin, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("disable-admin"),
        const_cast<char*>("-n"),
        const_cast<char*>("xxx"),
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    EdmCommand cmd(argc, argv);
    std::string result1 = cmd.ExecCommand();
    EXPECT_EQ(result1, cmd.GetMessageFromCode(EdmReturnErrCode::DISABLE_ADMIN_FAILED) + "errorCode: 9200005");
}

/**
 * @tc.name: TestDisableAdminSuccess
 * @tc.desc: Test EdmCommand: edm disable-admin -n <bundle-name> super.bundle.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCommandTest, TestDisableAdminSuccess, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("disable-admin"),
        const_cast<char*>("-n"),
        const_cast<char*>("super.bundle"),
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    EdmCommand cmd(argc, argv);
    std::string result1 = cmd.ExecCommand();
    EXPECT_EQ(result1, "disable-admin success.\n");
}

/**
 * @tc.name: TestDisableAdminHelpOfLong
 * @tc.desc: Test EdmCommand: edm disable-admin --help.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCommandTest, TestDisableAdminHelpOfLong, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("disable-admin"),
        const_cast<char*>("--help"),
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    EdmCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_DISABLE_ADMIN);
}

/**
 * @tc.name: TestDisableAdminOfLong
 * @tc.desc: Test EdmCommand: edm disable-admin --bundle-name <bundle-name>.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCommandTest, TestDisableAdminOfLong, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("disable-admin"),
        const_cast<char*>("--bundle-name"),
        const_cast<char*>("xxx"),
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    EdmCommand cmd(argc, argv);
    std::string result1 = cmd.ExecCommand();
    EXPECT_EQ(result1, cmd.GetMessageFromCode(EdmReturnErrCode::DISABLE_ADMIN_FAILED) + "errorCode: 9200005");
}

/**
 * @tc.name: TestDisableAdminSuccessOfLong
 * @tc.desc: Test EdmCommand: edm disable-admin --bundle-name <bundle-name> super.bundle.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCommandTest, TestDisableAdminSuccessOfLong, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("disable-admin"),
        const_cast<char*>("--bundle-name"),
        const_cast<char*>("super.bundle"),
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    EdmCommand cmd(argc, argv);
    std::string result1 = cmd.ExecCommand();
    EXPECT_EQ(result1, "disable-admin success.\n");
}

/**
 * @tc.name: TestErrorCommand
 * @tc.desc: Test EdmCommand: edm ***.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCommandTest, TestErrorCommand, TestSize.Level1)
{
    char* argv[] = {
        const_cast<char*>("edm"),
        const_cast<char*>("***"),
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    EdmCommand cmd(argc, argv);
    std::string result1 = cmd.ExecCommand();
    EXPECT_EQ(result1, HELP_MSG);
}

/**
 * @brief Generates test data for command-line argument parsing tests.
 *
 * This function returns a collection of test cases, each containing a command-line input
 * and the corresponding expected output. Used primarily for testing command-line argument
 * parsing functionality.
 *
 * @return std::vector<std::tuple<std::string, std::string>>
 *         Vector of test cases where each tuple contains:
 *         - First string: Simulated command-line input
 *         - Second string: Expected command-line output (empty string indicates no output or output to be defined)
 */
std::vector<std::tuple<std::string, std::string>> GenerateTestData()
{
    return {
        { "edm -h", HELP_MSG },
        { "edm enable-admin -n xxx -n xxx", "error: option requires only one argument.\n" + HELP_MSG_ENABLE_ADMIN },
        { "edm enable-admin -a xxx -a xxx", "error: option requires only one argument.\n" + HELP_MSG_ENABLE_ADMIN },
        { "edm enable-admin -t da -t byod", "error: option requires only one argument.\n" + HELP_MSG_ENABLE_ADMIN },
    };
}

/**
 * @tc.name: EnableAdminCommandTest
 * @tc.desc: Test EnableAdminCommand: test execute with dynamic addition.
 * @tc.type: FUNC
 */
HWTEST_P(EdmCommandTest, TestExecuteWithDynamicAddition, TestSize.Level1)
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

    EdmCommand cmd(argv.size() - 1, argv.data());
    std::string result1 = cmd.ExecCommand();
    EXPECT_EQ(result1, expected);
}

INSTANTIATE_TEST_SUITE_P(DynamicTests, EdmCommandTest, testing::ValuesIn(GenerateTestData()));
} // namespace TEST
} // namespace EDM
} // namespace OHOS
