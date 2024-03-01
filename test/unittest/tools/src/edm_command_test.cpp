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

#include "edm_command_test.h"

#include "edm_command.h"
#include "edm_log.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
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
        const_cast<char*>("")
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;
    EdmCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG);
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
        const_cast<char*>("")
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;
    EdmCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), cmd.GetMessageFromCode(ERR_EDM_TOOLS_COMMAND_NO_OPTION) + HELP_MSG_ENABLE_ADMIN);
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
        const_cast<char*>("")
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;
    EdmCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_ENABLE_ADMIN);
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
        const_cast<char*>("")
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;
    EdmCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), cmd.GetMessageFromCode(ERR_EDM_TOOLS_COMMAND_UNKNOWN_OPTION) + HELP_MSG_ENABLE_ADMIN);
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
        const_cast<char*>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;
    EdmCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(),
        cmd.GetMessageFromCode(ERR_EDM_TOOLS_COMMAND_N_OPTION_REQUIRES_AN_ARGUMENT) + HELP_MSG_ENABLE_ADMIN);
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
        const_cast<char*>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;
    EdmCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(),
        cmd.GetMessageFromCode(ERR_EDM_TOOLS_COMMAND_NO_ABILITY_NAME_OPTION) + HELP_MSG_ENABLE_ADMIN);
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
        const_cast<char*>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;
    EdmCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(),
        cmd.GetMessageFromCode(ERR_EDM_TOOLS_COMMAND_A_OPTION_REQUIRES_AN_ARGUMENT) + HELP_MSG_ENABLE_ADMIN);
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
        const_cast<char*>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;
    EdmCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(),
        cmd.GetMessageFromCode(ERR_EDM_TOOLS_COMMAND_NO_BUNDLE_NAME_OPTION) + HELP_MSG_ENABLE_ADMIN);
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
        const_cast<char*>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;
    EdmCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), cmd.GetMessageFromCode(EdmReturnErrCode::COMPONENT_INVALID));
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
        const_cast<char*>("")
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;
    EdmCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_ENABLE_ADMIN);
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
        const_cast<char*>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;
    EdmCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(),
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
        const_cast<char*>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;
    EdmCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(),
        cmd.GetMessageFromCode(ERR_EDM_TOOLS_COMMAND_NO_BUNDLE_NAME_OPTION) + HELP_MSG_ENABLE_ADMIN);
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
        const_cast<char*>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;
    EdmCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), cmd.GetMessageFromCode(EdmReturnErrCode::COMPONENT_INVALID));
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
        const_cast<char*>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;
    EdmCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), cmd.GetMessageFromCode(ERR_EDM_TOOLS_COMMAND_NO_OPTION) + HELP_MSG_DISABLE_ADMIN);
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
        const_cast<char*>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;
    EdmCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_DISABLE_ADMIN);
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
        const_cast<char*>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;
    EdmCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), cmd.GetMessageFromCode(ERR_EDM_TOOLS_COMMAND_UNKNOWN_OPTION) + HELP_MSG_DISABLE_ADMIN);
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
        const_cast<char*>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;
    EdmCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(),
        cmd.GetMessageFromCode(ERR_EDM_TOOLS_COMMAND_N_OPTION_REQUIRES_AN_ARGUMENT) + HELP_MSG_DISABLE_ADMIN);
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
        const_cast<char*>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;
    EdmCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), cmd.GetMessageFromCode(EdmReturnErrCode::DISABLE_ADMIN_FAILED));
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
        const_cast<char*>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;
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
        const_cast<char*>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;
    EdmCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), cmd.GetMessageFromCode(EdmReturnErrCode::DISABLE_ADMIN_FAILED));
}
} // TEST
} // EDM
} // OHOS
