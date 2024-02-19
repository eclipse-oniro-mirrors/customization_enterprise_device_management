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

#ifndef EDM_TOOLS_EDM_INCLUDE_EDM_COMMAND_H
#define EDM_TOOLS_EDM_INCLUDE_EDM_COMMAND_H

#include "shell_command.h"
#include "enterprise_device_mgr_proxy.h"

namespace OHOS {
namespace EDM {
namespace {
const std::string TOOL_NAME = "edm";

const std::string HELP_MSG = "usage: edm <command> [<options>]\n"
                             "These are common edm commands list:\n"
                             "  help                      list available commands\n"
                             "  enable-admin              enable a admin with options\n"
                             "  disable-admin             disable a admin with options\n";
}  // namespace

const std::string HELP_MSG_ENABLE_ADMIN = "usage: edm enable-admin <options>\n"
                                    "eg:edm enable-admin -n <bundle-name> -a <ability-name>\n"
                                    "options list:\n"
                                    "  -h, --help                                  list available commands\n"
                                    "  -n, --bundle-name <bundle-name>             enable an admin with bundle name\n"
                                    "  -a, --ability-name <ability-name>           enable an admin with ability name\n";

const std::string HELP_MSG_DISABLE_ADMIN = "usage: edm disable-admin <options>\n"
                                    "eg:edm disable-admin -n <bundle-name>\n"
                                    "options list:\n"
                                    "  -h, --help                                  list available commands\n"
                                    "  -n, --bundle-name <bundle-name>             disable an admin with bundle name\n";

class EdmCommand : public ShellCommand {
public:
    EdmCommand(int argc, char *argv[]);
    ~EdmCommand() override  = default;

private:
    ErrCode CreateCommandMap() override;
    ErrCode CreateMessageMap() override;
    ErrCode Init() override;
    ErrCode RunAsHelpCommand();
    ErrCode RunAsEnableCommand();
    ErrCode RunAsDisableAdminCommand();
    ErrCode ParseEnableAdminCommandOption(std::string &bundleName, std::string &abilityName);
    ErrCode RunAsEnableCommandMissingOptionArgument();
    ErrCode RunAsEnableCommandParseOptionArgument(int option, std::string &bundleName, std::string &abilityName);
    ErrCode ReportMessage(int32_t code, bool isEnable);

    std::shared_ptr<EnterpriseDeviceMgrProxy> enterpriseDeviceMgrProxy_;
};
} // namespace EDM
} // namespace OHOS

#endif // EDM_TOOLS_EDM_INCLUDE_EDM_COMMAND_H
