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

#include "help_command.h"

#include <edm_log.h>

namespace OHOS {
namespace EDM {

const std::string HELP_USAGE = "usage: edm <command> [<options>]\n"
                               "These are common edm commands list:\n"
                               "  help                      list available commands\n"
                               "  enable-admin              enable a admin with options\n"
                               "  disable-admin             disable a admin with options\n";

HelpCommand::HelpCommand()
    : ICommand("help")
{}

ErrCode HelpCommand::Execute()
{
    return ERR_EDM_TOOLS_COMMAND_HELP;
}

std::string HelpCommand::GetUsage() const
{
    return HELP_USAGE;
}
} // namespace EDM
} // namespace OHOS
