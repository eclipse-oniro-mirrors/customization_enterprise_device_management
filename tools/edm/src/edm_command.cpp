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

#include "edm_command.h"

#include <getopt.h>
#include <iostream>
#include <string>

#include "admin_type.h"
#include "command_parser.h"
#include "edm_errors.h"
#include "edm_log.h"
#include "element_name.h"

namespace OHOS {
namespace EDM {

EdmCommand::EdmCommand(int argc, char* argv[])
    : argc_(argc), argv_(argv)
{
    messageMap_ = {
        //  error + message
        { ERR_EDM_TOOLS_COMMAND_NO_OPTION, "error: command requires option." },
        { ERR_EDM_TOOLS_COMMAND_N_OPTION_REQUIRES_AN_ARGUMENT,
          "error: -n, --bundle-name option requires an argument." },
        { ERR_EDM_TOOLS_COMMAND_A_OPTION_REQUIRES_AN_ARGUMENT,
          "error: -a, --ability-name option requires an argument." },
        { ERR_EDM_TOOLS_COMMAND_OPTION_REQUIRES_ONE_ARGUMENT, "error: option requires only one argument." },
        { ERR_EDM_TOOLS_COMMAND_T_OPTION_REQUIRES_AN_ARGUMENT, "error: -t, --admin-type option requires an argument." },
        { ERR_EDM_TOOLS_COMMAND_UNKNOWN_OPTION, "error: unknown option." },
        { ERR_EDM_TOOLS_COMMAND_NO_BUNDLE_NAME_OPTION, "error: -n <bundle-name> is expected." },
        { ERR_EDM_TOOLS_COMMAND_NO_ABILITY_NAME_OPTION, "error: -a <ability-name> is expected." },
        { ERR_EDM_TOOLS_COMMAND_NO_ADMIN_TYPE_OPTION, "error: -t <admin-type> is expected." },
        { ERR_EDM_TOOLS_COMMAND_UNKNOWN_ADMIN_TYPE, "error: argument <admin-type> is unknown value." },
        { EdmReturnErrCode::COMPONENT_INVALID, "error: the administrator ability component is invalid." },
        { EdmReturnErrCode::ENABLE_ADMIN_FAILED,
          "error: failed to enable the administrator application of the device." },
        { EdmReturnErrCode::DISABLE_ADMIN_FAILED,
          "error: failed to disable the administrator application of the device." }
    };
}

std::string EdmCommand::ExecCommand()
{
    auto command = CommandParser::parse(argc_, argv_);
    if (!command) {
        return HELP_MSG;
    }

    ErrCode ret = command->Execute();
    if (ret == ERR_OK) {
        return command->GetName() + " success.\n";
    } else if (ret == ERR_EDM_TOOLS_COMMAND_HELP) {
        return command->GetUsage();
    } else if (ret == EdmReturnErrCode::COMPONENT_INVALID || ret == EdmReturnErrCode::ENABLE_ADMIN_FAILED ||
               ret == EdmReturnErrCode::DISABLE_ADMIN_FAILED) {
        std::string retStr = GetMessageFromCode(ret);
        retStr.append("errorCode: " + std::to_string(ret));
        return retStr;
    } else {
        std::string retStr = GetMessageFromCode(ret);
        retStr.append(command->GetUsage());
        return retStr;
    }
}

std::string EdmCommand::GetMessageFromCode(int32_t code) const
{
    EDMLOGI("ShellCommand::GetMessageFromCode enter.");
    std::string result;
    if (messageMap_.find(code) != messageMap_.end()) {
        std::string message = messageMap_.at(code);
        if (!message.empty()) {
            result.append(message + "\n");
        }
    }
    return result;
}
} // namespace EDM
} // namespace OHOS
