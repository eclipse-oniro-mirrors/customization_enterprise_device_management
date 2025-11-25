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

#ifndef EDM_TOOLS_EDM_INCLUDE_EDM_COMMAND_H
#define EDM_TOOLS_EDM_INCLUDE_EDM_COMMAND_H

#include "enterprise_device_mgr_proxy.h"

#include <map>

namespace OHOS {
namespace EDM {
namespace {
const std::string TOOL_NAME = "edm";

const std::string HELP_MSG = "usage: edm <command> [<options>]\n"
                             "These are common edm commands list:\n"
                             "  help                      list available commands\n"
                             "  enable-admin              enable an admin with options\n"
                             "  disable-admin             disable an admin with options\n";
}  // namespace

class EdmCommand  {
public:
    EdmCommand(int argc, char *argv[]);

    std::string ExecCommand();

private:
    [[nodiscard]] std::string GetMessageFromCode(int32_t code) const;

    int argc_;
    char **argv_;
    std::map<int32_t, std::string> messageMap_;
};
} // namespace EDM
} // namespace OHOS

#endif // EDM_TOOLS_EDM_INCLUDE_EDM_COMMAND_H
