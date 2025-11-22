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

#include "command_factory.h"

#include "disable_admin_command.h"
#include "enable_admin_command.h"
#include "help_command.h"

namespace OHOS {
namespace EDM {
CommandPtr CommandFactory::createCommand(const std::string& commandName, int argc, char* argv[])
{
    if (commandName == "help") {
        return std::make_unique<HelpCommand>();
    } else if (commandName == "enable-admin") {
        return std::make_unique<EnableAdminCommand>(argc, argv);
    } else if (commandName == "disable-admin") {
        return std::make_unique<DisableAdminCommand>(argc, argv);
    } else {
        return nullptr;
    }
}
} // namespace EDM
} // namespace OHOS