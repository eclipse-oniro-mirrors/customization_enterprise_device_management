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

#include "disable_admin_command.h"

#include <getopt.h>

#include "edm_log.h"
#include "element_name.h"
#include "ent_info.h"
#include "enterprise_device_mgr_proxy.h"

namespace OHOS {
namespace EDM {

const std::string HELP_USAGE_DISABLE_ADMIN =
    "usage: edm disable-admin <options>\n"
    "eg:edm disable-admin -n <bundle-name>\n"
    "options list:\n"
    "  -h, --help                                  list available commands\n"
    "  -n, --bundle-name <bundle-name>             disable an admin with bundle name\n";

constexpr option DISABLE_ADMIN_LONG_OPTIONS[] = { { "help", no_argument, nullptr, 'h' },
                                                  { "bundle-name", required_argument, nullptr, 'n' },
                                                  { nullptr, 0, nullptr, 0 } };

DisableAdminCommand::DisableAdminCommand(int argc, char* argv[])
    : ICommand("disable-admin"), argc_(argc), argv_(argv)
{}

ErrCode DisableAdminCommand::Execute()
{
    ErrCode ret = ParseArgs();
    if (ret != ERR_OK) {
        return ret;
    }

    if (params_.showHelp) {
        return ERR_EDM_TOOLS_COMMAND_HELP;
    }

    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(params_.bundleName);
    ErrCode result = EnterpriseDeviceMgrProxy::GetInstance()->DisableAdmin(elementName, DEFAULT_USER_ID);
    return result;
}

std::string DisableAdminCommand::GetUsage() const
{
    return HELP_USAGE_DISABLE_ADMIN;
}

ErrCode DisableAdminCommand::ParseArgs()
{
    if (argc_ <= 1) {
        return ERR_EDM_TOOLS_COMMAND_NO_OPTION;
    }

    // reset getopt
    optind = 0;
    int optionIndex = 0;
    int c;
    bool hasOption = false;
    while ((c = getopt_long(argc_, argv_, "hn:", DISABLE_ADMIN_LONG_OPTIONS, &optionIndex)) != -1) {
        hasOption = true;
        switch (c) {
            case 'h':
                params_.showHelp = true;
                return ERR_OK;
            case 'n':
                if (!ValidateUniqueOption('t')) {
                    return ERR_EDM_TOOLS_COMMAND_OPTION_REQUIRES_ONE_ARGUMENT;
                }
                params_.bundleName = optarg;
                break;
            case '?':
            case ':': {
                switch (optopt) {
                    case 'n':
                        return ERR_EDM_TOOLS_COMMAND_N_OPTION_REQUIRES_AN_ARGUMENT;
                    default:
                        return ERR_EDM_TOOLS_COMMAND_UNKNOWN_OPTION;
                }
            }
            default:
                break;
        }
    }
    if (!hasOption) {
        return ERR_EDM_TOOLS_COMMAND_NO_OPTION;
    }
    return ERR_OK;
}

} // namespace EDM
} // namespace OHOS