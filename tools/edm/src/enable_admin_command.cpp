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

#include "enable_admin_command.h"

#include <getopt.h>

#include "edm_log.h"
#include "element_name.h"
#include "ent_info.h"
#include "enterprise_device_mgr_proxy.h"

namespace OHOS {
namespace EDM {

const std::string HELP_USAGE_ENABLE_ADMIN =
    "usage: edm enable-admin <options>\n"
    "eg:edm enable-admin -n <bundle-name> -a <ability-name> -t <admin-type>\n"
    "options list:\n"
    "  -h, --help                                  list available commands\n"
    "  -n, --bundle-name <bundle-name>             enable an admin with bundle name\n"
    "  -a, --ability-name <ability-name>           enable an admin with ability name\n"
    "  -t, --admin-type <admin-type>               enable an admin with admin type,"
    "<admin-type>: super, byod, da.\n";

constexpr option ENABLE_ADMIN_LONG_OPTIONS[] = {
    { "help", no_argument, nullptr, 'h' },
    { "bundle-name", required_argument, nullptr, 'n' },
    { "ability-name", required_argument, nullptr, 'a' },
    { "admin-type", required_argument, nullptr, 't' },
    { nullptr, no_argument, nullptr, 0 }
};

EnableAdminCommand::EnableAdminCommand(int argc, char* argv[])
    : ICommand("enable-admin"), argc_(argc), argv_(argv)
{}

ErrCode EnableAdminCommand::Execute()
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
    elementName.SetAbilityName(params_.abilityName);
    EntInfo info;
    ErrCode result =
        EnterpriseDeviceMgrProxy::GetInstance()->EnableAdmin(elementName, info, params_.adminType, DEFAULT_USER_ID);
    return result;
}

std::string EnableAdminCommand::GetUsage() const
{
    return HELP_USAGE_ENABLE_ADMIN;
}

ErrCode EnableAdminCommand::ParseArgs()
{
    if (argc_ <= 1) {
        return ERR_EDM_TOOLS_COMMAND_NO_OPTION;
    }

    bool hasOption = false;
    auto ret = ParseArgs(hasOption);
    if (ret != ERR_OK) {
        return ret;
    }

    if (params_.showHelp) {
        return ERR_OK;
    }

    if (!hasOption) {
        return ERR_EDM_TOOLS_COMMAND_NO_OPTION;
    }
    if (params_.bundleName.empty()) {
        return ERR_EDM_TOOLS_COMMAND_NO_BUNDLE_NAME_OPTION;
    }
    if (params_.abilityName.empty()) {
        return ERR_EDM_TOOLS_COMMAND_NO_ABILITY_NAME_OPTION;
    }
    return ERR_OK;
}

ErrCode EnableAdminCommand::ParseArgs(bool& hasOption)
{
    // reset getopt
    optind = 0;
    int c;
    while ((c = getopt_long(argc_, argv_, "hn:a:t:", ENABLE_ADMIN_LONG_OPTIONS, nullptr)) != -1) {
        hasOption = true;
        switch (c) {
            case 'h':
                params_.showHelp = true;
                return ERR_OK;
            case 'n':
                if (!ValidateUniqueOption('n')) {
                    return ERR_EDM_TOOLS_COMMAND_OPTION_REQUIRES_ONE_ARGUMENT;
                }
                params_.bundleName = (optarg == nullptr ? "" : std::string(optarg));
                break;
            case 'a':
                if (!ValidateUniqueOption('a')) {
                    return ERR_EDM_TOOLS_COMMAND_OPTION_REQUIRES_ONE_ARGUMENT;
                }
                params_.abilityName = (optarg == nullptr ? "" : std::string(optarg));
                break;
            case 't': {
                if (!ValidateUniqueOption('t')) {
                    return ERR_EDM_TOOLS_COMMAND_OPTION_REQUIRES_ONE_ARGUMENT;
                }
                ErrCode ret =
                    this->ConvertStringToAdminType(optarg == nullptr ? "" : std::string(optarg), params_.adminType);
                if (ret != ERR_OK) {
                    return ret;
                }
                break;
            }
            case '?':
            case ':':
                return ParseMissingOptionArgs();
            default:
                break;
        }
    }
    return ERR_OK;
}

ErrCode EnableAdminCommand::ParseMissingOptionArgs()
{
    switch (optopt) {
        case 'n':
            return ERR_EDM_TOOLS_COMMAND_N_OPTION_REQUIRES_AN_ARGUMENT;
        case 'a':
            return ERR_EDM_TOOLS_COMMAND_A_OPTION_REQUIRES_AN_ARGUMENT;
        case 't':
            return ERR_EDM_TOOLS_COMMAND_T_OPTION_REQUIRES_AN_ARGUMENT;
        default:
            return ERR_EDM_TOOLS_COMMAND_UNKNOWN_OPTION;
    }
}

ErrCode EnableAdminCommand::ConvertStringToAdminType(std::string optarg, AdminType& adminType)
{
    ErrCode ret = ERR_OK;
    if (optarg == "super") {
        adminType = AdminType::ENT;
    } else if (optarg == "byod") {
        adminType = AdminType::BYOD;
    } else if (optarg == "da") {
        adminType = AdminType::NORMAL;
    } else {
        adminType = AdminType::UNKNOWN;
        ret = ERR_EDM_TOOLS_COMMAND_UNKNOWN_ADMIN_TYPE;
    }
    return ret;
}

} // namespace EDM
} // namespace OHOS