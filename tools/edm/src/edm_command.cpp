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

#include "edm_command.h"

#include <getopt.h>
#include <iostream>
#include <string>

#include "admin_type.h"
#include "element_name.h"

namespace OHOS {
namespace EDM {
const std::string SHORT_OPTIONS = "hn:a:t:";
const std::string ADMIN_TYPE_ENT_STRING = "super";
const std::string ADMIN_TYPE_BYOD_STRING = "byod";
constexpr int32_t OPTION_NUM = 4;

const struct option LONG_OPTIONS[OPTION_NUM] = {
    {"help", no_argument, nullptr, 'h'},
    {"bundle-name", required_argument, nullptr, 'n'},
    {"ability-name", required_argument, nullptr, 'a'},
    {"admin-type", required_argument, nullptr, 't'}
};

EdmCommand::EdmCommand(int argc, char *argv[]) : ShellCommand(argc, argv, TOOL_NAME) {}

ErrCode EdmCommand::CreateCommandMap()
{
    commandMap_ = {
        { "help", [this]{return this->RunAsHelpCommand();} },
        { "enable-admin", [this]{return this->RunAsEnableCommand();} },
        { "disable-admin", [this]{return this->RunAsDisableAdminCommand();} }
    };
    return ERR_OK;
}

ErrCode EdmCommand::CreateMessageMap()
{
    messageMap_ = { //  error + message
        {ERR_EDM_TOOLS_COMMAND_NO_OPTION, "error: command requires option."},
        {ERR_EDM_TOOLS_COMMAND_N_OPTION_REQUIRES_AN_ARGUMENT, "error: -n, --bundle-name option requires an argument."},
        {ERR_EDM_TOOLS_COMMAND_A_OPTION_REQUIRES_AN_ARGUMENT, "error: -a, --ability-name option requires an argument."},
        {ERR_EDM_TOOLS_COMMAND_T_OPTION_REQUIRES_AN_ARGUMENT, "error: -t, --admin-type option requires an argument."},
        {ERR_EDM_TOOLS_COMMAND_UNKNOWN_OPTION, "error: unknown option."},
        {ERR_EDM_TOOLS_COMMAND_NO_BUNDLE_NAME_OPTION, "error: -n <bundle-name> is expected."},
        {ERR_EDM_TOOLS_COMMAND_NO_ABILITY_NAME_OPTION, "error: -a <ability-name> is expected."},
        {ERR_EDM_TOOLS_COMMAND_NO_ADMIN_TYPE_OPTION, "error: -t <admin-type> is expected."},
        {ERR_EDM_TOOLS_COMMAND_UNKNOWN_ADMIN_TYPE, "error: argument <admin-type> is unknown value."},
        {EdmReturnErrCode::COMPONENT_INVALID, "error: the administrator ability component is invalid."},
        {EdmReturnErrCode::ENABLE_ADMIN_FAILED, "error: failed to enable the administrator application of the device."},
        {EdmReturnErrCode::DISABLE_ADMIN_FAILED,
            "error: failed to disable the administrator application of the device."}
    };
    return ERR_OK;
}

ErrCode EdmCommand::Init()
{
    if (!enterpriseDeviceMgrProxy_) {
        enterpriseDeviceMgrProxy_ = EnterpriseDeviceMgrProxy::GetInstance();
    }
    return ERR_OK;
}

ErrCode EdmCommand::RunAsHelpCommand()
{
    resultReceiver_.append(HELP_MSG);
    return ERR_OK;
}

ErrCode EdmCommand::RunAsEnableCommand()
{
    std::string bundleName;
    std::string abilityName;
    AdminType adminType = AdminType::ENT;
    ErrCode result = ParseEnableAdminCommandOption(bundleName, abilityName, adminType);
    if (result == ERR_EDM_TOOLS_COMMAND_HELP && bundleName.empty() &&
        abilityName.empty()) {
        return ReportMessage(ERR_EDM_TOOLS_COMMAND_HELP, true);
    }
    if (result != ERR_EDM_TOOLS_COMMAND_HELP && result != ERR_OK) {
        return ReportMessage(result, true);
    }
    if (bundleName.empty()) {
        return ReportMessage(ERR_EDM_TOOLS_COMMAND_NO_BUNDLE_NAME_OPTION, true);
    }
    if (abilityName.empty()) {
        return ReportMessage(ERR_EDM_TOOLS_COMMAND_NO_ABILITY_NAME_OPTION, true);
    }
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetElementBundleName(&elementName, bundleName.c_str());
    elementName.SetElementAbilityName(&elementName, abilityName.c_str());
    EntInfo info;
    result = enterpriseDeviceMgrProxy_->EnableAdmin(elementName, info, adminType, DEFAULT_USER_ID);
    return ReportMessage(result, true);
}

ErrCode EdmCommand::RunAsDisableAdminCommand()
{
    std::string bundleName;
    std::string abilityName;
    AdminType adminType = AdminType::UNKNOWN;
    ErrCode result = ParseEnableAdminCommandOption(bundleName, abilityName, adminType);
    if (result == ERR_EDM_TOOLS_COMMAND_HELP && bundleName.empty()) {
        return ReportMessage(ERR_EDM_TOOLS_COMMAND_HELP, false);
    }
    if (result != ERR_EDM_TOOLS_COMMAND_HELP && result != ERR_OK) {
        return ReportMessage(result, false);
    }
    if (bundleName.empty()) {
        return ReportMessage(ERR_EDM_TOOLS_COMMAND_NO_BUNDLE_NAME_OPTION, false);
    }
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetElementBundleName(&elementName, bundleName.c_str());
    elementName.SetElementAbilityName(&elementName, abilityName.c_str());
    result = enterpriseDeviceMgrProxy_->DisableAdmin(elementName, DEFAULT_USER_ID);
    return ReportMessage(result, false);
}

ErrCode EdmCommand::ParseEnableAdminCommandOption(std::string &bundleName, std::string &abilityName,
    AdminType &adminType)
{
    int count = 0;
    ErrCode ret = ERR_INVALID_VALUE;
    while (count < OPTION_NUM) {
        count++;
        int32_t option =  getopt_long(argc_, argv_, SHORT_OPTIONS.c_str(), LONG_OPTIONS, nullptr);
        if (option == -1) {
            if (count == 1) {
                ret = ERR_EDM_TOOLS_COMMAND_NO_OPTION;
            }
            break;
        }
        if (option == '?') {
            ret = RunAsEnableCommandMissingOptionArgument();
            break;
        }
        ret = RunAsEnableCommandParseOptionArgument(option, bundleName, abilityName, adminType);
    }
    return ret;
}

ErrCode EdmCommand::RunAsEnableCommandMissingOptionArgument()
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

ErrCode EdmCommand::RunAsEnableCommandParseOptionArgument(int option, std::string &bundleName,
    std::string &abilityName, AdminType &adminType)
{
    ErrCode ret = ERR_OK;
    switch (option) {
        case 'h':
            ret = ERR_EDM_TOOLS_COMMAND_HELP;
            break;
        case 'n':
            bundleName = optarg;
            break;
        case 'a':
            abilityName = optarg;
            break;
        case 't':
            ret = ConvertStringToAdminType(optarg, adminType);
            break;
        default:
            break;
    }
    return ret;
}

ErrCode EdmCommand::ReportMessage(int32_t code, bool isEnable)
{
    if (code == ERR_OK) {
        resultReceiver_.append(cmd_ + " success.\n");
        return ERR_OK;
    }
    if (code != ERR_EDM_TOOLS_COMMAND_HELP) {
        resultReceiver_.append(GetMessageFromCode(code));
    }
    if (code == EdmReturnErrCode::COMPONENT_INVALID || code == EdmReturnErrCode::ENABLE_ADMIN_FAILED ||
        code == EdmReturnErrCode::DISABLE_ADMIN_FAILED) {
        resultReceiver_.append("errorCode: " + std::to_string(code));
        return code;
    }
    if (isEnable) {
        resultReceiver_.append(HELP_MSG_ENABLE_ADMIN);
    } else {
        resultReceiver_.append(HELP_MSG_DISABLE_ADMIN);
    }
    if (code == ERR_EDM_TOOLS_COMMAND_HELP) {
        return ERR_OK;
    }
    return code;
}

ErrCode EdmCommand::ConvertStringToAdminType(std::string optarg, AdminType &adminType)
{
    ErrCode ret = ERR_OK;
    if (optarg == ADMIN_TYPE_ENT_STRING) {
        adminType = AdminType::ENT;
    } else if (optarg == ADMIN_TYPE_BYOD_STRING) {
        adminType = AdminType::BYOD;
    } else {
        adminType = AdminType::UNKNOWN;
        ret = ERR_EDM_TOOLS_COMMAND_UNKNOWN_ADMIN_TYPE;
    }
    return ret;
}
} // namespace EDM
} // namespace OHOS
