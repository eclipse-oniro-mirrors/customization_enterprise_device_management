/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <iostream>
#include <string_ex.h>

#include "element_name.h"

namespace OHOS {
namespace EDM {
constexpr int32_t ARR_INDEX_ZERO = 0;
constexpr int32_t ARR_INDEX_ONE = 1;
constexpr int32_t ARR_INDEX_TWO = 2;

constexpr size_t ARGS_SIZE_TWO = 2;
constexpr size_t ARGS_SIZE_THREE = 3;

constexpr int32_t DEFAULT_USER_ID = 100;

EdmCommand::EdmCommand(int argc, char *argv[])
    : ShellCommand(argc, argv, TOOL_NAME)
{}

ErrCode EdmCommand::CreateCommandMap()
{
    commandMap_ = {
        { "help", std::bind(&EdmCommand::RunAsHelpCommand, this) },
        { "enable-admin", std::bind(&EdmCommand::RunAsEnableAdminCommand, this) },
        { "enable-super-admin",
        std::bind(&EdmCommand::RunAsEnableSuperAdminCommand, this) },
        { "disable-admin",
        std::bind(&EdmCommand::RunDisableNormalAdminCommand, this) },
    };

    return ERR_OK;
}

ErrCode EdmCommand::CreateMessageMap()
{
    messageMap_ = { //  error + message
        {
            ERR_EDM_ADD_ADMIN_FAILED,
            "error: add admin internal error.",
        },
        {
            ERR_EDM_PERMISSION_ERROR,
            "error: permission check failed.",
        },
        {
            ERR_EDM_BMS_ERROR,
            "error: get bundle manager or query infos failed.",
        },
        {
            ERR_EDM_DENY_PERMISSION,
            "error: permission requested by app is not allowed.",
        },
        {
            ERR_EDM_DEL_ADMIN_FAILED,
            "error: disable admin internal error.",
        },
        {
            ERR_EDM_GET_PLUGIN_MGR_FAILED,
            "error: get plugin manager internal error.",
        },
        {
            ERR_EDM_PARAM_ERROR,
            "error: param count or value invalid",
        }
    };

    return ERR_OK;
}

ErrCode EdmCommand::init()
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

ErrCode EdmCommand::RunAsEnableAdminCommand()
{
    return RunAsEnableCommand(AdminType::NORMAL);
}

ErrCode EdmCommand::RunAsEnableSuperAdminCommand()
{
    return RunAsEnableCommand(AdminType::ENT);
}

ErrCode EdmCommand::RunAsEnableCommand(AdminType type)
{
    std::cout << "argc = " << argc_ << std::endl;
    if (argc_ != ARGS_SIZE_THREE) {
        resultReceiver_.append(GetMessageFromCode(ERR_EDM_PARAM_ERROR));
        return ERR_EDM_PARAM_ERROR;
    }
    std::vector<std::string> elementNameStr = split(argv_[ARR_INDEX_TWO], "/");
    if (elementNameStr.size() != ARGS_SIZE_TWO) {
        resultReceiver_.append(GetMessageFromCode(ERR_EDM_PARAM_ERROR));
        return ERR_EDM_PARAM_ERROR;
    }
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetElementBundleName(&elementName, elementNameStr[ARR_INDEX_ZERO].c_str());
    elementName.SetElementAbilityName(&elementName, elementNameStr[ARR_INDEX_ONE].c_str());
    EntInfo info;
    ErrCode result = enterpriseDeviceMgrProxy_->EnableAdmin(elementName, info, type, DEFAULT_USER_ID);
    if (result != ERR_OK) {
        resultReceiver_.append(GetMessageFromCode(result));
    }
    return result;
}

std::vector<std::string> EdmCommand::split(const std::string &str, const std::string &pattern)
{
    std::vector<std::string> res;
    if (str == "") {
        return res;
    }
    std::string strs = str + pattern;
    size_t pos = strs.find(pattern);

    while (pos != strs.npos) {
        std::string temp = strs.substr(0, pos);
        res.push_back(temp);
        strs = strs.substr(pos + 1, strs.size());
        pos = strs.find(pattern);
    }
    return res;
}

ErrCode EdmCommand::RunDisableNormalAdminCommand()
{
    std::cout << "argc = " << argc_ << std::endl;
    if (argc_ != ARGS_SIZE_THREE) {
        resultReceiver_.append(GetMessageFromCode(ERR_EDM_PARAM_ERROR));
        return ERR_EDM_PARAM_ERROR;
    }
    for (int i = 0; i < argc_; ++i) {
        std::cout << "argv[" << i << "] = " << argv_[i] << std::endl;
    }
    std::vector<std::string> elementNameStr = split(argv_[ARR_INDEX_TWO], "/");
    std::cout << "elementNameStr.size() = " << elementNameStr.size() << std::endl;
    if (elementNameStr.size() != ARGS_SIZE_TWO) {
        resultReceiver_.append(GetMessageFromCode(ERR_EDM_PARAM_ERROR));
        return ERR_EDM_PARAM_ERROR;
    }
    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetElementBundleName(&elementName, elementNameStr[ARR_INDEX_ZERO].c_str());
    elementName.SetElementAbilityName(&elementName, elementNameStr[ARR_INDEX_ONE].c_str());
    ErrCode result = enterpriseDeviceMgrProxy_->DisableAdmin(elementName, DEFAULT_USER_ID);
    if (result != ERR_OK) {
        resultReceiver_.append(GetMessageFromCode(result));
    }
    return result;
}
} // namespace EDM
} // namespace OHOS
