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

#include <cstring>
#include <iostream>
#include <string_ex.h>
#include <vector>

#include "element_name.h"

namespace OHOS {
namespace EDM {
constexpr int32_t ARR_INDEX_ZERO = 0;
constexpr int32_t ARR_INDEX_ONE = 1;
constexpr int32_t ARR_INDEX_TWO = 2;

constexpr size_t ARGS_SIZE_TWO = 2;
constexpr size_t ARGS_SIZE_THREE = 3;

constexpr int32_t DEFAULT_USER_ID = 100;

EnterpriseDeviceManagerShellCommand::EnterpriseDeviceManagerShellCommand(int argc, char *argv[])
    : ShellCommand(argc, argv, TOOL_NAME)
{}

ErrCode EnterpriseDeviceManagerShellCommand::CreateCommandMap()
{
    commandMap_ = {
        { "help", std::bind(&EnterpriseDeviceManagerShellCommand::RunAsHelpCommand, this) },
        { "activate-admin", std::bind(&EnterpriseDeviceManagerShellCommand::RunAsActivateAdminCommand, this) },
        { "activate-super-admin",
        std::bind(&EnterpriseDeviceManagerShellCommand::RunAsActivateSuperAdminCommand, this) },
        { "deactivate-admin",
        std::bind(&EnterpriseDeviceManagerShellCommand::RunDeactivateNormalAdminCommand, this) },
        { "deactivate-super-admin",
        std::bind(&EnterpriseDeviceManagerShellCommand::RunDeactivateSuperAdminCommand, this) },
    };

    return ERR_OK;
}

ErrCode EnterpriseDeviceManagerShellCommand::CreateMessageMap()
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
            "error: deactive admin internal error.",
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

ErrCode EnterpriseDeviceManagerShellCommand::init()
{
    ErrCode result = ERR_OK;

    if (!enterpriseDeviceMgrProxy_) {
        enterpriseDeviceMgrProxy_ = EnterpriseDeviceMgrProxy::GetInstance();
    }

    if (!enterpriseDeviceMgrProxy_) {
        result = OHOS::ERR_INVALID_VALUE;
    }

    return result;
}

ErrCode EnterpriseDeviceManagerShellCommand::RunAsHelpCommand()
{
    resultReceiver_.append(HELP_MSG);

    return ERR_OK;
}

ErrCode EnterpriseDeviceManagerShellCommand::RunAsActivateAdminCommand()
{
    return RunAsActivateCommand(AdminType::NORMAL);
}

ErrCode EnterpriseDeviceManagerShellCommand::RunAsActivateSuperAdminCommand()
{
    return RunAsActivateCommand(AdminType::ENT);
}

ErrCode EnterpriseDeviceManagerShellCommand::RunAsActivateCommand(AdminType type)
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
    ErrCode result = enterpriseDeviceMgrProxy_->ActivateAdmin(elementName, info, type, DEFAULT_USER_ID);
    if (result != ERR_OK) {
        resultReceiver_.append(GetMessageFromCode(result));
    }
    return result;
}

std::vector<std::string> EnterpriseDeviceManagerShellCommand::split(const std::string &str, const std::string &pattern)
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

ErrCode EnterpriseDeviceManagerShellCommand::RunDeactivateNormalAdminCommand()
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
    ErrCode result = enterpriseDeviceMgrProxy_->DeactivateAdmin(elementName, DEFAULT_USER_ID);
    if (result != ERR_OK) {
        resultReceiver_.append(GetMessageFromCode(result));
    }
    return result;
}

ErrCode EnterpriseDeviceManagerShellCommand::RunDeactivateSuperAdminCommand()
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
    ErrCode result = enterpriseDeviceMgrProxy_->DeactivateSuperAdmin(elementNameStr[ARR_INDEX_ZERO]);
    if (result != ERR_OK) {
        resultReceiver_.append(GetMessageFromCode(result));
    }
    return result;
}
} // namespace EDM
} // namespace OHOS
