/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "font_manager_plugin.h"

#include <fcntl.h>
#include <sys/stat.h>

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "edm_utils.h"
#include "font_manager_inner_api.h"
#include "func_code.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {

// Font manager inner error codes (see font_define.h FontErrorCode)
namespace {
constexpr int32_t FONT_MANAGER_ERR_OK = 0;
constexpr int32_t FONT_MANAGER_ERR_FILE_NOT_EXISTS = 31100101;
constexpr int32_t FONT_MANAGER_ERR_FILE_VERIFY_FAIL = 31100102;
constexpr int32_t FONT_MANAGER_ERR_COPY_FAIL = 31100103;
constexpr int32_t FONT_MANAGER_ERR_INSTALLED_ALREADY = 31100104;
constexpr int32_t FONT_MANAGER_ERR_MAX_FILE_COUNT = 31100105;
constexpr int32_t FONT_MANAGER_ERR_INSTALL_FAIL = 31100106;
constexpr int32_t FONT_MANAGER_ERR_UNINSTALL_FILE_NOT_EXISTS = 31100107;
constexpr int32_t FONT_MANAGER_ERR_UNINSTALL_REMOVE_FAIL = 31100108;
constexpr int32_t FONT_MANAGER_ERR_UNINSTALL_FAIL = 31100109;
} // namespace

const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<FontManagerPlugin>());

ErrCode FontManagerPlugin::MapFontManagerErrCode(int32_t ret)
{
    switch (ret) {
        case FONT_MANAGER_ERR_OK:
            return ERR_OK;
        case FONT_MANAGER_ERR_FILE_NOT_EXISTS:
            return EdmReturnErrCode::FONT_FILE_NOT_EXISTS;
        case FONT_MANAGER_ERR_FILE_VERIFY_FAIL:
            return EdmReturnErrCode::FONT_FILE_VERIFY_FAIL;
        case FONT_MANAGER_ERR_INSTALLED_ALREADY:
            return EdmReturnErrCode::FONT_INSTALLED_ALREADY;
        case FONT_MANAGER_ERR_MAX_FILE_COUNT:
            return EdmReturnErrCode::FONT_MAX_FILE_COUNT;
        case FONT_MANAGER_ERR_UNINSTALL_FILE_NOT_EXISTS:
            return EdmReturnErrCode::FONT_UNINSTALL_NOT_EXISTS;
        case FONT_MANAGER_ERR_COPY_FAIL:
        case FONT_MANAGER_ERR_INSTALL_FAIL:
        case FONT_MANAGER_ERR_UNINSTALL_REMOVE_FAIL:
        case FONT_MANAGER_ERR_UNINSTALL_FAIL:
        default:
            return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
}

FontManagerPlugin::FontManagerPlugin()
{
    EDMLOGI("FontManagerPlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::FONT_MANAGER;
    policyName_ = PolicyName::POLICY_FONT_MANAGER;
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SYSTEM);
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = false;
}

ErrCode FontManagerPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    EDMLOGI("FontManagerPlugin OnHandlePolicy");
    auto operateType = static_cast<FuncOperateType>(FUNC_TO_OPERATE(funcCode));
    if (operateType == FuncOperateType::SET) {
        return HandleInstall(data, userId);
    }
    if (operateType == FuncOperateType::REMOVE) {
        return HandleUninstall(data, userId);
    }
    EDMLOGW("FontManagerPlugin unsupported operate type: %{public}d.", static_cast<int32_t>(operateType));
    return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
}

ErrCode FontManagerPlugin::HandleInstall(MessageParcel &data, int32_t userId)
{
    int32_t fd = data.ReadFileDescriptor();
    if (fd < 0) {
        EDMLOGE("FontManagerPlugin read font file descriptor failed.");
        return EdmReturnErrCode::FONT_FILE_NOT_EXISTS;
    }
    fdsan_exchange_owner_tag(fd, 0, EdmConstants::LOG_DOMAINID);
    ErrCode ret = ERR_OK;
    struct stat statBuff;
    if (fstat(fd, &statBuff) != 0 || !S_ISREG(statBuff.st_mode)) {
        EDMLOGE("FontManagerPlugin invalid font file.");
        ret = EdmReturnErrCode::INVALID_PATH;
    } else if (statBuff.st_size <= 0 || statBuff.st_size > EdmConstants::SystemManager::MAX_FONT_FILE_SIZE) {
        EDMLOGE("FontManagerPlugin font file size check fail.");
        ret = EdmReturnErrCode::FONT_FILE_VERIFY_FAIL;
    }
    if (ret == ERR_OK) {
        // InstallFontByFd does not close the fd; it must stay open with stable content during the call.
        int32_t installRet = Global::FontManager::FontManagerInnerApi::InstallFontByFd(fd, userId);
        EDMLOGI("FontManagerPlugin InstallFontByFd userId=%{public}d ret=%{public}d.", userId, installRet);
        ret = MapFontManagerErrCode(installRet);
    }
    fdsan_close_with_tag(fd, EdmConstants::LOG_DOMAINID);
    return ret;
}

ErrCode FontManagerPlugin::HandleUninstall(MessageParcel &data, int32_t userId)
{
    std::string fontName = data.ReadString();
    if (fontName.empty()) {
        EDMLOGW("FontManagerPlugin invalid fontName.");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    int32_t ret = Global::FontManager::FontManagerInnerApi::UninstallFontByFullName(fontName, userId);
    EDMLOGI("FontManagerPlugin UninstallFontByFullName userId=%{public}d ret=%{public}d.", userId, ret);
    return MapFontManagerErrCode(ret);
}
} // namespace EDM
} // namespace OHOS
