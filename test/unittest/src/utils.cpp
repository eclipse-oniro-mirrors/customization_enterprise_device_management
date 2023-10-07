/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "utils.h"
#include "parameters.h"

namespace OHOS {
namespace EDM {
namespace TEST {
uint64_t Utils::selfTokenId_ = 0;
const std::string SET_EDM_SERVICE = "persist.edm.edm_enable";
const std::string EDM_MANAGE_DATETIME_PERMISSION = "ohos.permission.SET_TIME";
const std::string EDM_FACTORY_RESET_PERMISSION = "ohos.permission.FACTORY_RESET";
const std::string EDM_MANAGE_LOCAL_ACCOUNTS_PERMISSION = "ohos.permission.MANAGE_LOCAL_ACCOUNTS";
const std::string EDM_MANAGE_SECURE_SETTINGS_PERMISSION = "ohos.permission.MANAGE_SECURE_SETTINGS";
const std::string PERMISSION_ENTERPRISE_SUBSCRIBE_MANAGED_EVENT = "ohos.permission.ENTERPRISE_SUBSCRIBE_MANAGED_EVENT";
const std::string PERMISSION_MANAGE_ENTERPRISE_DEVICE_ADMIN = "ohos.permission.MANAGE_ENTERPRISE_DEVICE_ADMIN";
const std::string PERMISSION_SET_ENTERPRISE_INFO = "ohos.permission.SET_ENTERPRISE_INFO";
const std::string PERMISSION_ACCESS_CERT_MANAGER_INTERNAL = "ohos.permission.ACCESS_CERT_MANAGER_INTERNAL";
const std::string PERMISSION_ACCESS_CERT_MANAGER = "ohos.permission.ACCESS_CERT_MANAGER";
const std::string PERMISSION_NETSYS_INTERNAL = "ohos.permission.NETSYS_INTERNAL";
const std::string PERMISSION_INSTALL_BUNDLE = "ohos.permission.INSTALL_BUNDLE";
const std::string PERMISSION_RUNNING_STATE_OBSERVER = "ohos.permission.RUNNING_STATE_OBSERVER";
const std::string PERMISSION_ENTERPRISE_MANAGE_SECURITY = "ohos.permission.ENTERPRISE_MANAGE_SECURITY";

void Utils::ExecCmdSync(const std::string &cmd)
{
    FILE *fp = popen(cmd.c_str(), "r");
    if (fp != nullptr) {
        pclose(fp);
        fp = nullptr;
    }
}

void Utils::SetNativeTokenTypeAndPermissions(const char* permissions[], int size)
{
    uint64_t tokenId;
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = size,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = permissions,
        .acls = nullptr,
        .aplStr = "system_basic",
    };

    infoInstance.processName = "EdmServicesUnitTest";
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    seteuid(ROOT_UID);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
    seteuid(EDM_UID);
}

void Utils::SetEdmInitialEnv()
{
    selfTokenId_ = GetSelfTokenID();
    const char* permissions[] = {
        EDM_MANAGE_DATETIME_PERMISSION.c_str(),
        EDM_FACTORY_RESET_PERMISSION.c_str(),
        EDM_MANAGE_LOCAL_ACCOUNTS_PERMISSION.c_str(),
        EDM_MANAGE_SECURE_SETTINGS_PERMISSION.c_str(),
        PERMISSION_ENTERPRISE_SUBSCRIBE_MANAGED_EVENT.c_str(),
        PERMISSION_MANAGE_ENTERPRISE_DEVICE_ADMIN.c_str(),
        PERMISSION_SET_ENTERPRISE_INFO.c_str(),
        PERMISSION_ACCESS_CERT_MANAGER_INTERNAL.c_str(),
        PERMISSION_ACCESS_CERT_MANAGER.c_str(),
        PERMISSION_NETSYS_INTERNAL.c_str(),
        PERMISSION_INSTALL_BUNDLE.c_str(),
        PERMISSION_RUNNING_STATE_OBSERVER.c_str(),
        PERMISSION_ENTERPRISE_MANAGE_SECURITY.c_str()
    };
    Utils::SetNativeTokenTypeAndPermissions(permissions, sizeof(permissions) / sizeof(permissions[0]));
    seteuid(Utils::EDM_UID);
}

void Utils::ResetTokenTypeAndUid()
{
    seteuid(Utils::ROOT_UID);
    SetSelfTokenID(selfTokenId_);
}

bool Utils::IsOriginalUTEnv()
{
    return Utils::ROOT_UID == geteuid() && selfTokenId_ == GetSelfTokenID();
}

bool Utils::GetEdmServiceState()
{
    std::string edmParaValue = system::GetParameter("persist.edm.edm_enable", "false");
    return edmParaValue == "true";
}

void Utils::SetEdmServiceEnable()
{
    system::SetParameter(SET_EDM_SERVICE, "true");
}

void Utils::SetEdmServiceDisable()
{
    system::SetParameter(SET_EDM_SERVICE, "false");
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
