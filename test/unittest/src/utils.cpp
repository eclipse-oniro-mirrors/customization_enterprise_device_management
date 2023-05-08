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
    const char* permissions[] = {EDM_MANAGE_DATETIME_PERMISSION.c_str(), EDM_FACTORY_RESET_PERMISSION.c_str(),
        EDM_MANAGE_LOCAL_ACCOUNTS_PERMISSION.c_str(), EDM_MANAGE_SECURE_SETTINGS_PERMISSION.c_str()};
    Utils::SetNativeTokenTypeAndPermissions(permissions, sizeof(permissions) / sizeof(permissions[0]));
    seteuid(Utils::EDM_UID);
}

void Utils::ResetTokenTypeAndUid()
{
    seteuid(Utils::ROOT_UID);
    SetSelfTokenID(selfTokenId_);
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
