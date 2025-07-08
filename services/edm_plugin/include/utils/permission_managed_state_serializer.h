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

#ifndef INTERFACES_INNER_API_SECURITY_MANAGER_INCLUDE_PERMISSION_MANAGED_STATE_SERIALIZER_H
#define INTERFACES_INNER_API_SECURITY_MANAGER_INCLUDE_PERMISSION_MANAGED_STATE_SERIALIZER_H

#include <map>
#include "permission_managed_state_info.h"
#include "ipolicy_serializer.h"
#include "accesstoken_kit.h"
#include "edm_errors.h"

namespace OHOS {
namespace EDM {

const std::string APP_ID = "appId";
const std::string PERMISSION_NAME = "permissionName";
const std::string PERMISSION_NAMES = "permissionNames";
const std::string ACCOUNT_ID = "accountId";
const std::string APP_INDEX = "appIndex";
const std::string MANAGED_STATE = "managedState";
const std::string TOKEN_ID = "tokenId";

/*
* Policy data serializer of type int.
*/
class PermissionManagedStateSerializer : public IPolicySerializer<std::map<std::string, PermissionManagedStateInfo>>,
    public DelayedSingleton<PermissionManagedStateSerializer> {
public:

    bool Deserialize(const std::string &policy, std::map<std::string, PermissionManagedStateInfo> &dataObj) override;

    bool Serialize(const std::map<std::string, PermissionManagedStateInfo> &dataObj, std::string &policy) override;

    bool GetPolicy(MessageParcel &data, std::map<std::string, PermissionManagedStateInfo> &result) override;

    bool WritePolicy(MessageParcel &reply, std::map<std::string, PermissionManagedStateInfo> &result) override;

    bool MergePolicy(std::vector<std::map<std::string, PermissionManagedStateInfo>> &data,
        std::map<std::string, PermissionManagedStateInfo> &result) override;

    ErrCode GetAccessTokenId(int32_t userId, const std::string &appId, int32_t appIndex,
        Security::AccessToken::AccessTokenID &accessTokenId);
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_SECURITY_MANAGER_INCLUDE_PERMISSION_MANAGED_STATE_SERIALIZER_H
 