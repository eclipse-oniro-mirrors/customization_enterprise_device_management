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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_PERMISSION_MANAGED_STATE_PLUGIN_H
#define SERVICES_EDM_PLUGIN_INCLUDE_PERMISSION_MANAGED_STATE_PLUGIN_H

#include "permission_managed_state_serializer.h"
#include "plugin_singleton.h"
#include "accesstoken_kit.h"

namespace OHOS {
namespace EDM {
class SetPermissionManagedStatePlugin : public PluginSingleton<SetPermissionManagedStatePlugin,
        std::map<std::string, PermissionManagedStateInfo>> {
public:
    void InitPlugin(
        std::shared_ptr<IPluginTemplate<SetPermissionManagedStatePlugin,
        std::map<std::string, PermissionManagedStateInfo>>> ptr) override;

    ErrCode OnSetPolicy(
        std::map<std::string, PermissionManagedStateInfo> &data,
        std::map<std::string, PermissionManagedStateInfo> &currentData,
        std::map<std::string, PermissionManagedStateInfo> &mergeData, int32_t userId);

    ErrCode OnAdminRemove(
        const std::string &adminName,
        std::map<std::string, PermissionManagedStateInfo> &data,
        std::map<std::string, PermissionManagedStateInfo> &mergeData,
        int32_t userId);

    ErrCode GetAccessTokenId(int32_t userId, const std::string &appId, int32_t appIndex,
        Security::AccessToken::AccessTokenID &accessTokenId);

    ErrCode SetPermissionStatusWithPolicy(int32_t permissionFlag, PermissionManagedStateInfo info);
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_INCLUDE_PERMISSION_MANAGED_STATE_PLUGIN_H