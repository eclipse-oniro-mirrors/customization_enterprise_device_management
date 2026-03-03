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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_ALLOWED_NOTIFICATION_BUNDLES_PLUGIN_H
#define SERVICES_EDM_PLUGIN_INCLUDE_ALLOWED_NOTIFICATION_BUNDLES_PLUGIN_H

#include "allowed_notification_bundles_type.h"
#include "plugin_singleton.h"

namespace OHOS {
namespace EDM {

class AllowedNotificationBundlesPlugin : public
    PluginSingleton<AllowedNotificationBundlesPlugin, std::vector<AllowedNotificationBundlesType>> {
public:
    void InitPlugin(std::shared_ptr<IPluginTemplate<AllowedNotificationBundlesPlugin,
        std::vector<AllowedNotificationBundlesType>>> ptr) override;

private:
    ErrCode OnSetPolicy(std::vector<AllowedNotificationBundlesType> &data,
        std::vector<AllowedNotificationBundlesType> &currentData,
        std::vector<AllowedNotificationBundlesType> &mergeData, int32_t userId);

    ErrCode OnRemovePolicy(std::vector<AllowedNotificationBundlesType> &data,
        std::vector<AllowedNotificationBundlesType> &currentData,
        std::vector<AllowedNotificationBundlesType> &mergeData, int32_t userId);

    ErrCode OnAdminRemove(const std::string &adminName, std::vector<AllowedNotificationBundlesType> &data,
        std::vector<AllowedNotificationBundlesType> &mergeData, int32_t userId)
    {
        return ERR_OK;
    }

    void FindUserTrustList(std::vector<AllowedNotificationBundlesType> &data, int32_t userId,
        std::set<std::string> *&trustList);

    ErrCode SetAdditionConfig(std::vector<AllowedNotificationBundlesType> &data);
};

} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_INCLUDE_ALLOWED_NOTIFICATION_BUNDLES_PLUGIN_H
