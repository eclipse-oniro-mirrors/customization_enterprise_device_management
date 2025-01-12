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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_CLIPBOARD_POLICY_PLUGIN_H
#define SERVICES_EDM_PLUGIN_INCLUDE_CLIPBOARD_POLICY_PLUGIN_H

#include "clipboard_policy_serializer.h"
#include "plugin_singleton.h"

namespace OHOS {
namespace EDM {
class ClipboardPolicyPlugin : public PluginSingleton<ClipboardPolicyPlugin, std::map<int32_t, ClipboardPolicy>> {
public:
    void InitPlugin(std::shared_ptr<IPluginTemplate<ClipboardPolicyPlugin,
        std::map<int32_t, ClipboardPolicy>>> ptr) override;

    ErrCode OnSetPolicy(std::map<int32_t, ClipboardPolicy> &data,
        std::map<int32_t, ClipboardPolicy> &currentData, std::map<int32_t, ClipboardPolicy> &mergeData, int32_t userId);

    ErrCode OnAdminRemove(const std::string &adminName, std::map<int32_t, ClipboardPolicy> &data,
        std::map<int32_t, ClipboardPolicy> &mergeData, int32_t userId);
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_INCLUDE_CLIPBOARD_POLICY_PLUGIN_H