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
class ClipboardPolicyPlugin : public PluginSingleton<ClipboardPolicyPlugin, std::map<int32_t, ClipboardInfo>> {
public:
    void InitPlugin(std::shared_ptr<IPluginTemplate<ClipboardPolicyPlugin,
        std::map<int32_t, ClipboardInfo>>> ptr) override;

    ErrCode OnSetPolicy(std::map<int32_t, ClipboardInfo> &data,
        std::map<int32_t, ClipboardInfo> &currentData,
        std::map<int32_t, ClipboardInfo> &mergeData, int32_t userId);

    ErrCode OnAdminRemove(const std::string &adminName, std::map<int32_t, ClipboardInfo> &data,
        std::map<int32_t, ClipboardInfo> &mergeData, int32_t userId);
    
    ErrCode HandlePasteboardPolicy(std::map<int32_t, ClipboardInfo> &data);
    ErrCode DeleteHandle(std::map<int32_t, ClipboardInfo> &data, std::map<int32_t, ClipboardInfo> &afterHandle);
    ErrCode UpdateHandle(std::map<int32_t, ClipboardInfo> &data, std::map<int32_t, ClipboardInfo> &afterHandle);
    void OnOtherServiceStart();
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_INCLUDE_CLIPBOARD_POLICY_PLUGIN_H