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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_FONT_MANAGER_PLUGIN_H
#define SERVICES_EDM_PLUGIN_INCLUDE_FONT_MANAGER_PLUGIN_H

#include <string>

#include "iplugin.h"

namespace OHOS {
namespace EDM {
class FontManagerPlugin : public IPlugin {
public:
    FontManagerPlugin();
    // Map a font_manager inner error code to an EdmReturnErrCode value.
    static ErrCode MapFontManagerErrCode(int32_t ret);
    ErrCode OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
        HandlePolicyData &policyData, int32_t userId) override;
private:
    ErrCode HandleInstall(MessageParcel &data, int32_t userId);
    ErrCode HandleUninstall(MessageParcel &data, int32_t userId);
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_INCLUDE_FONT_MANAGER_PLUGIN_H
