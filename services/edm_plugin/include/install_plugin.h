/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_INSTALL_PLUGIN_H
#define SERVICES_EDM_PLUGIN_INCLUDE_INSTALL_PLUGIN_H

#include "install_param.h"
#include "install_param_serializer.h"
#include "plugin_singleton.h"

namespace OHOS {
namespace EDM {
class InstallPlugin : public PluginSingleton<InstallPlugin, InstallParam> {
public:
    void InitPlugin(std::shared_ptr<IPluginTemplate<InstallPlugin, InstallParam>> ptr) override;

    ErrCode OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId) override;

    ErrCode OnSetPolicy(InstallParam &param, MessageParcel &reply);

private:
    bool CreateDirectory();

    bool DeleteFiles();

    ErrCode InstallParamInit(InstallParam &param, MessageParcel &reply, AppExecFwk::InstallParam &installParam,
        std::vector<std::string> &realPaths);
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_INCLUDE_INSTALL_PLUGIN_H
