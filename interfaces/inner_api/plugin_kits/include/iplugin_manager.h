/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef SERVICES_EDM_INCLUDE_EDM_IPLUGIN_MANAGER_H
#define SERVICES_EDM_INCLUDE_EDM_IPLUGIN_MANAGER_H

#include <dlfcn.h>
#include <map>
#include <memory>

#include "execute_strategy.h"
#include "iplugin.h"

namespace OHOS {
namespace EDM {
class IPluginManager {
public:
    static IPluginManager* GetInstance();
    virtual bool AddPlugin(std::shared_ptr<IPlugin> plugin)
    {
        return true;
    }

    virtual bool AddExtensionPlugin(std::shared_ptr<IPlugin> extensionPlugin, uint32_t basicPluginCode,
        ExecuteStrategy strategy)
    {
        return true;
    }
    virtual ~IPluginManager() {}

protected:
    static IPluginManager* pluginManagerInstance_;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_EDM_PLUGIN_MANAGER_H
