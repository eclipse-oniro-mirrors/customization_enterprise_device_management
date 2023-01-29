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

#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
IPluginManager* IPluginManager::pluginManagerInstance_ = nullptr;

IPluginManager* IPluginManager::GetInstance()
{
    if (pluginManagerInstance_ == nullptr) {
        pluginManagerInstance_ = new (std::nothrow) IPluginManager();
    }
    return pluginManagerInstance_;
}
} // namespace EDM
} // namespace OHOS
