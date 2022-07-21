/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_SET_DATETIME_PLUGIN_H
#define SERVICES_EDM_PLUGIN_INCLUDE_SET_DATETIME_PLUGIN_H

#include "long_serializer.h"
#include "iplugin_template.h"

namespace OHOS {
namespace EDM {
class SetDateTimePlugin : public PluginSingleton<SetDateTimePlugin, int64_t> {
public:
    void InitPlugin(std::shared_ptr<IPluginTemplate<SetDateTimePlugin, int64_t>> ptr) override;

    ErrCode OnSetPolicy(int64_t &data);
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_INCLUDE_SET_DATETIME_PLUGIN_H
