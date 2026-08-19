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

#ifndef COMMON_NATIVE_INCLUDE_PUBLISH_FORM_TO_DESKTOP_PARAM_H
#define COMMON_NATIVE_INCLUDE_PUBLISH_FORM_TO_DESKTOP_PARAM_H

#include <string>
#include "parcel_macro.h"

namespace OHOS {
namespace EDM {
struct PublishFormToDesktopParam {
    std::string bundleName; // 卡片所属包的Bundle名称
    std::string moduleName; // 卡片所属模块的模块名称
    std::string abilityName; // 卡片所属的Ability名称
    std::string name; // 卡片名称
    int32_t dimension = 0; // 卡片尺寸枚举数值

    bool Marshalling(MessageParcel &data) const
    {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, data, bundleName);
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, data, moduleName);
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, data, abilityName);
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, data, name);
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, data, dimension);
        return true;
    }

    static bool UnMarshalling(MessageParcel &data, PublishFormToDesktopParam &param)
    {
        READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, data, param.bundleName);
        READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, data, param.moduleName);
        READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, data, param.abilityName);
        READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, data, param.name);
        READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, data, param.dimension);
        return true;
    }
};
} // namespace EDM
} // namespace OHOS
#endif // COMMON_NATIVE_INCLUDE_PUBLISH_FORM_TO_DESKTOP_PARAM_H