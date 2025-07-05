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

#ifndef INTERFACES_INNER_API_DEVICE_SETTINGS_INCLUDE_WALL_PAPER_PARAM_SERIALIZER_H
#define INTERFACES_INNER_API_DEVICE_SETTINGS_INCLUDE_WALL_PAPER_PARAM_SERIALIZER_H

#include "ipolicy_serializer.h"
#include "singleton.h"
#include "wall_paper_param.h"

namespace OHOS {
namespace EDM {
/*
 * Policy data serializer of type int.
 */
class WallPaperParamSerializer : public IPolicySerializer<WallPaperParam>,
    public DelayedSingleton<WallPaperParamSerializer> {
public:
    bool Deserialize(const std::string &jsonString, WallPaperParam &dataObj) override;

    bool Serialize(const WallPaperParam &dataObj, std::string &jsonString) override;

    bool GetPolicy(MessageParcel &data, WallPaperParam &result) override;

    bool WritePolicy(MessageParcel &reply, WallPaperParam &result) override;

    bool MergePolicy(std::vector<WallPaperParam> &data, WallPaperParam &result) override;
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_DEVICE_SETTINGS_INCLUDE_WALL_PAPER_PARAM_SERIALIZER_H
