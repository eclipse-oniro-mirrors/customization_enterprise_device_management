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

#ifndef SERVICES_EDM_INCLUDE_UTILS_WATERMARK_IMAGE_SERIALIZER_H
#define SERVICES_EDM_INCLUDE_UTILS_WATERMARK_IMAGE_SERIALIZER_H

#include <map>
#include "ipolicy_serializer.h"
#include "watermark_image_type.h"

namespace OHOS {
namespace EDM {

/*
 * Policy data serializer of watermark image.
 */
class WatermarkImageSerializer
    : public IPolicySerializer<std::map<std::pair<std::string, int32_t>, WatermarkImageType>>,
      public DelayedSingleton<WatermarkImageSerializer> {
public:
    bool Deserialize(const std::string &policy,
        std::map<std::pair<std::string, int32_t>, WatermarkImageType> &dataObj) override;

    bool Serialize(const std::map<std::pair<std::string, int32_t>, WatermarkImageType> &dataObj,
        std::string &policy) override;

    bool GetPolicy(MessageParcel &data, std::map<std::pair<std::string, int32_t>, WatermarkImageType> &result) override;

    bool WritePolicy(MessageParcel &reply,
        std::map<std::pair<std::string, int32_t>, WatermarkImageType> &result) override;

    bool MergePolicy(std::vector<std::map<std::pair<std::string, int32_t>, WatermarkImageType>> &data,
        std::map<std::pair<std::string, int32_t>, WatermarkImageType> &result) override;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_UTILS_WATERMARK_IMAGE_SERIALIZER_H
