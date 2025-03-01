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

#ifndef COMMON_NATIVE_INCLUDE_WATERMARK_PARAM_H
#define COMMON_NATIVE_INCLUDE_WATERMARK_PARAM_H

namespace OHOS {
namespace EDM {
struct WatermarkParam {
    std::string bundleName;
    int32_t accountId = 0;
    int32_t width = 0;
    int32_t height = 0;
    int32_t size = 0;
    void* pixels = nullptr;

    void SetPixels(void* data)
    {
        CheckAndFreePixels();
        pixels = data;
    }

    void CheckAndFreePixels()
    {
        if (pixels != nullptr) {
            free(pixels);
            pixels = nullptr;
        }
    }

    ~WatermarkParam()
    {
        CheckAndFreePixels();
    }
};
}
}
#endif // COMMON_NATIVE_INCLUDE_WATERMARK_PARAM_H