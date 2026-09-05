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

#ifndef INTERFACES_INNER_API_COMMON_MANAGER_INCLUDE_COMMON_MANAGER_PROXY_H
#define INTERFACES_INNER_API_COMMON_MANAGER_INCLUDE_COMMON_MANAGER_PROXY_H

#include <cstdint>
#include <memory>
#include <mutex>

namespace OHOS {
namespace EDM {
class CommonManagerProxy {
public:
    static std::shared_ptr<CommonManagerProxy> GetCommonManagerProxy();
    bool IsFeatureSupported(int32_t feature);

private:
    static std::shared_ptr<CommonManagerProxy> instance_;
    static std::once_flag flag_;
};
} // namespace EDM
} // namespace OHOS
#endif // INTERFACES_INNER_API_COMMON_MANAGER_INCLUDE_COMMON_MANAGER_PROXY_H
