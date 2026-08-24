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
 
#ifndef EDM_COMMON_NATIVE_INCLUDE_PLUGIN_UTILS_IP_UTILS_H
#define EDM_COMMON_NATIVE_INCLUDE_PLUGIN_UTILS_IP_UTILS_H
 
#include <string>
 
namespace OHOS {
namespace EDM {
namespace Utils {
 
class IpUtils {
public:
    static bool IsValidIPv4(const std::string &ip);
    static bool IsValidIPv6(const std::string &ip);
    static bool IsValidIpAddress(const std::string &ip);
private:
    IpUtils() = default;
};
 
} // namespace Utils
} // namespace EDM
} // namespace OHOS
 
#endif // EDM_COMMON_NATIVE_INCLUDE_PLUGIN_UTILS_IP_UTILS_H