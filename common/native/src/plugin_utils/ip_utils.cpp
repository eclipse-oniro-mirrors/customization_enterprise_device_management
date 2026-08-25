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
 
#include "ip_utils.h"
#include <regex>
 
namespace OHOS {
namespace EDM {
namespace Utils {
 
namespace {
const char* const IPV4_PATTERN =
    "((2([0-4]\\d|5[0-5])|1\\d\\d|[1-9]\\d|\\d)\\.){3}(2([0-4]\\d|5[0-5])|1\\d\\d|[1-9]\\d|\\d)";
 
const char* const IPV6_PATTERN =
    "([0-9a-fA-F]{4}:){7}[0-9a-fA-F]{4}";
}
 
bool IpUtils::IsValidIPv4(const std::string &ip)
{
    if (ip.empty()) {
        return false;
    }
    return std::regex_match(ip, std::regex(IPV4_PATTERN));
}
 
bool IpUtils::IsValidIPv6(const std::string &ip)
{
    if (ip.empty()) {
        return false;
    }
    return std::regex_match(ip, std::regex(IPV6_PATTERN));
}
 
bool IpUtils::IsValidIpAddress(const std::string &ip)
{
    return IsValidIPv4(ip) || IsValidIPv6(ip);
}
} // namespace Utils
} // namespace EDM
} // namespace OHOS