/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNER_API_PLUGIN_KITS_INCLUDE_IPLUGIN_EVENT_SUBSCRIBE_MANAGER_H
#define INTERFACES_INNER_API_PLUGIN_KITS_INCLUDE_IPLUGIN_EVENT_SUBSCRIBE_MANAGER_H

#include <cstdint>
#include <mutex>
#include <string>

namespace OHOS {
namespace EDM {

class IPluginEventSubscribeManager {
public:
    virtual ~IPluginEventSubscribeManager() = default;

    virtual bool SubscribeEvent(const std::string &policyName, uint32_t eventCode,
        uint32_t policyCode, bool needAdminIteration, bool useEventUserId) = 0;

    virtual bool UnsubscribeEvent(const std::string &policyName, uint32_t eventCode) = 0;

    virtual bool SubscribeCustomEvent(const std::string &policyName, uint32_t eventCode,
        uint32_t policyCode, const std::string &eventFilter, const std::string &permission) = 0;

    virtual bool UnsubscribeCustomEvent(const std::string &policyName, uint32_t eventCode) = 0;

    static IPluginEventSubscribeManager *GetInstance()
    {
        std::lock_guard<std::mutex> lock(instanceMutex_);
        return instance_;
    }

    static void SetInstance(IPluginEventSubscribeManager *instance)
    {
        std::lock_guard<std::mutex> lock(instanceMutex_);
        instance_ = instance;
    }

protected:
    IPluginEventSubscribeManager() = default;

    static IPluginEventSubscribeManager *instance_;
    static std::mutex instanceMutex_;
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_PLUGIN_KITS_INCLUDE_IPLUGIN_EVENT_SUBSCRIBE_MANAGER_H
