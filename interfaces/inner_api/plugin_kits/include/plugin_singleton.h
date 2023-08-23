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

#ifndef SERVICES_EDM_INCLUDE_EDM_PLUGIN_SINGLETON_H
#define SERVICES_EDM_INCLUDE_EDM_PLUGIN_SINGLETON_H

#include "iplugin_template.h"

namespace OHOS {
namespace EDM {
/*
 * Policy processing plugin singleton mode template,which needs to inherit the template.
 *
 * @tparam CT Policy processing logic class, which is the code to be implemented.
 * @tparam DT Policy data type, for example:string,vector<string>,map<string,string>...
 */
template <typename CT, typename DT>
class PluginSingleton : public NoCopyable {
public:
    /*
     * Initialize the plugin. The subclass needs to implement the pure virtual
     * function, define the code,name and permission of the plugin, and listen
     * to policy events.
     *
     * @param ptr std::shared_ptr<IPluginTemplate<CT, DT>>
     */
    virtual void InitPlugin(std::shared_ptr<IPluginTemplate<CT, DT>> ptr) = 0;

    /*
     * Obtains the singleton of the plugin interface.
     *
     * @return std::shared_ptr<IPlugin>
     */
    static std::shared_ptr<IPlugin> GetPlugin();

    virtual ErrCode OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId);

    static void DestroyPlugin();

protected:
    static std::shared_ptr<IPluginTemplate<CT, DT>> pluginInstance_;
    static std::mutex mutexLock_;
};

template <typename CT, typename DT>
std::shared_ptr<IPluginTemplate<CT, DT>> PluginSingleton<CT, DT>::pluginInstance_ = nullptr;

template <typename CT, typename DT>
std::mutex PluginSingleton<CT, DT>::mutexLock_;

template <typename CT, typename DT>
std::shared_ptr<IPlugin> PluginSingleton<CT, DT>::GetPlugin()
{
    if (pluginInstance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutexLock_);
        if (pluginInstance_ == nullptr) {
            std::shared_ptr<CT> ptr = std::make_shared<CT>();
            pluginInstance_ = std::make_shared<IPluginTemplate<CT, DT>>();
            pluginInstance_->SetInstance(ptr);
            ptr->InitPlugin(pluginInstance_);
        }
    }
    return pluginInstance_;
}

template <typename CT, typename DT>
ErrCode PluginSingleton<CT, DT>::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("PluginSingleton::OnGetPolicy");
    return ERR_OK;
}

template <typename CT, typename DT>
void PluginSingleton<CT, DT>::DestroyPlugin()
{
    std::lock_guard<std::mutex> lock(mutexLock_);
    if (pluginInstance_ != nullptr) {
        pluginInstance_.reset();
        pluginInstance_ = nullptr;
    }
}

} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_INCLUDE_EDM_PLUGIN_SINGLETON_H