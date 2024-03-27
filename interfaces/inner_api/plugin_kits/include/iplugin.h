/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef SERVICES_EDM_INCLUDE_EDM_IPLUGIN_H
#define SERVICES_EDM_INCLUDE_EDM_IPLUGIN_H

#include <iostream>
#include <map>
#include <string>
#include "edm_errors.h"
#include "func_code.h"
#include "handle_policy_data.h"
#include "iplugin_execute_strategy.h"
#include "message_parcel.h"

namespace OHOS {
namespace EDM {
constexpr int32_t DEFAULT_USER_ID = 100;
constexpr const char *NONE_PERMISSION_MATCH = "NA";

class IPlugin {
public:
    enum class PluginType {
        BASIC = 0,
        EXTENSION,
    };

    enum class PermissionType {
        NORMAL_DEVICE_ADMIN = 0,
        SUPER_DEVICE_ADMIN,
        UNKNOWN,
    };

    enum class ApiType {
        PUBLIC = 0,
        SYSTEM,
        TEST,
        UNKNOWN,
    };

    struct PolicyPermissionConfig {
        std::string permission;
        std::map<std::string, std::string> tagPermissions;
        PermissionType permissionType;
        ApiType apiType;

        PolicyPermissionConfig()
        {
            permissionType = PermissionType::UNKNOWN;
            apiType = ApiType::UNKNOWN;
        }

        PolicyPermissionConfig(std::string _permission, PermissionType _permissionType, ApiType _apiType)
            : permission(std::move(_permission)), permissionType(std::move(_permissionType)),
            apiType(std::move(_apiType)) {}

        PolicyPermissionConfig(std::map<std::string, std::string> _tagPermissions,
            PermissionType _permissionType, ApiType _apiType) : tagPermissions(std::move(_tagPermissions)),
            permissionType(std::move(_permissionType)), apiType(std::move(_apiType)) {}
    };

    /*
     * handle policy
     *
     * @param funcCode func code
     * @param data Data sent from the IPC
     * @param reply Reply return to the IPC
     * @param policyData Policy data after processing
     * @return If the operation is successful, ERR_OK is returned.
     */
    virtual ErrCode OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
        HandlePolicyData &policyData, int32_t userId) = 0;

    /*
     * Merge policy data
     *
     * @param adminName current admin name
     * @param policyData in:Current cached policy data,out:comprehensive data of all admins currently cached.
     * @return If ERR_OK is returned,policyData incoming and outgoing data will be saved to a file.
     */
    virtual ErrCode MergePolicyData(const std::string &adminName, std::string &policyData);
    virtual void OnHandlePolicyDone(std::uint32_t funcCode, const std::string &adminName, bool isGlobalChanged,
        int32_t userId) = 0;
    virtual ErrCode OnAdminRemove(const std::string &adminName, const std::string &policyData, int32_t userId) = 0;
    virtual void OnAdminRemoveDone(const std::string &adminName, const std::string &currentJsonData,
        int32_t userId) = 0;
    virtual ErrCode WritePolicyToParcel(const std::string &policyData, MessageParcel &reply);
    virtual ErrCode OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
        int32_t userId) = 0;

    std::uint32_t GetCode();
    std::string GetPolicyName();
    bool NeedSavePolicy();
    bool IsGlobalPolicy();
    PolicyPermissionConfig GetAllPermission(FuncOperateType operaType);
    std::string GetPermission(FuncOperateType operaType, std::string permissionTag = "");
    IPlugin::PermissionType GetPermissionType(FuncOperateType operaType);
    IPlugin::ApiType GetApiType(FuncOperateType operaType);
    void SetExtensionPlugin(std::shared_ptr<IPlugin> extensionPlugin);
    std::shared_ptr<IPlugin> GetExtensionPlugin();
    void SetExecuteStrategy(std::shared_ptr<IPluginExecuteStrategy> strategy);
    std::shared_ptr<IPluginExecuteStrategy> GetExecuteStrategy();
    void SetPluginType(IPlugin::PluginType type);
    IPlugin::PluginType GetPluginType();
    virtual ~IPlugin();

protected:
    std::uint32_t policyCode_ = 0;
    std::string policyName_;
    PolicyPermissionConfig permissionConfig_;
    std::map<FuncOperateType, PolicyPermissionConfig> permissionMap_;
    std::shared_ptr<IPlugin> extensionPlugin_ = nullptr;
    std::shared_ptr<IPluginExecuteStrategy> strategy_ = std::make_shared<IPluginExecuteStrategy>();
    bool needSave_ = true;
    bool isGlobal_ = true;
    IPlugin::PluginType type_ = PluginType::BASIC;

private:
    std::string CheckAndGetPermissionFromConfig(const std::string &permissionTag,
        std::map<std::string, std::string> tagPermissions, const std::string &commonPermission);
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_EDM_IPLUGIN_H
