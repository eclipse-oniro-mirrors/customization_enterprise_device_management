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

#include "default_application_plugin.h"

#include <system_ability_definition.h>

#include <unordered_map>

#include "appexecfwk_errors.h"
#include "bundle_info.h"
#include "default_application_type.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "edm_sys_manager.h"
#include "element_name.h"
#include "iplugin_manager.h"
#include "want.h"

namespace OHOS {
namespace EDM {
namespace {
constexpr int32_t ACCOUNT_ID_MIN = 0;
// BMS DefaultAppMgr matches the type against a case-sensitive whitelist, so these must stay upper case.
const std::unordered_map<int32_t, std::string> DEFAULT_APP_TYPE_MAP = {
    {static_cast<int32_t>(DefaultApplicationType::BROWSER), "BROWSER"},
    {static_cast<int32_t>(DefaultApplicationType::IMAGE), "IMAGE"},
    {static_cast<int32_t>(DefaultApplicationType::AUDIO), "AUDIO"},
    {static_cast<int32_t>(DefaultApplicationType::VIDEO), "VIDEO"},
    {static_cast<int32_t>(DefaultApplicationType::PDF), "PDF"},
    {static_cast<int32_t>(DefaultApplicationType::WORD), "WORD"},
    {static_cast<int32_t>(DefaultApplicationType::EXCEL), "EXCEL"},
    {static_cast<int32_t>(DefaultApplicationType::PPT), "PPT"},
    {static_cast<int32_t>(DefaultApplicationType::EMAIL), "EMAIL"},
};
} // namespace

const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<DefaultApplicationPlugin>());

DefaultApplicationPlugin::DefaultApplicationPlugin()
{
    EDMLOGI("DefaultApplicationPlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::DEFAULT_APPLICATION;
    policyName_ = PolicyName::POLICY_DEFAULT_APPLICATION;
    permissionConfig_ = IPlugin::PolicyPermissionConfig(EdmPermission::PERMISSION_ENTERPRISE_INSTALL_BUNDLE,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
    needSave_ = false;
}

ErrCode DefaultApplicationPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    int32_t type = data.ReadInt32();
    std::string bundleName = data.ReadString();
    std::string abilityName = data.ReadString();
    int32_t accountId = data.ReadInt32();
    EDMLOGI("DefaultApplicationPlugin OnHandlePolicy, type=%{public}d, bundleName=%{public}s, "
        "abilityName=%{public}s, accountId=%{public}d", type, bundleName.c_str(), abilityName.c_str(), accountId);

    std::string appType;
    ErrCode ret = ConvertAppType(type, appType);
    if (FAILED(ret)) {
        return ret;
    }
    if (bundleName.empty() || abilityName.empty()) {
        EDMLOGE("DefaultApplicationPlugin: bundleName or abilityName is empty");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    ret = CheckAccountId(accountId);
    if (FAILED(ret)) {
        return ret;
    }
    return InnerSetDefaultApplication(appType, bundleName, abilityName, accountId);
}

ErrCode DefaultApplicationPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    int32_t type = data.ReadInt32();
    int32_t accountId = data.ReadInt32();
    EDMLOGI("DefaultApplicationPlugin OnGetPolicy, type=%{public}d, accountId=%{public}d", type, accountId);

    std::string appType;
    ErrCode ret = ConvertAppType(type, appType);
    if (SUCCEEDED(ret)) {
        ret = CheckAccountId(accountId);
    }
    if (FAILED(ret)) {
        reply.WriteInt32(ret);
        return ret;
    }
    std::string bundleName;
    ret = InnerGetDefaultApplicationBundleName(appType, accountId, bundleName);
    reply.WriteInt32(ret);
    if (ret == ERR_OK) {
        reply.WriteString(bundleName);
    }
    return ret;
}

sptr<AppExecFwk::IBundleMgr> DefaultApplicationPlugin::GetBundleMgrProxy()
{
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (proxy == nullptr) {
        EDMLOGE("DefaultApplicationPlugin GetBundleMgrProxy failed.");
    }
    return proxy;
}

sptr<AppExecFwk::IDefaultApp> DefaultApplicationPlugin::GetDefaultAppProxy()
{
    auto bundleMgr = GetBundleMgrProxy();
    if (bundleMgr == nullptr) {
        return nullptr;
    }
    auto defaultAppProxy = bundleMgr->GetDefaultAppProxy();
    if (defaultAppProxy == nullptr) {
        EDMLOGE("DefaultApplicationPlugin GetDefaultAppProxy failed.");
    }
    return defaultAppProxy;
}

ErrCode DefaultApplicationPlugin::QueryModuleName(const std::string &bundleName, const std::string &abilityName,
    int32_t accountId, std::string &moduleName)
{
    // The API only carries bundleName and abilityName, but BMS rejects an ElementName without moduleName.
    auto bundleMgr = GetBundleMgrProxy();
    if (bundleMgr == nullptr) {
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    AppExecFwk::ElementName element;
    element.SetBundleName(bundleName);
    element.SetAbilityName(abilityName);
    AAFwk::Want want;
    want.SetElement(element);
    std::vector<AppExecFwk::AbilityInfo> abilityInfos;
    bool queried = bundleMgr->QueryAbilityInfos(want, AppExecFwk::AbilityInfoFlag::GET_ABILITY_INFO_DEFAULT,
        accountId, abilityInfos);
    if (!queried) {
        EDMLOGE("DefaultApplicationPlugin QueryAbilityInfos failed.");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    for (const auto &abilityInfo : abilityInfos) {
        if (abilityInfo.name == abilityName && !abilityInfo.moduleName.empty()) {
            moduleName = abilityInfo.moduleName;
            return ERR_OK;
        }
    }
    EDMLOGE("DefaultApplicationPlugin: no module owns the given ability");
    return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
}

ErrCode DefaultApplicationPlugin::InnerSetDefaultApplication(const std::string &appType,
    const std::string &bundleName, const std::string &abilityName, int32_t accountId)
{
    std::string moduleName;
    ErrCode ret = QueryModuleName(bundleName, abilityName, accountId, moduleName);
    if (FAILED(ret)) {
        return ret;
    }
    auto defaultAppProxy = GetDefaultAppProxy();
    if (defaultAppProxy == nullptr) {
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName(bundleName);
    elementName.SetModuleName(moduleName);
    elementName.SetAbilityName(abilityName);
    AAFwk::Want want;
    want.SetElement(elementName);
    int32_t bmsRet = defaultAppProxy->SetDefaultApplicationForCustom(accountId, appType, want);
    if (bmsRet != ERR_OK) {
        EDMLOGE("DefaultApplicationPlugin SetDefaultApplicationForCustom failed, ret=%{public}d", bmsRet);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    // BMS only reports whether the enterprise fallback row was recorded, not whether it took effect for this user,
    // so read the current default back and reject anything that did not land on the requested bundle.
    std::string currentBundleName;
    ret = InnerGetDefaultApplicationBundleName(appType, accountId, currentBundleName);
    if (FAILED(ret)) {
        return ret;
    }
    if (currentBundleName != bundleName) {
        EDMLOGE("DefaultApplicationPlugin: set not effective, appType=%{public}s, expected=%{public}s, "
            "current=%{public}s", appType.c_str(), bundleName.c_str(), currentBundleName.c_str());
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    EDMLOGI("DefaultApplicationPlugin InnerSetDefaultApplication end, appType=%{public}s, bundleName=%{public}s",
        appType.c_str(), bundleName.c_str());
    return ERR_OK;
}

ErrCode DefaultApplicationPlugin::InnerGetDefaultApplicationBundleName(const std::string &appType,
    int32_t accountId, std::string &bundleName)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    if (defaultAppProxy == nullptr) {
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    AppExecFwk::BundleInfo bundleInfo;
    int32_t bmsRet = defaultAppProxy->GetDefaultApplication(accountId, appType, bundleInfo);
    if (bmsRet == ERR_BUNDLE_MANAGER_DEFAULT_APP_NOT_EXIST) {
        EDMLOGI("DefaultApplicationPlugin: no default application has been set, return empty bundle name");
        return ERR_OK;
    }
    if (bmsRet != ERR_OK) {
        EDMLOGE("DefaultApplicationPlugin GetDefaultApplication failed, ret=%{public}d", bmsRet);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    bundleName = bundleInfo.name;
    EDMLOGI("DefaultApplicationPlugin InnerGetDefaultApplicationBundleName end, bundleName=%{public}s",
        bundleName.c_str());
    return ERR_OK;
}

ErrCode DefaultApplicationPlugin::ConvertAppType(int32_t type, std::string &appType)
{
    auto iter = DEFAULT_APP_TYPE_MAP.find(type);
    if (iter == DEFAULT_APP_TYPE_MAP.end()) {
        EDMLOGE("DefaultApplicationPlugin: invalid default application type %{public}d", type);
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    appType = iter->second;
    return ERR_OK;
}

ErrCode DefaultApplicationPlugin::CheckAccountId(int32_t accountId)
{
    if (accountId < ACCOUNT_ID_MIN) {
        EDMLOGE("DefaultApplicationPlugin: invalid accountId %{public}d", accountId);
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    bool isExist = false;
    ErrCode ret = externalManagerFactory_->CreateOsAccountManager()->IsOsAccountExists(accountId, isExist);
    if (FAILED(ret) || !isExist) {
        EDMLOGE("DefaultApplicationPlugin: accountId %{public}d does not exist", accountId);
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
