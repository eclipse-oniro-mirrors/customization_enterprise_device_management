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

#include "language_manager.h"

#include "admin_manager.h"
#include "bundle_info.h"
#include "cJSON.h"
#include "edm_constants.h"
#include "edm_data_ability_utils.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "external_manager_factory.h"
#include "func_code_utils.h"
#include "iexternal_manager_factory.h"
#include "locale_config.h"
#include "locale_info.h"
#include "message_parcel.h"
#include "plugin_manager.h"
#include "res_common.h"

namespace OHOS {
namespace EDM {
std::string LanguageManager::GetEnterpriseManagedTips()
{
    std::string result;
    if (GetValueFromCloudSettings(result)) {
        return result;
    }
    bool ret = GetValueFromLocal(result);
    EDMLOGD("GetValueFromLocal %{public}d", ret);
    return result;
}

bool LanguageManager::GetValueFromCloudSettings(std::string& result)
{
    std::string jsonStr;
    EdmDataAbilityUtils::GetStringFromSettingsDataShare(EdmConstants::ENTERPRISE_MANAGED_TIPS, jsonStr);
    if (!jsonStr.empty()) {
        std::string language = Global::I18n::LocaleConfig::GetSystemLanguage();
        std::string valueFromSettingsData = GetTargetLanguageValue(jsonStr, language);
        if (!valueFromSettingsData.empty()) {
            result = valueFromSettingsData;
            return true;
        }
    }
    EDMLOGW("GetValueFromCloudSettings empty");
    return false;
}

bool LanguageManager::GetValueFromLocal(std::string& result)
{
    std::shared_ptr<Global::Resource::ResourceManager> resMgr(Global::Resource::CreateResourceManager(false));
    if (resMgr == nullptr) {
        return false;
    }
    if (!InitResourceManager(resMgr)) {
        return false;
    }
    AddDataToResourceManager(resMgr);
    std::string resultValue;
    std::string enterpriseName = GetEnterpriseName();
    Global::Resource::RState res;
    if (enterpriseName.empty()) {
        res = resMgr->GetStringByName(EdmConstants::ENTERPRISE_DEVICE_DEFAULT_TEXT, resultValue);
        if (res == Global::Resource::RState::SUCCESS) {
            result = resultValue;
            return true;
        }
        return false;
    }
    std::vector<std::tuple<Global::Resource::ResourceManager::NapiValueType, std::string>> jsParams;
    jsParams.emplace_back(
        std::make_tuple(Global::Resource::ResourceManager::NapiValueType::NAPI_STRING, enterpriseName));
    res = resMgr->GetStringFormatByName(EdmConstants::ENTERPRISE_DEVICE_TEXT, resultValue, jsParams);
    if (res == Global::Resource::RState::SUCCESS) {
        result = resultValue;
        return true;
    }
    return false;
}

std::string LanguageManager::GetTargetLanguageValue(const std::string& jsonStr, const std::string& language)
{
    if (jsonStr.empty() || language.empty()) {
        EDMLOGE("GetTargetLanguageValue input value empty");
        return "";
    }
    cJSON* root = cJSON_Parse(jsonStr.c_str());
    if (root == nullptr) {
        EDMLOGE("GetTargetLanguageValue cJSON_Parse error");
        return "";
    }
    if (!cJSON_IsObject(root)) {
        EDMLOGE("GetTargetLanguageValue cJSON_IsObject error");
        cJSON_Delete(root);
        return "";
    }
    std::string langKey = language;
    std::string result;
    cJSON* langItem = cJSON_GetObjectItem(root, langKey.c_str());
    if (langItem != nullptr && cJSON_IsString(langItem) && langItem->valuestring != nullptr) {
        result = langItem->valuestring;
        cJSON_Delete(root);
        return result;
    }
    std::string baseValue = "default";
    cJSON* baseItem = cJSON_GetObjectItem(root, baseValue.c_str());
    if (baseItem != nullptr && cJSON_IsString(baseItem) && baseItem->valuestring != nullptr) {
        std::string defaultLanguage = baseItem->valuestring;
        cJSON* defaultItem = cJSON_GetObjectItem(root, defaultLanguage.c_str());
        if (defaultItem != nullptr && cJSON_IsString(defaultItem) && defaultItem->valuestring != nullptr) {
            result = defaultItem->valuestring;
        }
        cJSON_Delete(root);
        return result;
    }
    cJSON_Delete(root);
    return "";
}

bool LanguageManager::GetDefaultLanguageResourcePath(std::string &path)
{
    std::uint32_t code =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::GET, (std::uint32_t)EdmInterfaceCode::GET_ADMINPROVISION_INFO);
    auto loadRet = PluginManager::GetInstance()->LoadPluginByFuncCode(code);
    if (loadRet != ERR_OK) {
        EDMLOGE("GetDefaultLanguageResourcePath loadRet error");
        return false;
    }
    std::shared_ptr<IPlugin> plugin = PluginManager::GetInstance()->GetPluginByFuncCode(code);
    if (plugin == nullptr || plugin->GetExecuteStrategy() == nullptr) {
        EDMLOGE("GetDefaultLanguageResourcePath plugin error");
        return false;
    }
    std::string policyValue;
    MessageParcel data;
    MessageParcel reply;
    ErrCode getRet =
        plugin->GetExecuteStrategy()->OnGetExecute(code, policyValue, data, reply, EdmConstants::DEFAULT_USER_ID);
    if (getRet != ERR_OK) {
        EDMLOGE("GetDefaultLanguageResourcePath getRet error");
        return false;
    }
    int32_t resCode = ERR_INVALID_VALUE;
    if (!reply.ReadInt32(resCode) || FAILED(resCode)) {
        EDMLOGE("GetDefaultLanguageResourcePath reply error");
        return false;
    }
    path = reply.ReadString();
    return true;
}

bool LanguageManager::InitResourceManager(std::shared_ptr<Global::Resource::ResourceManager>& resMgr)
{
    std::unique_ptr<Global::Resource::ResConfig> resConfig(Global::Resource::CreateResConfig());
    if (resConfig == nullptr) {
        EDMLOGE("InitResourceManager resConfig error");
        return false;
    }
    std::map<std::string, std::string> configs;
    OHOS::Global::I18n::LocaleInfo locale(OHOS::Global::I18n::LocaleConfig::GetSystemLocale(), configs);
    Global::Resource::RState res =
        resConfig->SetLocaleInfo(locale.GetLanguage().c_str(), locale.GetScript().c_str(), locale.GetRegion().c_str());
    if (res != Global::Resource::RState::SUCCESS) {
        EDMLOGE("InitResourceManager SetLocaleInfo error");
        return false;
    }
    res = resMgr->UpdateResConfig(*resConfig);
    if (res != Global::Resource::RState::SUCCESS) {
        EDMLOGE("InitResourceManager UpdateResConfig error");
        return false;
    }
    return true;
}

void LanguageManager::AddDataToResourceManager(std::shared_ptr<Global::Resource::ResourceManager>& resMgr)
{
    std::string resourcePath;
    bool ret = GetDefaultLanguageResourcePath(resourcePath);
    if (!ret) {
        EDMLOGE("AddDataToResourceManager ret failed");
        return;
    }
    if (resourcePath.empty()) {
        EDMLOGE("AddDataToResourceManager resourcePath empty");
        return;
    }
    AppExecFwk::BundleInfo bundleInfo;
    std::shared_ptr<IExternalManagerFactory> externalManagerFactory = std::make_shared<ExternalManagerFactory>();
    bool bundleRet = externalManagerFactory->CreateBundleManager()->GetBundleInfoV9(resourcePath,
        static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE), bundleInfo,
        EdmConstants::DEFAULT_USER_ID);
    if (!bundleRet) {
        EDMLOGE("AddDataToResourceManager bundleRet false");
        return;
    }
    for (const auto& hapInfo : bundleInfo.hapModuleInfos) {
        resMgr->AddResource(hapInfo.hapPath.c_str());
    }
}

std::string LanguageManager::GetEnterpriseName()
{
    auto adminItem = AdminManager::GetInstance()->GetSuperAdmin();
    if (adminItem == nullptr) {
        return "";
    }
    return adminItem->adminInfo_.entInfo_.enterpriseName;
}
} // namespace EDM
} // namespace OHOS
