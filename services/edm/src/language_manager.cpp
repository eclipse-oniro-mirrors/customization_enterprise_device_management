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

#include <map>

#include "ipc_skeleton.h"
#include "parameters.h"

#include "admin_manager.h"
#include "bundle_info.h"
#include "cJSON.h"
#include "edm_constants.h"
#include "edm_data_ability_utils.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "edm_os_account_manager_impl.h"
#include "external_manager_factory.h"
#include "ext_info_manager.h"
#include "func_code_utils.h"
#include "iexternal_manager_factory.h"
#include "locale_config.h"
#include "locale_info.h"
#include "message_parcel.h"
#include "permission_checker.h"
#include "plugin_manager.h"
#include "res_common.h"

namespace OHOS {
namespace EDM {
std::string LanguageManager::GetEnterpriseManagedTips()
{
    std::string mdmResult;
    bool hasMdmDisplayInfo = GetValueFromMdmSettings(mdmResult);
    if (!IsNeedToShowEnterpriseManagedTips(hasMdmDisplayInfo)) {
        EDMLOGW("LanguageManager::GetEnterpriseManagedTips no need to show enterprise managed tips.");
        return "";
    }
    if (hasMdmDisplayInfo) {
        return mdmResult;
    }
    std::string result;
    if (GetValueFromCloudSettings(result)) {
        return result;
    }
    bool ret = GetValueFromLocal(result);
    EDMLOGD("GetValueFromLocal %{public}d", ret);
    return result;
}

bool LanguageManager::GetValueFromMdmSettings(std::string &result)
{
    std::string jsonStr;
    if (FAILED(EdmDataAbilityUtils::GetStringFromSettingsDataShare(EdmConstants::ENTERPRISE_DISPLAY_INFO, jsonStr)) ||
        jsonStr.empty()) {
        EDMLOGD("GetValueFromMdmSettings no mdm display info");
        return false;
    }
    std::map<std::string, std::string> enterpriseNames;
    std::string defaultLanguage;
    if (FAILED(ParseEnterpriseDisplayInfo(jsonStr, enterpriseNames, defaultLanguage)) ||
        enterpriseNames.empty()) {
        EDMLOGW("GetValueFromMdmSettings parse mdm display info failed");
        return false;
    }
    std::string language = Global::I18n::LocaleConfig::GetSystemLanguage();
    std::string enterpriseName = FindEnterpriseName(enterpriseNames, language);
    if (enterpriseName.empty()) {
        enterpriseName = FindEnterpriseName(enterpriseNames, defaultLanguage);
    }
    if (enterpriseName.empty()) {
        EDMLOGW("GetValueFromMdmSettings no matched enterprise name");
        return false;
    }
    std::string tips = GetSystemStringFormatByName(EdmConstants::ENTERPRISE_DEVICE_TEXT, enterpriseName);
    if (tips.empty()) {
        EDMLOGW("GetValueFromMdmSettings get system template failed");
        return false;
    }
    result = tips;
    return true;
}

bool LanguageManager::GetValueFromCloudSettings(std::string& result)
{
    std::string jsonStr;
    if (IsSettingsCalling()) {
        EdmDataAbilityUtils::GetStringFromSettingsDataShare(EdmConstants::ENTERPRISE_MANAGED_TIPS_ON_SETTINGS, jsonStr);
    } else {
        EdmDataAbilityUtils::GetStringFromSettingsDataShare(EdmConstants::ENTERPRISE_MANAGED_TIPS, jsonStr);
    }
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

std::string LanguageManager::GetSystemStringByName(const std::string &name)
{
    std::shared_ptr<Global::Resource::ResourceManager> resMgr(Global::Resource::CreateResourceManager(false));
    if (resMgr == nullptr) {
        return "";
    }
    if (!InitResourceManager(resMgr)) {
        return "";
    }
    AddDataToResourceManager(resMgr);
    std::string resultValue;
    Global::Resource::RState res = resMgr->GetStringByName(name.c_str(), resultValue);
    if (res == Global::Resource::RState::SUCCESS) {
        return resultValue;
    }
    EDMLOGE("GetTargetLanguageValue GetSystemStringByName failed. %{public}d", res);
    return "";
}

std::string LanguageManager::GetSystemStringFormatByName(const std::string &name, const std::string &param)
{
    std::shared_ptr<Global::Resource::ResourceManager> resMgr(Global::Resource::CreateResourceManager(false));
    if (resMgr == nullptr) {
        return "";
    }
    if (!InitResourceManager(resMgr)) {
        return "";
    }
    AddDataToResourceManager(resMgr);
    std::vector<std::tuple<Global::Resource::ResourceManager::NapiValueType, std::string>> jsParams;
    jsParams.emplace_back(
        std::make_tuple(Global::Resource::ResourceManager::NapiValueType::NAPI_STRING, param));
    std::string resultValue;
    Global::Resource::RState res = resMgr->GetStringFormatByName(name.c_str(), resultValue, jsParams);
    if (res == Global::Resource::RState::SUCCESS) {
        return resultValue;
    }
    EDMLOGE("GetSystemStringFormatByName failed. %{public}d", res);
    return "";
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

std::string LanguageManager::FindEnterpriseName(const std::map<std::string, std::string> &enterpriseNames,
    const std::string &language)
{
    if (language.empty()) {
        return "";
    }
    // Match the language tag exactly first, then strip trailing subtags gradually,
    // e.g. en-Latn-US -> en-Latn -> en, zh-Hans-CN -> zh-Hans.
    std::string languageTag = language;
    while (!languageTag.empty()) {
        auto item = enterpriseNames.find(languageTag);
        if (item != enterpriseNames.end()) {
            return item->second;
        }
        size_t pos = languageTag.rfind('-');
        if (pos == std::string::npos) {
            break;
        }
        languageTag.erase(pos);
    }
    return "";
}

size_t LanguageManager::CountUtf8CodePoints(const std::string &value)
{
    size_t count = 0;
    for (unsigned char ch : value) {
        if ((ch & 0xC0) != 0x80) {
            ++count;
        }
    }
    return count;
}

bool LanguageManager::IsValidEnterpriseName(const std::string &name)
{
    size_t length = CountUtf8CodePoints(name);
    return length >= EdmConstants::MIN_ENTERPRISE_NAME_LENGTH &&
        length <= EdmConstants::MAX_ENTERPRISE_NAME_LENGTH;
}

ErrCode LanguageManager::ParseEnterpriseDisplayInfo(const std::string &jsonStr,
    std::map<std::string, std::string> &enterpriseNames, std::string &defaultLanguage)
{
    enterpriseNames.clear();
    defaultLanguage.clear();
    if (jsonStr.empty() || jsonStr.size() > EdmConstants::MAX_ENTERPRISE_DISPLAY_INFO_LENGTH) {
        EDMLOGE("LanguageManager ParseEnterpriseDisplayInfo: invalid json length.");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    cJSON *root = cJSON_Parse(jsonStr.c_str());
    if (root == nullptr) {
        EDMLOGE("LanguageManager ParseEnterpriseDisplayInfo: cJSON_Parse failed.");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    if (!cJSON_IsObject(root)) {
        EDMLOGE("LanguageManager ParseEnterpriseDisplayInfo: json root is not object.");
        cJSON_Delete(root);
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    cJSON *item = nullptr;
    cJSON_ArrayForEach(item, root) {
        if (item->string == nullptr || item->string[0] == '\0' ||
            !cJSON_IsString(item) || item->valuestring == nullptr) {
            continue;
        }
        std::string key(item->string);
        if (key == EdmConstants::ENTERPRISE_DISPLAY_INFO_DEFAULT) {
            defaultLanguage = item->valuestring;
        } else {
            enterpriseNames[key] = item->valuestring;
        }
    }
    cJSON_Delete(root);
    return ERR_OK;
}

bool LanguageManager::ValidateDisplayInfoItems(cJSON *root, bool &hasDefault, size_t &languageCount)
{
    cJSON *item = nullptr;
    cJSON_ArrayForEach(item, root) {
        if (item->string == nullptr || item->string[0] == '\0' ||
            !cJSON_IsString(item) || item->valuestring == nullptr) {
            EDMLOGE("LanguageManager ValidateEnterpriseDisplayInfo: item is not a string field.");
            return false;
        }
        if (std::string(item->string) == EdmConstants::ENTERPRISE_DISPLAY_INFO_DEFAULT) {
            if (item->valuestring[0] == '\0') {
                EDMLOGE("LanguageManager ValidateEnterpriseDisplayInfo: default language is empty.");
                return false;
            }
            hasDefault = true;
            continue;
        }
        if (!IsValidEnterpriseName(item->valuestring)) {
            EDMLOGE("LanguageManager ValidateEnterpriseDisplayInfo: enterprise name invalid.");
            return false;
        }
        ++languageCount;
    }
    return true;
}

ErrCode LanguageManager::ValidateEnterpriseDisplayInfo(const std::string &jsonStr)
{
    // Only the json format is verified here, the language tag is not restricted to a preset list.
    // The "default" field is mandatory, the enterprise name length and the language count are limited.
    if (jsonStr.empty() || jsonStr.size() > EdmConstants::MAX_ENTERPRISE_DISPLAY_INFO_LENGTH) {
        EDMLOGE("LanguageManager ValidateEnterpriseDisplayInfo: invalid json length.");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    cJSON *root = cJSON_Parse(jsonStr.c_str());
    if (root == nullptr) {
        EDMLOGE("LanguageManager ValidateEnterpriseDisplayInfo: cJSON_Parse failed.");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    if (!cJSON_IsObject(root)) {
        EDMLOGE("LanguageManager ValidateEnterpriseDisplayInfo: json root is not object.");
        cJSON_Delete(root);
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    size_t languageCount = 0;
    bool hasDefault = false;
    bool isValid = ValidateDisplayInfoItems(root, hasDefault, languageCount);
    if (isValid) {
        isValid = hasDefault && languageCount > 0 &&
            languageCount <= EdmConstants::MAX_ENTERPRISE_DISPLAY_LANGUAGE_COUNT;
    }
    cJSON_Delete(root);
    if (!isValid) {
        EDMLOGE("LanguageManager ValidateEnterpriseDisplayInfo: validate failed.");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    return ERR_OK;
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
    std::string resourcePath = ExtInfoManager::GetInstance()->GetAdminProvisioningInfo();
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

bool LanguageManager::IsNeedToShowEnterpriseManagedTips(bool hasMdmDisplayInfo)
{
    // The MDM configured display info takes precedence over the HEM "do not show" switch.
    if (!hasMdmDisplayInfo) {
        bool disableTips = false;
        if (IsSettingsCalling()) {
            disableTips = system::GetBoolParameter(EdmConstants::MANAGED_TIPS_DISABLED_ON_SETTINGS, false);
        } else {
            disableTips = system::GetBoolParameter(EdmConstants::MANAGED_TIPS_DISABLED, false);
        }
        if (disableTips) {
            return false;
        }
    }
    EdmOsAccountManagerImpl osAccountMgr;
    int32_t userId = osAccountMgr.GetCurrentUserId();
    if (AdminManager::GetInstance()->IsExistTargetAdmin(true, userId)) {
        EDMLOGW("IsNeedToShowEnterpriseManagedTips has debug admin, need to show.");
        return true;
    }
    if (userId != EdmConstants::DEFAULT_USER_ID) {
        EDMLOGW("IsNeedToShowEnterpriseManagedTips not default account, does not show.");
        return false;
    }
    if (AdminManager::GetInstance()->IsByodAdminExist()) {
        EDMLOGW("IsNeedToShowEnterpriseManagedTips exist byod admin, does not show.");
        return false;
    }
    return true;
}

bool LanguageManager::IsSettingsCalling()
{
    auto settingsInfo = ExtInfoManager::GetInstance()->GetWantAgentInfo();
    if (settingsInfo.bundleName.empty()) {
        return false;
    }
    return PermissionChecker::GetInstance()->CheckCallingUid(settingsInfo.bundleName) == ERR_OK;
}
} // namespace EDM
} // namespace OHOS
