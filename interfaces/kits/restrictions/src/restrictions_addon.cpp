/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "restrictions_addon.h"

#include <algorithm>
#include <vector>

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "restrictions_feature.h"

using namespace OHOS::EDM;

std::unordered_map<std::string, uint32_t> RestrictionsAddon::labelCodeMap = {
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_BLUETOOTH, EdmInterfaceCode::DISABLE_BLUETOOTH},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_MODIFY_DATETIME, EdmInterfaceCode::DISALLOW_MODIFY_DATETIME},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_PRINTER, EdmInterfaceCode::DISABLED_PRINTER},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_HDC, EdmInterfaceCode::DISABLED_HDC},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_MIC, EdmInterfaceCode::DISABLE_MICROPHONE},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_FINGER_PRINT, EdmInterfaceCode::FINGERPRINT_AUTH},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_USB, EdmInterfaceCode::DISABLE_USB},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_WIFI, EdmInterfaceCode::DISABLE_WIFI},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_MTP_CLIENT, EdmInterfaceCode::DISABLE_MTP_CLIENT},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_MTP_SERVER, EdmInterfaceCode::DISABLE_MTP_SERVER},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_SAMBA_CLIENT, EdmInterfaceCode::DISABLE_SAMBA_CLIENT},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_SAMBA_SERVER, EdmInterfaceCode::DISABLE_SAMBA_SERVER},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_MAINTENANCE_MODE, EdmInterfaceCode::DISABLE_MAINTENANCE_MODE},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_REMOTE_DESK, EdmInterfaceCode::POLICY_CODE_END + 25},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_REMOTE_DIAGNOSIS, EdmInterfaceCode::POLICY_CODE_END + 26},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_SCREENSHOT, EdmInterfaceCode::POLICY_CODE_END + 11},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_SCREEN_RECORD, EdmInterfaceCode::POLICY_CODE_END + 12},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_DISK_RECOVERY_KEY, EdmInterfaceCode::POLICY_CODE_END + 17},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_NEAR_LINK, EdmInterfaceCode::POLICY_CODE_END + 18},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_TETHERING, EdmInterfaceCode::DISALLOWED_TETHERING},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_INACTIVE_USER_FREEZE, EdmInterfaceCode::INACTIVE_USER_FREEZE},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_CAMERA, EdmInterfaceCode::DISABLE_CAMERA},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_DEVELOPER_MODE, POLICY_CODE_END + 20},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_RESET_FACTORY, POLICY_CODE_END + 21},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_NFC, POLICY_CODE_END + 24},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_SMS, EdmInterfaceCode::DISALLOWED_SMS},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_MMS, EdmInterfaceCode::DISALLOWED_MMS},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_BACKUP_AND_RESTORE,
        EdmInterfaceCode::DISABLE_BACKUP_AND_RESTORE},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_MOBILE_DATA, EdmInterfaceCode::DISALLOWED_MOBILE_DATA},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_AIRPLANE_MODE, EdmInterfaceCode::DISALLOWED_AIRPLANE_MODE},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_NOTIFICATION, EdmInterfaceCode::DISALLOWED_NOTIFICATION},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_APP_CLONE, EdmInterfaceCode::DISABLED_APP_CLONE},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_TELEPHONY_CALL, EdmInterfaceCode::DISALLOWED_TELEPHONY_CALL},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_VPN, EdmInterfaceCode::DISALLOW_VPN},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_OTA, POLICY_CODE_END + EdmConstants::PolicyCode::DISABLE_OTA},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_RANDOM_MAC_ADDRESS,
        EdmInterfaceCode::DISALLOWED_RANDOM_MAC_ADDRESS},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_EXTERNAL_STORAGE_CARD,
        EdmInterfaceCode::DISALLOWED_EXTERNAL_STORAGE_CARD},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_PRIVATE_SPACE, EdmInterfaceCode::DISABLE_PRIVATE_SPACE},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_HDC_REMOTE, EdmInterfaceCode::DISABLED_HDC_REMOTE},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_UNMUTE_DEVICE, EdmInterfaceCode::DISALLOW_UNMUTE_DEVICE},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_VIRTUAL_SERVICE, EdmInterfaceCode::DISALLOW_VIRTUAL_SERVICE},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_USB_SERIAL, EdmInterfaceCode::DISALLOW_USB_SERIAL},
};

std::unordered_map<std::string, uint32_t> RestrictionsAddon::itemCodeMap = {
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_APN, EdmInterfaceCode::DISALLOW_MODIFY_APN},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_POWER_LONG_PRESS,
        EdmInterfaceCode::DISALLOW_POWER_LONG_PRESS},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_SET_BIOMETRICS_AND_SCREENLOCK,
        EdmInterfaceCode::DISABLE_SET_BIOMETRICS_AND_SCREENLOCK},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_SET_DEVICE_NAME,
        EdmInterfaceCode::DISABLE_SET_DEVICE_NAME},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_ETHERNET_IP, EdmInterfaceCode::DISALLOW_MODIFY_ETHERNET_IP},
};

std::unordered_map<std::string, uint32_t> RestrictionsAddon::itemQueryCodeMap = {
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_SET_BIOMETRICS_AND_SCREENLOCK,
        EdmInterfaceCode::DISABLE_SET_BIOMETRICS_AND_SCREENLOCK},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_SET_DEVICE_NAME,
        EdmInterfaceCode::DISABLE_SET_DEVICE_NAME},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_ETHERNET_IP, EdmInterfaceCode::DISALLOW_MODIFY_ETHERNET_IP},
};

std::unordered_map<std::string, uint32_t> RestrictionsAddon::itemCodeForAccountMap = {
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_MODIFY_WALLPAPER,
        EdmInterfaceCode::DISALLOW_MODIFY_WALLPAPER},
};

std::vector<uint32_t> RestrictionsAddon::multiPermCodes = {
    EdmInterfaceCode::DISABLE_BLUETOOTH,
    EdmInterfaceCode::DISALLOW_MODIFY_DATETIME,
    EdmInterfaceCode::DISABLED_PRINTER,
    EdmInterfaceCode::DISABLED_HDC,
    EdmInterfaceCode::DISABLE_USB,
    EdmInterfaceCode::DISABLE_WIFI,
};

std::unordered_map<std::string, uint32_t> RestrictionsAddon::labelCodeMapForAccount = {
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_FINGER_PRINT, EdmInterfaceCode::FINGERPRINT_AUTH},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_MTP_CLIENT, EdmInterfaceCode::DISABLE_USER_MTP_CLIENT},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_SUDO, EdmInterfaceCode::DISALLOWED_SUDO},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_DISTRIBUTED_TRANSMISSION,
        EdmInterfaceCode::DISALLOWED_DISTRIBUTED_TRANSMISSION},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_EXPORT_RECOVERY_KEY,
        EdmInterfaceCode::DISALLOWED_EXPORT_RECOVERY_KEY},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_USB_STORAGE_DEVICE_WRITE,
        EdmInterfaceCode::DISALLOWED_USB_STORAGE_DEVICE_WRITE},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_PRINT, EdmInterfaceCode::DISABLED_PRINT},
    {EdmConstants::Restrictions::LABEL_DISALLOWED_POLICY_OPEN_FILE_BOOST, EdmInterfaceCode::DISALLOWED_FILEBOOST_OPEN},
};

std::unordered_map<int32_t, uint32_t> RestrictionsAddon::featureEnum2InterfaceCodeMap = {
    {static_cast<int32_t>(RestrictionsFeature::WIFI_P2P), EdmInterfaceCode::DISALLOWED_P2P},
    {static_cast<int32_t>(RestrictionsFeature::LOCAL_INPUT), EdmInterfaceCode::DISALLOWED_UINPUT},
    {static_cast<int32_t>(RestrictionsFeature::SUDO), EdmInterfaceCode::DISALLOWED_DEVICE_SUDO},
    {static_cast<int32_t>(RestrictionsFeature::TRAFFIC_REDIRECTION), EdmInterfaceCode::DISALLOWED_TRAFFIC_REDIRECTION},
    {static_cast<int32_t>(RestrictionsFeature::CORE_DUMP), EdmInterfaceCode::DISALLOW_CORE_DUMP},
    {static_cast<int32_t>(RestrictionsFeature::SECURE_ERASE),
        EdmInterfaceCode::POLICY_CODE_END + EdmConstants::PolicyCode::DISABLE_SECURE_ERASE},
    {static_cast<int32_t>(RestrictionsFeature::RS232), EdmInterfaceCode::DISALLOW_RS232},
    {static_cast<int32_t>(RestrictionsFeature::BLUETOOTH), EdmInterfaceCode::DISABLE_BLUETOOTH},
    {static_cast<int32_t>(RestrictionsFeature::MODIFY_DATETIME), EdmInterfaceCode::DISALLOW_MODIFY_DATETIME},
    {static_cast<int32_t>(RestrictionsFeature::PRINTER), EdmInterfaceCode::DISABLED_PRINTER},
    {static_cast<int32_t>(RestrictionsFeature::HDC), EdmInterfaceCode::DISABLED_HDC},
    {static_cast<int32_t>(RestrictionsFeature::MICROPHONE), EdmInterfaceCode::DISABLE_MICROPHONE},
    {static_cast<int32_t>(RestrictionsFeature::FINGERPRINT), EdmInterfaceCode::FINGERPRINT_AUTH},
    {static_cast<int32_t>(RestrictionsFeature::USB), EdmInterfaceCode::DISABLE_USB},
    {static_cast<int32_t>(RestrictionsFeature::WIFI), EdmInterfaceCode::DISABLE_WIFI},
    {static_cast<int32_t>(RestrictionsFeature::TETHERING), EdmInterfaceCode::DISALLOWED_TETHERING},
    {static_cast<int32_t>(RestrictionsFeature::INACTIVE_USER_FREEZE), EdmInterfaceCode::INACTIVE_USER_FREEZE},
    {static_cast<int32_t>(RestrictionsFeature::CAMERA), EdmInterfaceCode::DISABLE_CAMERA},
    {static_cast<int32_t>(RestrictionsFeature::MTP_CLIENT), EdmInterfaceCode::DISABLE_MTP_CLIENT},
    {static_cast<int32_t>(RestrictionsFeature::MTP_SERVER), EdmInterfaceCode::DISABLE_MTP_SERVER},
    {static_cast<int32_t>(RestrictionsFeature::SAMBA_CLIENT), EdmInterfaceCode::DISABLE_SAMBA_CLIENT},
    {static_cast<int32_t>(RestrictionsFeature::SAMBA_SERVER), EdmInterfaceCode::DISABLE_SAMBA_SERVER},
    {static_cast<int32_t>(RestrictionsFeature::BACKUP_AND_RESTORE), EdmInterfaceCode::DISABLE_BACKUP_AND_RESTORE},
    {static_cast<int32_t>(RestrictionsFeature::MAINTENANCE_MODE), EdmInterfaceCode::DISABLE_MAINTENANCE_MODE},
    {static_cast<int32_t>(RestrictionsFeature::MMS), EdmInterfaceCode::DISALLOWED_MMS},
    {static_cast<int32_t>(RestrictionsFeature::SMS), EdmInterfaceCode::DISALLOWED_SMS},
    {static_cast<int32_t>(RestrictionsFeature::MOBILE_DATA), EdmInterfaceCode::DISALLOWED_MOBILE_DATA},
    {static_cast<int32_t>(RestrictionsFeature::AIRPLANE_MODE), EdmInterfaceCode::DISALLOWED_AIRPLANE_MODE},
    {static_cast<int32_t>(RestrictionsFeature::VPN), EdmInterfaceCode::DISALLOW_VPN},
    {static_cast<int32_t>(RestrictionsFeature::NOTIFICATION), EdmInterfaceCode::DISALLOWED_NOTIFICATION},
    {static_cast<int32_t>(RestrictionsFeature::NFC), EdmInterfaceCode::POLICY_CODE_END + 24},
    {static_cast<int32_t>(RestrictionsFeature::PRIVATE_SPACE), EdmInterfaceCode::DISABLE_PRIVATE_SPACE},
    {static_cast<int32_t>(RestrictionsFeature::TELEPHONY_CALL), EdmInterfaceCode::DISALLOWED_TELEPHONY_CALL},
    {static_cast<int32_t>(RestrictionsFeature::APP_CLONE), EdmInterfaceCode::DISABLED_APP_CLONE},
    {static_cast<int32_t>(RestrictionsFeature::EXTERNAL_STORAGE_CARD),
        EdmInterfaceCode::DISALLOWED_EXTERNAL_STORAGE_CARD},
    {static_cast<int32_t>(RestrictionsFeature::RANDOM_MAC), EdmInterfaceCode::DISALLOWED_RANDOM_MAC_ADDRESS},
    {static_cast<int32_t>(RestrictionsFeature::UNMUTE_DEVICE), EdmInterfaceCode::DISALLOW_UNMUTE_DEVICE},
    {static_cast<int32_t>(RestrictionsFeature::HDC_REMOTE), EdmInterfaceCode::DISABLED_HDC_REMOTE},
    {static_cast<int32_t>(RestrictionsFeature::VIRTUAL_SERVICE), EdmInterfaceCode::DISALLOW_VIRTUAL_SERVICE},
    {static_cast<int32_t>(RestrictionsFeature::USB_SERIAL), EdmInterfaceCode::DISALLOW_USB_SERIAL},
    {static_cast<int32_t>(RestrictionsFeature::SCREENSHOT), EdmInterfaceCode::POLICY_CODE_END + 11},
    {static_cast<int32_t>(RestrictionsFeature::SCREEN_RECORD), EdmInterfaceCode::POLICY_CODE_END + 12},
    {static_cast<int32_t>(RestrictionsFeature::DISK_RECOVERY_KEY), EdmInterfaceCode::POLICY_CODE_END + 17},
    {static_cast<int32_t>(RestrictionsFeature::NEAR_LINK), EdmInterfaceCode::POLICY_CODE_END + 18},
    {static_cast<int32_t>(RestrictionsFeature::DEVELOPER_MODE), EdmInterfaceCode::POLICY_CODE_END + 20},
    {static_cast<int32_t>(RestrictionsFeature::RESET_FACTORY), EdmInterfaceCode::POLICY_CODE_END + 21},
    {static_cast<int32_t>(RestrictionsFeature::REMOTE_DESK), EdmInterfaceCode::POLICY_CODE_END + 25},
    {static_cast<int32_t>(RestrictionsFeature::REMOTE_DIAGNOSIS), EdmInterfaceCode::POLICY_CODE_END + 26},
    {static_cast<int32_t>(RestrictionsFeature::OTA_UPDATE),
        EdmInterfaceCode::POLICY_CODE_END + EdmConstants::PolicyCode::DISABLE_OTA},
};

std::unordered_map<int32_t, uint32_t> RestrictionsAddon::featureForAccountEnum2InterfaceCodeMap = {
    {static_cast<int32_t>(RestrictionsFeatureForAccount::MULTI_WINDOW),
        EdmInterfaceCode::DISALLOWED_MULTI_WINDOW},
    {static_cast<int32_t>(RestrictionsFeatureForAccount::DISTRIBUTED_TRANSMISSION),
        EdmInterfaceCode::DISALLOWED_DISTRIBUTED_TRANSMISSION_FULL},
    {static_cast<int32_t>(RestrictionsFeatureForAccount::SUPER_HUB),
        POLICY_CODE_END + EdmConstants::PolicyCode::DISABLE_SUPERHUB},
    {static_cast<int32_t>(RestrictionsFeatureForAccount::FINGERPRINT), EdmInterfaceCode::FINGERPRINT_AUTH},
    {static_cast<int32_t>(RestrictionsFeatureForAccount::PRINT), EdmInterfaceCode::DISABLED_PRINT},
    {static_cast<int32_t>(RestrictionsFeatureForAccount::MTP_CLIENT), EdmInterfaceCode::DISABLE_USER_MTP_CLIENT},
    {static_cast<int32_t>(RestrictionsFeatureForAccount::USB_STORAGE_DEVICE_WRITE),
        EdmInterfaceCode::DISALLOWED_USB_STORAGE_DEVICE_WRITE},
    {static_cast<int32_t>(RestrictionsFeatureForAccount::DISK_RECOVERY_KEY),
        EdmInterfaceCode::DISALLOWED_EXPORT_RECOVERY_KEY},
    {static_cast<int32_t>(RestrictionsFeatureForAccount::SUDO), EdmInterfaceCode::DISALLOWED_SUDO},
    {static_cast<int32_t>(RestrictionsFeatureForAccount::DISTRIBUTED_TRANSMISSION_OUTGOING),
        EdmInterfaceCode::DISALLOWED_DISTRIBUTED_TRANSMISSION},
    {static_cast<int32_t>(RestrictionsFeatureForAccount::OPEN_FILE_BOOST), EdmInterfaceCode::DISALLOWED_FILEBOOST_OPEN},
};

std::unordered_map<int32_t, uint32_t> RestrictionsAddon::userRestrictionForDeviceEnum2CodeMap = {
    {static_cast<int32_t>(UserRestrictionForDevice::SET_APN), EdmInterfaceCode::DISALLOW_MODIFY_APN},
    {static_cast<int32_t>(UserRestrictionForDevice::POWER_LONG_PRESS), EdmInterfaceCode::DISALLOW_POWER_LONG_PRESS},
    {static_cast<int32_t>(UserRestrictionForDevice::SET_ETHERNET_IP), EdmInterfaceCode::DISALLOW_MODIFY_ETHERNET_IP},
    {static_cast<int32_t>(UserRestrictionForDevice::SET_DEVICE_NAME), EdmInterfaceCode::DISABLE_SET_DEVICE_NAME},
    {static_cast<int32_t>(UserRestrictionForDevice::SET_BIOMETRICS_AND_SCREENLOCK),
        EdmInterfaceCode::DISABLE_SET_BIOMETRICS_AND_SCREENLOCK},
};

std::unordered_map<int32_t, uint32_t> RestrictionsAddon::userRestrictionForAccountEnum2CodeMap = {
    {static_cast<int32_t>(UserRestrictionForAccount::MODIFY_WALLPAPER), EdmInterfaceCode::DISALLOW_MODIFY_WALLPAPER},
};

napi_value RestrictionsAddon::Init(napi_env env, napi_value exports)
{
    napi_value nFeatureForDevice = nullptr;
    napi_value nFeatureForAccount = nullptr;
    napi_value nSettingsForDevice = nullptr;
    napi_value nSettingsForAccount = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nFeatureForDevice));
    NAPI_CALL(env, napi_create_object(env, &nFeatureForAccount));
    NAPI_CALL(env, napi_create_object(env, &nSettingsForDevice));
    NAPI_CALL(env, napi_create_object(env, &nSettingsForAccount));
    CreateFeatureForDeviceObject(env, nFeatureForDevice);
    CreateFeatureForAccountObject(env, nFeatureForAccount);
    CreateUserRestrictionForDeviceObject(env, nSettingsForDevice);
    CreateUserRestrictionForAccountObject(env, nSettingsForAccount);
    napi_property_descriptor property[] = {
        DECLARE_NAPI_FUNCTION("setPrinterDisabled", SetPrinterDisabled),
        DECLARE_NAPI_FUNCTION("isPrinterDisabled", IsPrinterDisabled),
        DECLARE_NAPI_FUNCTION("setHdcDisabled", SetHdcDisabled),
        DECLARE_NAPI_FUNCTION("isHdcDisabled", IsHdcDisabled),
        DECLARE_NAPI_FUNCTION("disableMicrophone", DisableMicrophone),
        DECLARE_NAPI_FUNCTION("isMicrophoneDisabled", IsMicrophoneDisabled),
        DECLARE_NAPI_FUNCTION("setFingerprintAuthDisabled", SetFingerprintAuthDisabled),
        DECLARE_NAPI_FUNCTION("isFingerprintAuthDisabled", IsFingerprintAuthDisabled),
        DECLARE_NAPI_FUNCTION("setDisallowedPolicy", SetDisallowedPolicy),
        DECLARE_NAPI_FUNCTION("getDisallowedPolicy", GetDisallowedPolicy),
        DECLARE_NAPI_FUNCTION("setDisallowedPolicyForAccount", SetDisallowedPolicyForAccount),
        DECLARE_NAPI_FUNCTION("getDisallowedPolicyForAccount", GetDisallowedPolicyForAccount),
        DECLARE_NAPI_FUNCTION("addDisallowedListForAccount", AddDisallowedListForAccount),
        DECLARE_NAPI_FUNCTION("removeDisallowedListForAccount", RemoveDisallowedListForAccount),
        DECLARE_NAPI_FUNCTION("getDisallowedListForAccount", GetDisallowedListForAccount),
        DECLARE_NAPI_FUNCTION("setUserRestriction", SetUserRestriction),
        DECLARE_NAPI_FUNCTION("getUserRestricted", GetUserRestricted),
        DECLARE_NAPI_FUNCTION("setUserRestrictionForAccount", SetUserRestrictionForAccount),
        DECLARE_NAPI_FUNCTION("getUserRestrictedForAccount", GetUserRestrictedForAccount),
        DECLARE_NAPI_PROPERTY("FeatureForDevice", nFeatureForDevice),
        DECLARE_NAPI_PROPERTY("FeatureForAccount", nFeatureForAccount),
        DECLARE_NAPI_PROPERTY("SettingsForDevice", nSettingsForDevice),
        DECLARE_NAPI_PROPERTY("SettingsForAccount", nSettingsForAccount),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(property) / sizeof(property[0]), property));
    return exports;
}

napi_value RestrictionsAddon::SetPrinterDisabled(napi_env env, napi_callback_info info)
{
    return SetPolicyDisabled(env, info, EdmInterfaceCode::DISABLED_PRINTER);
}

napi_value RestrictionsAddon::SetHdcDisabled(napi_env env, napi_callback_info info)
{
    return SetPolicyDisabled(env, info, EdmInterfaceCode::DISABLED_HDC);
}

void RestrictionsAddon::SetPolicyDisabledCommon(AddonMethodSign &addonMethodSign, int policyCode)
{
    addonMethodSign.name = "SetPolicyDisabled";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::BOOLEAN};
    addonMethodSign.methodAttribute = MethodAttribute::HANDLE;
    addonMethodSign.policyCode = policyCode;
    std::string permissionTag = (std::find(multiPermCodes.begin(), multiPermCodes.end(),
        policyCode) == multiPermCodes.end()) ? WITHOUT_PERMISSION_TAG : EdmConstants::PERMISSION_TAG_VERSION_11;
    addonMethodSign.apiVersionTag = permissionTag;
}

napi_value RestrictionsAddon::SetPolicyDisabled(napi_env env, napi_callback_info info, int policyCode)
{
    EDMLOGI("NAPI_SetPolicyDisabled called");
    AddonMethodSign addonMethodSign;
    SetPolicyDisabledCommon(addonMethodSign, policyCode);
    return AddonMethodAdapter(env, info, addonMethodSign, NativeSetPolicyDisabled, NativeVoidCallbackComplete);
}

void RestrictionsAddon::NativeSetPolicyDisabled(napi_env env, void *data)
{
    EDMLOGI("NativeSetPolicyDisabled called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AdapterAddonData *asyncCallbackInfo = static_cast<AdapterAddonData *>(data);
    asyncCallbackInfo->ret = RestrictionsProxy::GetRestrictionsProxy()->SetDisallowedPolicy(
        asyncCallbackInfo->data, asyncCallbackInfo->policyCode);
}

OHOS::ErrCode RestrictionsAddon::NativeSetDisallowedPolicy(const AppExecFwk::ElementName &elementName,
    bool disallow, std::uint32_t ipcCode, ErrcodeType errcodeType)
{
    EDMLOGI("NativeSetDisallowedPolicy called");
    auto proxy = RestrictionsProxy::GetRestrictionsProxy();
    if (proxy == nullptr) {
        EDMLOGE("can not get RestrictionsProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    
    if (ipcCode == EdmInterfaceCode::FINGERPRINT_AUTH) {
        return proxy->SetFingerprintAuthDisabled(elementName, disallow);
    }
    
    std::string permissionTag;
    if (ipcCode == EdmInterfaceCode::DISALLOWED_MOBILE_DATA ||
        ipcCode == EdmInterfaceCode::DISALLOWED_AIRPLANE_MODE) {
        permissionTag = (errcodeType == ErrcodeType::STRING) ? EdmConstants::PERMISSION_TAG_VERSION_11 :
            EdmConstants::PERMISSION_TAG_VERSION_26;
    } else if (std::find(multiPermCodes.begin(), multiPermCodes.end(), ipcCode) != multiPermCodes.end()) {
        permissionTag = EdmConstants::PERMISSION_TAG_VERSION_12;
    } else {
        permissionTag = WITHOUT_PERMISSION_TAG;
    }
    return proxy->SetDisallowedPolicy(elementName, disallow, ipcCode, permissionTag);
}

OHOS::ErrCode RestrictionsAddon::NativeGetDisallowedPolicy(AppExecFwk::ElementName *elementName,
    std::uint32_t ipcCode, bool &disallow, ErrcodeType errcodeType)
{
    EDMLOGI("NativeGetDisallowedPolicy called");
    auto proxy = RestrictionsProxy::GetRestrictionsProxy();
    if (proxy == nullptr) {
        EDMLOGE("can not get RestrictionsProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    
    if (ipcCode == EdmInterfaceCode::FINGERPRINT_AUTH) {
        return proxy->IsFingerprintAuthDisabled(elementName, disallow);
    }
    
    std::string permissionTag;
    if (ipcCode == EdmInterfaceCode::DISALLOWED_MOBILE_DATA ||
        ipcCode == EdmInterfaceCode::DISALLOWED_AIRPLANE_MODE) {
        permissionTag = (errcodeType == ErrcodeType::STRING) ? EdmConstants::PERMISSION_TAG_VERSION_11 :
            EdmConstants::PERMISSION_TAG_VERSION_26;
    } else if (std::find(multiPermCodes.begin(), multiPermCodes.end(), ipcCode) != multiPermCodes.end()) {
        permissionTag = EdmConstants::PERMISSION_TAG_VERSION_12;
    } else {
        permissionTag = WITHOUT_PERMISSION_TAG;
    }
    return proxy->GetDisallowedPolicy(elementName, ipcCode, disallow, permissionTag);
}

napi_value RestrictionsAddon::IsPrinterDisabled(napi_env env, napi_callback_info info)
{
    return IsPolicyDisabled(env, info, EdmInterfaceCode::DISABLED_PRINTER);
}

napi_value RestrictionsAddon::IsHdcDisabled(napi_env env, napi_callback_info info)
{
    return IsPolicyDisabled(env, info, EdmInterfaceCode::DISABLED_HDC);
}

napi_value RestrictionsAddon::IsPolicyDisabled(napi_env env, napi_callback_info info, int policyCode)
{
    EDMLOGI("NAPI_IsPolicyDisabled called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    auto asyncCallbackInfo = new (std::nothrow) AsyncRestrictionsCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncRestrictionsCallbackInfo> callbackPtr{asyncCallbackInfo};
    bool matchFlag = false;
    if (MatchValueType(env, argv[ARR_INDEX_ZERO], napi_null)) {
        asyncCallbackInfo->hasAdmin = false;
        matchFlag = true;
    } else if (MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object)) {
        matchFlag = true;
        asyncCallbackInfo->hasAdmin = true;
        bool ret = ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]);
        ASSERT_AND_THROW_PARAM_ERROR(env, ret, "element name param error");
        EDMLOGD(
            "IsPolicyDisabled: asyncCallbackInfo->elementName.bundlename %{public}s, "
            "asyncCallbackInfo->abilityname:%{public}s",
            asyncCallbackInfo->elementName.GetBundleName().c_str(),
            asyncCallbackInfo->elementName.GetAbilityName().c_str());
    }
    if (argc > ARGS_SIZE_ONE) {
        matchFlag = matchFlag && MatchValueType(env, argv[ARR_INDEX_ONE], napi_function);
    }
    ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter type error");
    if (argc > ARGS_SIZE_ONE) {
        EDMLOGD("NAPI_IsPolicyDisabled argc == ARGS_SIZE_TWO");
        NAPI_CALL(env, napi_create_reference(env, argv[ARR_INDEX_ONE], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
    }
    asyncCallbackInfo->policyCode = policyCode;
    napi_value asyncWorkReturn =
        HandleAsyncWork(env, asyncCallbackInfo, "IsPolicyDisabled", NativeIsPolicyDisabled, NativeBoolCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

void RestrictionsAddon::NativeIsPolicyDisabled(napi_env env, void *data)
{
    EDMLOGI("NativeIsPolicyDisabled called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncRestrictionsCallbackInfo *asyncCallbackInfo = static_cast<AsyncRestrictionsCallbackInfo *>(data);
    std::string permissionTag = (std::find(multiPermCodes.begin(), multiPermCodes.end(),
        asyncCallbackInfo->policyCode) == multiPermCodes.end()) ? WITHOUT_PERMISSION_TAG :
        EdmConstants::PERMISSION_TAG_VERSION_11;
    if (asyncCallbackInfo->hasAdmin) {
        asyncCallbackInfo->ret = RestrictionsProxy::GetRestrictionsProxy()->GetDisallowedPolicy(
            &(asyncCallbackInfo->elementName), asyncCallbackInfo->policyCode, asyncCallbackInfo->boolRet,
            permissionTag);
    } else {
        asyncCallbackInfo->ret = RestrictionsProxy::GetRestrictionsProxy()->GetDisallowedPolicy(
            nullptr, asyncCallbackInfo->policyCode, asyncCallbackInfo->boolRet, permissionTag);
    }
}

napi_value RestrictionsAddon::DisableMicrophone(napi_env env, napi_callback_info info)
{
    return SetPolicyDisabledSync(env, info, EdmInterfaceCode::DISABLE_MICROPHONE);
}

napi_value RestrictionsAddon::IsMicrophoneDisabled(napi_env env, napi_callback_info info)
{
    return IsPolicyDisabledSync(env, info, EdmInterfaceCode::DISABLE_MICROPHONE);
}

napi_value RestrictionsAddon::SetFingerprintAuthDisabled(napi_env env, napi_callback_info info)
{
    EDMLOGI("SetFingerprintAuthDisabled called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter admin error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ONE], napi_boolean),
        "parameter disallow error");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    EDMLOGD("SetFingerprintAuthDisabled: elementName.bundleName %{public}s, elementName.abilityName:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());
    bool disallow = false;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseBool(env, disallow, argv[ARR_INDEX_ONE]), "parameter disallow parse error");

    auto proxy = RestrictionsProxy::GetRestrictionsProxy();
    if (proxy == nullptr) {
        EDMLOGE("can not get RestrictionsProxy");
        napi_throw(env, CreateError(env, EdmReturnErrCode::SYSTEM_ABNORMALLY));
        return nullptr;
    }
    ErrCode ret = proxy->SetFingerprintAuthDisabled(elementName, disallow);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
}

napi_value RestrictionsAddon::IsFingerprintAuthDisabled(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_IsFingerprintAuthDisabled called");
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    bool hasAdmin = false;
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, CheckGetPolicyAdminParam(env, argv[ARR_INDEX_ZERO], hasAdmin, elementName),
        "param admin need be null or want");
    EDMLOGD("IsFingerprintAuthDisabled: elementName.bundleName %{public}s, elementName.abilityName:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());

    auto proxy = RestrictionsProxy::GetRestrictionsProxy();
    if (proxy == nullptr) {
        EDMLOGE("can not get RestrictionsProxy");
        napi_throw(env, CreateError(env, EdmReturnErrCode::SYSTEM_ABNORMALLY));
        return nullptr;
    }
    bool disallow = false;
    ErrCode ret;
    if (hasAdmin) {
        ret = proxy->IsFingerprintAuthDisabled(&elementName, disallow);
    } else {
        ret = proxy->IsFingerprintAuthDisabled(nullptr, disallow);
    }
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, disallow, &result));
    return result;
}

napi_value RestrictionsAddon::SetPolicyDisabledSync(napi_env env, napi_callback_info info, int policyCode)
{
    EDMLOGI("NAPI_SetPolicyDisabledSync called");
    AddonMethodSign addonMethodSign;
    SetPolicyDisabledCommon(addonMethodSign, policyCode);

    AdapterAddonData adapterAddonData{};
    if (JsObjectToData(env, info, addonMethodSign, &adapterAddonData) == nullptr) {
        return nullptr;
    }
    ErrCode ret = RestrictionsProxy::GetRestrictionsProxy()->SetDisallowedPolicy(adapterAddonData.data, policyCode);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
}

napi_value RestrictionsAddon::IsPolicyDisabledSync(napi_env env, napi_callback_info info, int policyCode)
{
    EDMLOGI("NAPI_IsPolicyDisabled called");
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    bool hasAdmin = false;
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, CheckGetPolicyAdminParam(env, argv[ARR_INDEX_ZERO], hasAdmin, elementName),
        "param admin need be null or want");
    ErrCode ret = ERR_OK;
    bool boolRet = false;
    std::string permissionTag = (std::find(multiPermCodes.begin(), multiPermCodes.end(),
        policyCode) == multiPermCodes.end()) ? WITHOUT_PERMISSION_TAG : EdmConstants::PERMISSION_TAG_VERSION_11;
    if (hasAdmin) {
        ret = RestrictionsProxy::GetRestrictionsProxy()->GetDisallowedPolicy(&elementName, policyCode, boolRet,
            permissionTag);
    } else {
        ret = RestrictionsProxy::GetRestrictionsProxy()->GetDisallowedPolicy(nullptr, policyCode, boolRet,
            permissionTag);
    }
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        EDMLOGE("SetPolicyDisabledSync failed!");
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, boolRet, &result));
    return result;
}

napi_value RestrictionsAddon::SetDisallowedPolicy(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_SetDisallowedPolicy called");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_THREE, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter admin error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_TWO], napi_boolean),
        "parameter disallow error");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    EDMLOGD("SetDisallowedPolicy: elementName.bundleName %{public}s, elementName.abilityName:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());
    std::uint32_t ipcCode = 0;
    std::string feature;
    ErrcodeType errcodeType = ErrcodeType::STRING;
    auto ret = GetInterfaceCodeAndFeature(env, argv[ARR_INDEX_ONE], feature, ipcCode, errcodeType);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret, errcodeType));
        return nullptr;
    }
    bool disallow = false;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseBool(env, disallow, argv[ARR_INDEX_TWO]), "parameter disallow parse error");

    ret = NativeSetDisallowedPolicy(elementName, disallow, ipcCode, errcodeType);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret, errcodeType));
    }
    return nullptr;
}

OHOS::ErrCode RestrictionsAddon::GetInterfaceCodeAndFeature(napi_env env, napi_value value,
    std::string &feature, uint32_t &ipcCode, ErrcodeType &errcodeType)
{
    if (MatchValueType(env, value, napi_string)) {
        errcodeType = ErrcodeType::STRING;
        if (!ParseString(env, feature, value)) {
            return EdmReturnErrCode::PARAM_ERROR;
        }
        auto labelCode = labelCodeMap.find(feature);
        if (labelCode == labelCodeMap.end()) {
            return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
        }
        ipcCode = labelCode->second;
    } else if (MatchValueType(env, value, napi_number)) {
        errcodeType = ErrcodeType::NUMBER;
        int32_t featureNumber = -1;
        if (!ParseInt(env, featureNumber, value)) {
            return EdmReturnErrCode::PARAM_ERROR;
        }
        auto it = featureEnum2InterfaceCodeMap.find(featureNumber);
        if (it == featureEnum2InterfaceCodeMap.end()) {
            return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
        }
        ipcCode = it->second;
    } else {
        errcodeType = ErrcodeType::STRING;
        return EdmReturnErrCode::PARAM_ERROR;
    }
    return ERR_OK;
}

napi_value RestrictionsAddon::GetDisallowedPolicy(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    bool hasAdmin = false;
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, CheckGetPolicyAdminParam(env, argv[ARR_INDEX_ZERO], hasAdmin, elementName),
        "param admin need be null or want");
    std::uint32_t ipcCode = 0;
    std::string feature;
    ErrcodeType errcodeType = ErrcodeType::STRING;
    auto ret = GetInterfaceCodeAndFeature(env, argv[ARR_INDEX_ONE], feature, ipcCode, errcodeType);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret, errcodeType));
        return nullptr;
    }
    if (hasAdmin) {
        EDMLOGD("GetDisallowedPolicy: elementName.bundleName %{public}s, elementName.abilityName:%{public}s",
            elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());
    } else {
        EDMLOGD("GetDisallowedPolicy: elementName is null");
    }

    bool disallow = false;
    ret = NativeGetDisallowedPolicy(hasAdmin ? &elementName : nullptr, ipcCode, disallow, errcodeType);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret, errcodeType));
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, disallow, &result));
    return result;
}

napi_value RestrictionsAddon::SetDisallowedPolicyForAccount(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_SetDisallowedPolicyForAccount called");
    size_t argc = ARGS_SIZE_FOUR;
    napi_value argv[ARGS_SIZE_FOUR] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_FOUR, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter admin error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_TWO], napi_boolean),
        "parameter disallow error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_THREE], napi_number),
        "parameter accountId error");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    EDMLOGD("SetDisallowedPolicyForAccount: elementName.bundleName %{public}s, elementName.abilityName:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());
    std::uint32_t ipcCode = 0;
    std::string feature;
    ErrcodeType errcodeType = ErrcodeType::STRING;
    auto ret = GetInterfaceCodeAndFeatureForAccount(env, argv[ARR_INDEX_ONE], feature, ipcCode, errcodeType);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret, errcodeType));
        return nullptr;
    }
    bool disallow = false;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseBool(env, disallow, argv[ARR_INDEX_TWO]), "parameter disallow parse error");
    int32_t accountId = -1;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, accountId, argv[ARR_INDEX_THREE]),
        "parameter accountId parse error");
    auto proxy = RestrictionsProxy::GetRestrictionsProxy();
    if (proxy == nullptr) {
        EDMLOGE("can not get RestrictionsProxy");
        napi_throw(env, CreateError(env, EdmReturnErrCode::SYSTEM_ABNORMALLY, errcodeType));
        return nullptr;
    }
    std::string permissionTag = (errcodeType == ErrcodeType::NUMBER) ?
        EdmConstants::PERMISSION_TAG_VERSION_23 : WITHOUT_PERMISSION_TAG;
    if (ipcCode == EdmInterfaceCode::FINGERPRINT_AUTH) {
        ret = proxy->SetFingerprintAuthDisallowedPolicyForAccount(elementName, disallow,
            ipcCode, permissionTag, accountId);
    } else {
        ret = proxy->SetDisallowedPolicyForAccount(elementName, disallow, ipcCode, permissionTag, accountId);
    }
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret, errcodeType));
    }
    return nullptr;
}

OHOS::ErrCode RestrictionsAddon::GetInterfaceCodeAndFeatureForAccount(napi_env env, napi_value value,
    std::string &feature, uint32_t &ipcCode, ErrcodeType &errcodeType)
{
    if (MatchValueType(env, value, napi_string)) {
        errcodeType = ErrcodeType::STRING;
        if (!ParseString(env, feature, value)) {
            return EdmReturnErrCode::PARAM_ERROR;
        }
        auto labelCode = labelCodeMapForAccount.find(feature);
        if (labelCode == labelCodeMapForAccount.end()) {
            return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
        }
        ipcCode = labelCode->second;
    } else if (MatchValueType(env, value, napi_number)) {
        errcodeType = ErrcodeType::NUMBER;
        int32_t featureNumber = -1;
        if (!ParseInt(env, featureNumber, value)) {
            return EdmReturnErrCode::PARAM_ERROR;
        }
        auto it = featureForAccountEnum2InterfaceCodeMap.find(featureNumber);
        if (it == featureForAccountEnum2InterfaceCodeMap.end()) {
            return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
        }
        ipcCode = it->second;
    } else {
        errcodeType = ErrcodeType::STRING;
        return EdmReturnErrCode::PARAM_ERROR;
    }
    return ERR_OK;
}

napi_value RestrictionsAddon::GetDisallowedPolicyForAccount(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetDisallowedPolicyForAccount called");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_THREE, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_TWO], napi_number),
        "parameter accountId error");
    bool hasAdmin = false;
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, CheckGetPolicyAdminParam(env, argv[ARR_INDEX_ZERO], hasAdmin, elementName),
        "param admin need be null or want");
    EDMLOGD("GetDisallowedPolicyForAccount: elementName.bundleName %{public}s, elementName.abilityName:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());
    std::uint32_t ipcCode = 0;
    std::string feature;
    ErrcodeType errcodeType = ErrcodeType::STRING;
    auto ret = GetInterfaceCodeAndFeatureForAccount(env, argv[ARR_INDEX_ONE], feature, ipcCode, errcodeType);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret, errcodeType));
        return nullptr;
    }
    int32_t accountId = -1;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, accountId, argv[ARR_INDEX_TWO]), "parameter accountId parse error");

    bool disallow = false;
    ret = NativeGetDisallowedPolicyForAccount(hasAdmin ? &elementName : nullptr,
        ipcCode, accountId, disallow, errcodeType);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret, errcodeType));
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, disallow, &result));
    return result;
}

OHOS::ErrCode RestrictionsAddon::NativeGetDisallowedPolicyForAccount(AppExecFwk::ElementName *elementName,
    std::uint32_t ipcCode, int32_t accountId, bool &disallow, ErrcodeType errcodeType)
{
    std::string permissionTag = (errcodeType == ErrcodeType::NUMBER) ?
        EdmConstants::PERMISSION_TAG_VERSION_23 : WITHOUT_PERMISSION_TAG;
    auto proxy = RestrictionsProxy::GetRestrictionsProxy();
    if (proxy == nullptr) {
        EDMLOGE("can not get RestrictionsProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (ipcCode == EdmInterfaceCode::FINGERPRINT_AUTH) {
        return proxy->GetFingerprintAuthDisallowedPolicyForAccount(elementName, ipcCode,
            disallow, permissionTag, accountId);
    } else {
        if (elementName == nullptr && errcodeType == ErrcodeType::STRING) {
            return EdmReturnErrCode::PARAM_ERROR;
        }
        return proxy->GetDisallowedPolicyForAccount(elementName, ipcCode, disallow, permissionTag, accountId);
    }
}

napi_value RestrictionsAddon::AddDisallowedListForAccount(napi_env env, napi_callback_info info)
{
    return AddOrRemoveDisallowedListForAccount(env, info, true);
}

napi_value RestrictionsAddon::RemoveDisallowedListForAccount(napi_env env, napi_callback_info info)
{
    return AddOrRemoveDisallowedListForAccount(env, info, false);
}

napi_value RestrictionsAddon::GetDisallowedListForAccount(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetDisallowedListForAccount called");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_THREE, "parameter count error");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "param admin need be want");
    std::string feature;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseString(env, feature, argv[ARR_INDEX_ONE]), "parameter feature parse error");

    int32_t accountId = -1;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, accountId, argv[ARR_INDEX_TWO]), "parameter accountId parse error");

    auto proxy = RestrictionsProxy::GetRestrictionsProxy();
    if (proxy == nullptr) {
        EDMLOGE("can not get RestrictionsProxy");
        napi_throw(env, CreateError(env, EdmReturnErrCode::SYSTEM_ABNORMALLY));
        return nullptr;
    }
    std::vector<std::string> resultArray;
    ErrCode ret = proxy->GetDisallowedListForAccount(elementName, feature, accountId, resultArray);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_array(env, &result));
    ConvertStringVectorToJS(env, resultArray, result);
    return result;
}

napi_value RestrictionsAddon::AddOrRemoveDisallowedListForAccount(napi_env env, napi_callback_info info,
    bool isAdd)
{
    EDMLOGI("NAPI_AddOrRemoveDisallowedListForAccount called");
    size_t argc = ARGS_SIZE_FOUR;
    napi_value argv[ARGS_SIZE_FOUR] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_FOUR, "parameter count error");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    EDMLOGD("SetDisallowedPolicy: elementName.bundleName %{public}s, elementName.abilityName:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());
    std::string feature;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseString(env, feature, argv[ARR_INDEX_ONE]), "parameter feature parse error");
    std::vector<std::string> bundleNameArray;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseStringArray(env, bundleNameArray, argv[ARR_INDEX_TWO]),
        "parameter bundle name error");
    int32_t accountId = 0;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, accountId, argv[ARR_INDEX_THREE]),
        "parameter accountId parse error");

    auto proxy = RestrictionsProxy::GetRestrictionsProxy();
    if (proxy == nullptr) {
        EDMLOGE("can not get RestrictionsProxy");
        napi_throw(env, CreateError(env, EdmReturnErrCode::SYSTEM_ABNORMALLY));
        return nullptr;
    }
    ErrCode ret = proxy->AddOrRemoveDisallowedListForAccount(elementName, feature, bundleNameArray, accountId, isAdd);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
}

napi_value RestrictionsAddon::SetUserRestriction(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_SetUserRestriction called");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_THREE, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter admin error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_TWO], napi_boolean),
        "parameter disallow error");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    EDMLOGD("SetUserRestriction: elementName.bundleName %{public}s, elementName.abilityName:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());
    std::uint32_t ipcCode = 0;
    ErrcodeType errcodeType = ErrcodeType::STRING;
    auto ret = GetInterfaceCodeAndSettingsItem(env, argv[ARR_INDEX_ONE],
        ipcCode, errcodeType, SettingsItemMode::SET_DEVICE);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret, errcodeType));
        return nullptr;
    }
    bool disallow = false;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseBool(env, disallow, argv[ARR_INDEX_TWO]),
        "parameter disallow parse error");

    auto proxy = RestrictionsProxy::GetRestrictionsProxy();
    if (proxy == nullptr) {
        EDMLOGE("can not get RestrictionsProxy");
        napi_throw(env, CreateError(env, EdmReturnErrCode::SYSTEM_ABNORMALLY, errcodeType));
        return nullptr;
    }
    ret = proxy->SetUserRestriction(elementName, disallow, ipcCode);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret, errcodeType));
    }
    return nullptr;
}

napi_value RestrictionsAddon::GetUserRestricted(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetUserRestricted called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    bool hasAdmin = false;
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, CheckGetPolicyAdminParam(env, argv[ARR_INDEX_ZERO], hasAdmin, elementName),
        "param admin need be null or want");
    std::uint32_t ipcCode = 0;
    ErrcodeType errcodeType = ErrcodeType::STRING;
    auto ret = GetInterfaceCodeAndSettingsItem(env, argv[ARR_INDEX_ONE],
        ipcCode, errcodeType, SettingsItemMode::QUERY_DEVICE);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret, errcodeType));
        return nullptr;
    }
    if (hasAdmin) {
        EDMLOGD("GetUserRestricted: elementName.bundleName %{public}s, elementName.abilityName:%{public}s",
            elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());
    } else {
        EDMLOGD("GetUserRestricted: elementName is null");
    }

    auto proxy = RestrictionsProxy::GetRestrictionsProxy();
    if (proxy == nullptr) {
        EDMLOGE("can not get RestrictionsProxy");
        napi_throw(env, CreateError(env, EdmReturnErrCode::SYSTEM_ABNORMALLY, errcodeType));
        return nullptr;
    }

    bool restricted = false;
    ret = proxy->GetUserRestricted(hasAdmin ? &elementName : nullptr, ipcCode, restricted);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret, errcodeType));
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, restricted, &result));
    return result;
}

napi_value RestrictionsAddon::SetUserRestrictionForAccount(napi_env env, napi_callback_info info)
{
    EDMLOGD("NAPI_SetUserRestrictionForAccount called");
    size_t argc = ARGS_SIZE_FOUR;
    napi_value argv[ARGS_SIZE_FOUR] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_FOUR, "parameter count error");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    std::uint32_t ipcCode = 0;
    ErrcodeType errcodeType = ErrcodeType::STRING;
    auto ret = GetInterfaceCodeAndSettingsItem(env, argv[ARR_INDEX_ONE],
        ipcCode, errcodeType, SettingsItemMode::SET_ACCOUNT);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret, errcodeType));
        return nullptr;
    }
    int32_t accountId = 0;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, accountId, argv[ARR_INDEX_TWO]),
        "parameter accountId parse error");
    bool disallow = false;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseBool(env, disallow, argv[ARR_INDEX_THREE]),
        "parameter disallow parse error");
    auto proxy = RestrictionsProxy::GetRestrictionsProxy();
    if (proxy == nullptr) {
        EDMLOGE("can not get RestrictionsProxy");
        napi_throw(env, CreateError(env, EdmReturnErrCode::SYSTEM_ABNORMALLY, errcodeType));
        return nullptr;
    }
    std::string permissionTag = (errcodeType == ErrcodeType::NUMBER) ?
        EdmConstants::PERMISSION_TAG_VERSION_23 : WITHOUT_PERMISSION_TAG;
    ret = proxy->SetUserRestrictionForAccount(elementName, accountId, disallow, permissionTag, ipcCode);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret, errcodeType));
    }
    return nullptr;
}

napi_value RestrictionsAddon::GetUserRestrictedForAccount(napi_env env, napi_callback_info info)
{
    EDMLOGD("NAPI_GetUserRestrictedForAccount called");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_THREE, "parameter count error");
    bool hasAdmin = false;
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, CheckGetPolicyAdminParam(env, argv[ARR_INDEX_ZERO], hasAdmin, elementName),
        "param admin need be null or want");
    std::uint32_t ipcCode = 0;
    ErrcodeType errcodeType = ErrcodeType::STRING;
    auto ret = GetInterfaceCodeAndSettingsItem(env, argv[ARR_INDEX_ONE],
        ipcCode, errcodeType, SettingsItemMode::QUERY_ACCOUNT);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret, errcodeType));
        return nullptr;
    }
    int32_t accountId = 0;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, accountId, argv[ARR_INDEX_TWO]),
        "parameter accountId parse error");
    if (hasAdmin) {
        EDMLOGD("GetUserRestrictedForAccount: elementName.bundleName %{public}s, elementName.abilityName:%{public}s",
            elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());
    } else {
        EDMLOGD("GetUserRestrictedForAccount: elementName is null");
    }
    auto proxy = RestrictionsProxy::GetRestrictionsProxy();
    if (proxy == nullptr) {
        EDMLOGE("can not get RestrictionsProxy");
        napi_throw(env, CreateError(env, EdmReturnErrCode::SYSTEM_ABNORMALLY, errcodeType));
        return nullptr;
    }
    bool restricted = false;
    std::string permissionTag = (errcodeType == ErrcodeType::NUMBER) ?
        EdmConstants::PERMISSION_TAG_VERSION_23 : WITHOUT_PERMISSION_TAG;
    ret = proxy->GetUserRestrictedForAccount(hasAdmin ? &elementName : nullptr,
        accountId, ipcCode, permissionTag, restricted);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret, errcodeType));
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, restricted, &result));
    return result;
}

void RestrictionsAddon::SetEnumProperty(napi_env env, napi_value obj, const char *name, uint32_t value)
{
    napi_value nVal;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, value, &nVal));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, obj, name, nVal));
}

void RestrictionsAddon::CreateFeatureForDeviceObject(napi_env env, napi_value value)
{
    CreateFeatureForDevicePart1(env, value);
    CreateFeatureForDevicePart2(env, value);
}

void RestrictionsAddon::CreateFeatureForDevicePart1(napi_env env, napi_value value)
{
    struct EnumEntry { const char *name; uint32_t val; };
    EnumEntry entries[] = {
        {"WIFI_P2P", static_cast<uint32_t>(RestrictionsFeature::WIFI_P2P)},
        {"SUDO", static_cast<uint32_t>(RestrictionsFeature::SUDO)},
        {"LOCAL_INPUT", static_cast<uint32_t>(RestrictionsFeature::LOCAL_INPUT)},
        {"TRAFFIC_REDIRECTION", static_cast<uint32_t>(RestrictionsFeature::TRAFFIC_REDIRECTION)},
        {"CORE_DUMP", static_cast<uint32_t>(RestrictionsFeature::CORE_DUMP)},
        {"DISK_ERASURE", static_cast<uint32_t>(RestrictionsFeature::SECURE_ERASE)},
        {"RS232", static_cast<uint32_t>(RestrictionsFeature::RS232)},
        {"BLUETOOTH", static_cast<uint32_t>(RestrictionsFeature::BLUETOOTH)},
        {"MODIFY_DATETIME", static_cast<uint32_t>(RestrictionsFeature::MODIFY_DATETIME)},
        {"PRINTER", static_cast<uint32_t>(RestrictionsFeature::PRINTER)},
        {"HDC", static_cast<uint32_t>(RestrictionsFeature::HDC)},
        {"MICROPHONE", static_cast<uint32_t>(RestrictionsFeature::MICROPHONE)},
        {"FINGERPRINT", static_cast<uint32_t>(RestrictionsFeature::FINGERPRINT)},
        {"USB", static_cast<uint32_t>(RestrictionsFeature::USB)},
        {"WIFI", static_cast<uint32_t>(RestrictionsFeature::WIFI)},
        {"MTP_CLIENT", static_cast<uint32_t>(RestrictionsFeature::MTP_CLIENT)},
        {"MTP_SERVER", static_cast<uint32_t>(RestrictionsFeature::MTP_SERVER)},
        {"SAMBA_CLIENT", static_cast<uint32_t>(RestrictionsFeature::SAMBA_CLIENT)},
        {"SAMBA_SERVER", static_cast<uint32_t>(RestrictionsFeature::SAMBA_SERVER)},
        {"MAINTENANCE_MODE", static_cast<uint32_t>(RestrictionsFeature::MAINTENANCE_MODE)},
        {"REMOTE_DESK", static_cast<uint32_t>(RestrictionsFeature::REMOTE_DESK)},
        {"REMOTE_DIAGNOSIS", static_cast<uint32_t>(RestrictionsFeature::REMOTE_DIAGNOSIS)},
        {"SCREENSHOT", static_cast<uint32_t>(RestrictionsFeature::SCREENSHOT)},
        {"SCREEN_RECORD", static_cast<uint32_t>(RestrictionsFeature::SCREEN_RECORD)},
    };
    for (auto &e : entries) {
        SetEnumProperty(env, value, e.name, e.val);
    }
}

void RestrictionsAddon::CreateFeatureForDevicePart2(napi_env env, napi_value value)
{
    struct EnumEntry { const char *name; uint32_t val; };
    EnumEntry entries[] = {
        {"DISK_RECOVERY_KEY", static_cast<uint32_t>(RestrictionsFeature::DISK_RECOVERY_KEY)},
        {"NEAR_LINK", static_cast<uint32_t>(RestrictionsFeature::NEAR_LINK)},
        {"TETHERING", static_cast<uint32_t>(RestrictionsFeature::TETHERING)},
        {"INACTIVE_USER_FREEZE", static_cast<uint32_t>(RestrictionsFeature::INACTIVE_USER_FREEZE)},
        {"CAMERA", static_cast<uint32_t>(RestrictionsFeature::CAMERA)},
        {"DEVELOPER_MODE", static_cast<uint32_t>(RestrictionsFeature::DEVELOPER_MODE)},
        {"RESET_FACTORY", static_cast<uint32_t>(RestrictionsFeature::RESET_FACTORY)},
        {"NFC", static_cast<uint32_t>(RestrictionsFeature::NFC)},
        {"SMS", static_cast<uint32_t>(RestrictionsFeature::SMS)},
        {"MMS", static_cast<uint32_t>(RestrictionsFeature::MMS)},
        {"BACKUP_AND_RESTORE", static_cast<uint32_t>(RestrictionsFeature::BACKUP_AND_RESTORE)},
        {"MOBILE_DATA", static_cast<uint32_t>(RestrictionsFeature::MOBILE_DATA)},
        {"AIRPLANE_MODE", static_cast<uint32_t>(RestrictionsFeature::AIRPLANE_MODE)},
        {"NOTIFICATION", static_cast<uint32_t>(RestrictionsFeature::NOTIFICATION)},
        {"APP_CLONE", static_cast<uint32_t>(RestrictionsFeature::APP_CLONE)},
        {"TELEPHONY_CALL", static_cast<uint32_t>(RestrictionsFeature::TELEPHONY_CALL)},
        {"VPN", static_cast<uint32_t>(RestrictionsFeature::VPN)},
        {"OTA_UPDATE", static_cast<uint32_t>(RestrictionsFeature::OTA_UPDATE)},
        {"RANDOM_MAC", static_cast<uint32_t>(RestrictionsFeature::RANDOM_MAC)},
        {"EXTERNAL_STORAGE_CARD", static_cast<uint32_t>(RestrictionsFeature::EXTERNAL_STORAGE_CARD)},
        {"PRIVATE_SPACE", static_cast<uint32_t>(RestrictionsFeature::PRIVATE_SPACE)},
        {"HDC_REMOTE", static_cast<uint32_t>(RestrictionsFeature::HDC_REMOTE)},
        {"UNMUTE_DEVICE", static_cast<uint32_t>(RestrictionsFeature::UNMUTE_DEVICE)},
        {"VIRTUAL_SERVICE", static_cast<uint32_t>(RestrictionsFeature::VIRTUAL_SERVICE)},
        {"USB_SERIAL", static_cast<uint32_t>(RestrictionsFeature::USB_SERIAL)},
    };
    for (auto &e : entries) {
        SetEnumProperty(env, value, e.name, e.val);
    }
}

void RestrictionsAddon::CreateFeatureForAccountObject(napi_env env, napi_value value)
{
    struct EnumEntry { const char *name; uint32_t val; };
    EnumEntry entries[] = {
        {"MULTI_WINDOW", static_cast<uint32_t>(RestrictionsFeatureForAccount::MULTI_WINDOW)},
        {"DISTRIBUTED_TRANSMISSION", static_cast<uint32_t>(RestrictionsFeatureForAccount::DISTRIBUTED_TRANSMISSION)},
        {"SUPER_HUB", static_cast<uint32_t>(RestrictionsFeatureForAccount::SUPER_HUB)},
        {"FINGERPRINT", static_cast<uint32_t>(RestrictionsFeatureForAccount::FINGERPRINT)},
        {"PRINT", static_cast<uint32_t>(RestrictionsFeatureForAccount::PRINT)},
        {"MTP_CLIENT", static_cast<uint32_t>(RestrictionsFeatureForAccount::MTP_CLIENT)},
        {"USB_STORAGE_DEVICE_WRITE", static_cast<uint32_t>(RestrictionsFeatureForAccount::USB_STORAGE_DEVICE_WRITE)},
        {"DISK_RECOVERY_KEY", static_cast<uint32_t>(RestrictionsFeatureForAccount::DISK_RECOVERY_KEY)},
        {"SUDO", static_cast<uint32_t>(RestrictionsFeatureForAccount::SUDO)},
        {"DISTRIBUTED_TRANSMISSION_OUTGOING",
            static_cast<uint32_t>(RestrictionsFeatureForAccount::DISTRIBUTED_TRANSMISSION_OUTGOING)},
        {"OPEN_FILE_BOOST", static_cast<uint32_t>(RestrictionsFeatureForAccount::OPEN_FILE_BOOST)},
    };
    for (auto &e : entries) {
        SetEnumProperty(env, value, e.name, e.val);
    }
}

void RestrictionsAddon::CreateUserRestrictionForDeviceObject(napi_env env, napi_value value)
{
    struct EnumEntry { const char *name; uint32_t val; };
    EnumEntry entries[] = {
        {"SET_APN", static_cast<uint32_t>(UserRestrictionForDevice::SET_APN)},
        {"POWER_LONG_PRESS", static_cast<uint32_t>(UserRestrictionForDevice::POWER_LONG_PRESS)},
        {"SET_ETHERNET_IP", static_cast<uint32_t>(UserRestrictionForDevice::SET_ETHERNET_IP)},
        {"SET_DEVICE_NAME", static_cast<uint32_t>(UserRestrictionForDevice::SET_DEVICE_NAME)},
        {"SET_BIOMETRICS_AND_SCREENLOCK",
            static_cast<uint32_t>(UserRestrictionForDevice::SET_BIOMETRICS_AND_SCREENLOCK)},
    };
    for (auto &e : entries) {
        SetEnumProperty(env, value, e.name, e.val);
    }
}

void RestrictionsAddon::CreateUserRestrictionForAccountObject(napi_env env, napi_value value)
{
    struct EnumEntry { const char *name; uint32_t val; };
    EnumEntry entries[] = {
        {"MODIFY_WALLPAPER", static_cast<uint32_t>(UserRestrictionForAccount::MODIFY_WALLPAPER)},
    };
    for (auto &e : entries) {
        SetEnumProperty(env, value, e.name, e.val);
    }
}

OHOS::ErrCode RestrictionsAddon::GetInterfaceCodeAndSettingsItem(napi_env env, napi_value value,
    uint32_t &ipcCode, ErrcodeType &errcodeType, SettingsItemMode mode)
{
    if (MatchValueType(env, value, napi_string)) {
        errcodeType = ErrcodeType::STRING;
        std::string settingsItem;
        if (!ParseString(env, settingsItem, value)) {
            return EdmReturnErrCode::PARAM_ERROR;
        }
        if (mode == SettingsItemMode::SET_DEVICE) {
            auto it = itemCodeMap.find(settingsItem);
            if (it == itemCodeMap.end()) {
                return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
            }
            ipcCode = it->second;
        } else if (mode == SettingsItemMode::QUERY_DEVICE) {
            auto it = itemQueryCodeMap.find(settingsItem);
            if (it == itemQueryCodeMap.end()) {
                return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
            }
            ipcCode = it->second;
        } else {
            auto it = itemCodeForAccountMap.find(settingsItem);
            if (it == itemCodeForAccountMap.end()) {
                return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
            }
            ipcCode = it->second;
        }
    } else if (MatchValueType(env, value, napi_number)) {
        errcodeType = ErrcodeType::NUMBER;
        int32_t featureNumber = -1;
        if (!ParseInt(env, featureNumber, value)) {
            return EdmReturnErrCode::PARAM_ERROR;
        }
        bool isAccount = (mode == SettingsItemMode::SET_ACCOUNT || mode == SettingsItemMode::QUERY_ACCOUNT);
        auto &enumMap = isAccount ? userRestrictionForAccountEnum2CodeMap
            : userRestrictionForDeviceEnum2CodeMap;
        auto it = enumMap.find(featureNumber);
        if (it == enumMap.end()) {
            return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
        }
        ipcCode = it->second;
    } else {
        errcodeType = ErrcodeType::STRING;
        return EdmReturnErrCode::PARAM_ERROR;
    }
    return ERR_OK;
}

static napi_module g_restrictionsModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = RestrictionsAddon::Init,
    .nm_modname = "enterprise.restrictions",
    .nm_priv = ((void *)0),
    .reserved = {0},
};

extern "C" __attribute__((constructor)) void RestrictionsRegister()
{
    napi_module_register(&g_restrictionsModule);
}
