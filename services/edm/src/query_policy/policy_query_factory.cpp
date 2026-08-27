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

#include "policy_query_factory.h"

#include "edm_constants.h"
#include "generic_policy_query.h"
#include "edm_log.h"

#ifdef USERIAM_EDM_ENABLE
#include "password_policy_query.h"
#include "fingerprint_auth_query.h"
#endif

#ifdef PASTEBOARD_EDM_ENABLE
#include "clipboard_policy_query.h"
#endif

#ifdef LOCATION_EDM_ENABLE
#include "location_policy_query.h"
#endif

#ifdef TELEPHONY_EDM_ENABLE
#include "telephony_call_policy_query.h"
#endif

#ifdef USB_SERVICE_EDM_ENABLE
#include "allowed_usb_devices_query.h"
#endif

#include "allowed_app_distribution_types_query.h"
#include "ntp_server_query.h"

#include "is_app_kiosk_allowed_query.h"

#include "allowed_notification_bundles_query.h"

#ifdef WIFI_EDM_ENABLE
#include "allowed_wifi_list_query.h"
#include "disallowed_wifi_list_query.h"
#endif

#include "set_browser_policies_query.h"

#include "get_display_version_query.h"
#include "get_security_patch_tag_query.h"
#include "get_device_encryption_status_query.h"
#include "get_watermark_image_apps_query.h"

#include "permission_managed_state_query.h"
#include "allowed_permission_bundle_query.h"
#include "device_security_level_policy_query.h"
#include "installed_bundle_info_list_query.h"
#include "get_installed_bundle_storage_stats_query.h"
#include "query_bundle_stats_infos_query.h"

#ifdef FEATURE_PC_ONLY
#include "install_local_enterprise_app_enabled_query.h"
#include "install_local_enterprise_app_enabled_for_account_query.h"
#include "get_auto_unlock_after_reboot_query.h"
#endif

#ifndef FEATURE_PC_ONLY
#include "hide_launcher_icon_query.h"
#endif

namespace OHOS {
namespace EDM {

std::shared_mutex PolicyQueryFactory::mutex_;
std::unordered_map<uint32_t, std::shared_ptr<IPolicyQuery>> PolicyQueryFactory::queryCache_;

ErrCode PolicyQueryFactory::CheckFeatureEnabled(uint32_t policyCode)
{
    const PolicyQueryConfigEntry* entry = PolicyQueryConfigTable::FindConfig(policyCode);
    if (entry == nullptr) {
        return ERR_CANNOT_FIND_QUERY_FAILED;
    }
    if (entry->config.isFeatureEnabled) {
        return ERR_OK;
    }
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
}

std::shared_ptr<IPolicyQuery> PolicyQueryFactory::CreateQuery(uint32_t policyCode)
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = queryCache_.find(policyCode);
    if (it != queryCache_.end()) {
        return it->second;
    }
    
    lock.unlock();
    std::unique_lock<std::shared_mutex> writeLock(mutex_);
    
    const PolicyQueryConfigEntry* entry = PolicyQueryConfigTable::FindConfig(policyCode);
    if (entry == nullptr) {
        EDMLOGE("PolicyQueryFactory: policyCode %{public}u not found in config table", policyCode);
        return nullptr;
    }
    
    const PolicyQueryConfig& config = entry->config;
    std::shared_ptr<IPolicyQuery> query;
    
    if (config.dataType == PolicyDataType::CUSTOM) {
        query = CreateCustomQuery(policyCode, config);
    } else {
        query = CreateGenericQuery(config);
    }
    
    if (query != nullptr) {
        queryCache_[policyCode] = query;
    }
    
    return query;
}

std::shared_ptr<IPolicyQuery> PolicyQueryFactory::CreateGenericQuery(
    const PolicyQueryConfig& config)
{
    return std::make_shared<GenericPolicyQuery>(config);
}

std::shared_ptr<IPolicyQuery> PolicyQueryFactory::CreateCustomDeviceInfoQuery(uint32_t policyCode)
{
    switch (policyCode) {
        case EdmInterfaceCode::GET_DISPLAY_VERSION:
            return std::make_shared<GetDisplayVersionQuery>();
        case EdmInterfaceCode::GET_SECURITY_PATCH_TAG:
            return std::make_shared<GetSecurityPatchTagQuery>();
        case EdmInterfaceCode::GET_DEVICE_ENCRYPTION_STATUS:
            return std::make_shared<GetDeviceEncryptionStatusQuery>();
        default:
            return nullptr;
    }
}

std::shared_ptr<IPolicyQuery> PolicyQueryFactory::CreateCustomSecurityQuery(uint32_t policyCode)
{
    switch (policyCode) {
#ifdef USERIAM_EDM_ENABLE
        case EdmInterfaceCode::PASSWORD_POLICY:
            return std::make_shared<PasswordPolicyQuery>();
        case EdmInterfaceCode::FINGERPRINT_AUTH:
            return std::make_shared<FingerprintAuthQuery>();
#endif
        case EdmInterfaceCode::WATERMARK_IMAGE:
            return std::make_shared<GetWatermarkImageAppsQuery>();
        case EdmInterfaceCode::PERMISSION_MANAGED_STATE:
            return std::make_shared<PermissionManagedStateQuery>();
        case EdmInterfaceCode::ALLOWED_PERMISSION_BUNDLE:
            return std::make_shared<AllowedPermissionBundleQuery>();
#ifdef USB_SERVICE_EDM_ENABLE
        case EdmInterfaceCode::ALLOWED_USB_DEVICES:
            return std::make_shared<AllowedUsbDevicesQuery>();
#endif
        case EdmInterfaceCode::DEVICE_SECURITY_LEVEL_POLICY:
            return std::make_shared<DeviceSecurityLevelPolicyQuery>();
        default:
            return nullptr;
    }
}

std::shared_ptr<IPolicyQuery> PolicyQueryFactory::CreateCustomAppManageQuery(uint32_t policyCode)
{
    switch (policyCode) {
#ifdef LOCATION_EDM_ENABLE
        case EdmInterfaceCode::LOCATION_POLICY:
            return std::make_shared<LocationPolicyQuery>();
#endif
#ifdef PASTEBOARD_EDM_ENABLE
        case EdmInterfaceCode::CLIPBOARD_POLICY:
            return std::make_shared<ClipboardPolicyQuery>();
#endif
        case EdmInterfaceCode::SET_BROWSER_POLICIES:
            return std::make_shared<SetBrowserPoliciesQuery>();
#ifdef TELEPHONY_EDM_ENABLE
        case EdmInterfaceCode::TELEPHONY_CALL_POLICY:
            return std::make_shared<TelephonyCallPolicyQuery>();
#endif
        case EdmInterfaceCode::GET_BUNDLE_INFO_LIST:
            return std::make_shared<InstalledBundleInfoListQuery>();
        case EdmInterfaceCode::ALLOWED_INSTALL_APP_TYPE:
            return std::make_shared<AllowedAppDistributionTypesQuery>();
        case EdmInterfaceCode::ALLOWED_NOTIFICATION_BUNDLES:
            return std::make_shared<AllowedNotificationBundlesQuery>();
        case EdmInterfaceCode::NTP_SERVER:
            return std::make_shared<NTPServerQuery>();
        case EdmInterfaceCode::GET_BUNDLE_STORAGE_STATS:
            return std::make_shared<GetInstalledBundleStorageStatsQuery>();
        case EdmInterfaceCode::QUERY_BUNDLE_STATS_INFOS:
            return std::make_shared<QueryBundleStatsInfosQuery>();
#ifdef WIFI_EDM_ENABLE
        case EdmInterfaceCode::ALLOWED_WIFI_LIST:
            return std::make_shared<AllowedWifiListQuery>();
        case EdmInterfaceCode::DISALLOWED_WIFI_LIST:
            return std::make_shared<DisallowedWifiListQuery>();
#endif
        default:
            return nullptr;
    }
}

std::shared_ptr<IPolicyQuery> PolicyQueryFactory::CreateCustomOtherQuery(uint32_t policyCode)
{
    switch (policyCode) {
#ifdef FEATURE_PC_ONLY
        case EdmInterfaceCode::SET_INSTALL_LOCAL_ENTERPRISE_APP_ENABLED:
            return std::make_shared<InstallLocalEnterpriseAppEnabledQuery>();
        case EdmInterfaceCode::INSTALL_LOCAL_ENTERPRISE_APP_ENABLED_FOR_ACCOUNT:
            return std::make_shared<InstallLocalEnterpriseAppEnabledForAccountQuery>();
        case EdmInterfaceCode::SET_AUTO_UNLOCK_AFTER_REBOOT:
            return std::make_shared<GetAutoUnlockAfterRebootQuery>();
#endif
#ifndef FEATURE_PC_ONLY
        case EdmInterfaceCode::POLICY_CODE_END + EdmConstants::PolicyCode::HIDE_LAUNCHER_ICON:
            return std::make_shared<HideLauncherIconQuery>();
#endif
        case EdmInterfaceCode::IS_APP_KIOSK_ALLOWED:
            return std::make_shared<IsAppKioskAllowedQuery>();
        default:
            return nullptr;
    }
}

std::shared_ptr<IPolicyQuery> PolicyQueryFactory::CreateCustomQuery(uint32_t policyCode,
    const PolicyQueryConfig& config)
{
    auto query = CreateCustomDeviceInfoQuery(policyCode);
    if (query != nullptr) {
        return query;
    }
    query = CreateCustomSecurityQuery(policyCode);
    if (query != nullptr) {
        return query;
    }
    query = CreateCustomAppManageQuery(policyCode);
    if (query != nullptr) {
        return query;
    }
    query = CreateCustomOtherQuery(policyCode);
    if (query != nullptr) {
        return query;
    }
    EDMLOGE("PolicyQueryFactory: custom query for policyCode %{public}u not implemented",
        policyCode);
    return nullptr;
}

} // namespace EDM
} // namespace OHOS