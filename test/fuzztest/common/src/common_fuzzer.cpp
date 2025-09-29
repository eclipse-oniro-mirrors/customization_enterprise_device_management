/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "common_fuzzer.h"

#include <system_ability_definition.h>

#define protected public
#define private public
#include "enterprise_device_mgr_ability.h"
#undef protected
#undef private
#ifdef OS_ACCOUNT_EDM_ENABLE
#include "add_os_account_plugin.h"
#endif
#include "allowed_bluetooth_devices_plugin.h"
#include "allowed_install_bundles_plugin.h"
#include "allowed_usb_devices_plugin.h"
#include "disable_bluetooth_plugin.h"
#include "disable_hdc_plugin.h"
#include "disable_microphone_plugin.h"
#include "disable_hdc_remote_plugin.h"
#include "disable_printer_plugin.h"
#include "disable_usb_plugin.h"
#include "disabled_network_interface_plugin.h"
#ifdef OS_ACCOUNT_EDM_ENABLE
#include "disallow_add_local_account_plugin.h"
#include "disallow_add_os_account_by_user_plugin.h"
#endif
#include "disallow_modify_datetime_plugin.h"
#include "disallowed_install_bundles_plugin.h"
#include "disallowed_running_bundles_plugin.h"
#include "disallowed_uninstall_bundles_plugin.h"
#include "domain_filter_rule_plugin.h"
#include "fingerprint_auth_plugin.h"
#include "firewall_rule_plugin.h"
#include "func_code.h"
#include "get_all_network_interfaces_plugin.h"
#include "get_bluetooth_info_plugin.h"
#include "get_device_info_plugin.h"
#include "get_ip_or_mac_address_plugin.h"
#include "global_proxy_plugin.h"
#include "ienterprise_device_mgr.h"
#ifdef FEATURE_PC_ONLY
#include "install_local_enterprise_app_enabled_plugin.h"
#endif
#include "install_plugin.h"
#include "iptables_rule_plugin.h"
#include "is_wifi_active_plugin.h"
#include "location_policy_plugin.h"
#include "lock_screen_plugin.h"
#include "manage_auto_start_apps_plugin.h"
#include "manage_auto_start_apps_serializer.h"
#include "manage_keep_alive_apps_plugin.h"
#include "ntp_server_plugin.h"
#include "operate_device_plugin.h"
#include "password_policy_plugin.h"
#include "power_policy_plugin.h"
#include "reset_factory_plugin.h"
#include "screen_off_time_plugin.h"
#include "set_browser_policies_plugin.h"
#include "set_wifi_disabled_plugin.h"
#include "set_wifi_profile_plugin.h"
#include "uninstall_plugin.h"
#include "usb_read_only_plugin.h"
#include "user_cert_plugin.h"
#include "utils.h"

namespace OHOS {
namespace EDM {
constexpr int32_t NUM_24 = 24;
constexpr int32_t NUM_16 = 16;
constexpr int32_t NUM_8 = 8;
constexpr int32_t NUM_INDEX_ZERO = 0;
constexpr int32_t NUM_INDEX_FIRST = 1;
constexpr int32_t NUM_INDEX_SECOND = 2;
constexpr int32_t NUM_INDEX_THIRD = 3;
constexpr int32_t BYTE_SIZE = 8;
constexpr int32_t MAX_STRING_SIZE = 1024;
#ifdef OS_ACCOUNT_EDM_ENABLE
const bool REGISTER_ADD_OS_ACCOUNT_PLUGIN = PluginManager::GetInstance()->AddPlugin(AddOsAccountPlugin::GetPlugin());
#endif
const bool REGISTER_ALLOWED_BLUETOOTH_DEVICES_PLUGIN =
    PluginManager::GetInstance()->AddPlugin(AllowedBluetoothDevicesPlugin::GetPlugin());
const bool REGISTER_ALLOWED_INSTALL_BUNDLES_PLUGIN =
    PluginManager::GetInstance()->AddPlugin(AllowedInstallBundlesPlugin::GetPlugin());
const bool REGISTER_ALLOW_USB_DEVICES_PLUGIN =
    PluginManager::GetInstance()->AddPlugin(AllowUsbDevicesPlugin::GetPlugin());
const bool REGISTER_DISABLE_BLUETOOTH_PLUGIN =
    PluginManager::GetInstance()->AddPlugin(DisableBluetoothPlugin::GetPlugin());
const bool REGISTER_DISABLE_HDC_PLUGIN = PluginManager::GetInstance()->AddPlugin(DisableHdcPlugin::GetPlugin());
const bool REGISTER_DISABLE_MICROPHONE_PLUGIN =
    PluginManager::GetInstance()->AddPlugin(DisableMicrophonePlugin::GetPlugin());
const bool REGISTER_DISABLE_HDC_REMOTE_PLUGIN =
    PluginManager::GetInstance()->AddPlugin(DisableHdcRemotePlugin::GetPlugin());
const bool REGISTER_DISABLE_PRINTER_PLUGIN = PluginManager::GetInstance()->AddPlugin(DisablePrinterPlugin::GetPlugin());
const bool REGISTER_DISABLE_USB_PLUGIN = PluginManager::GetInstance()->AddPlugin(DisableUsbPlugin::GetPlugin());
const bool REGISTER_DISABLED_NETWORK_INTERFACE_PLUGIN =
    PluginManager::GetInstance()->AddPlugin(DisabledNetworkInterfacePlugin::GetPlugin());
#ifdef OS_ACCOUNT_EDM_ENABLE
const bool REGISTER_DISALLOW_ADD_LOCAL_ACCOUNT_PLUGIN =
    PluginManager::GetInstance()->AddPlugin(DisallowAddLocalAccountPlugin::GetPlugin());
const bool REGISTER_DISALLOW_ADD_OS_ACCOUNT_BY_USER_PLUGIN =
    PluginManager::GetInstance()->AddPlugin(DisallowAddOsAccountByUserPlugin::GetPlugin());
#endif
const bool REGISTER_DISALL_MODIFY_DATE_TIME_PLUGIN =
    PluginManager::GetInstance()->AddPlugin(DisallModifyDateTimePlugin::GetPlugin());
const bool REGISTER_DISALLOWED_INSTALL_BUNDLES_PLUGIN =
    PluginManager::GetInstance()->AddPlugin(DisallowedInstallBundlesPlugin::GetPlugin());
const bool REGISTER_DISALLOWED_RUNNING_BUNDLES_PLUGIN =
    PluginManager::GetInstance()->AddPlugin(DisallowedRunningBundlesPlugin::GetPlugin());
const bool REGISTER_DISALLOWED_UNINSTALL_BUNDLES_PLUGIN =
    PluginManager::GetInstance()->AddPlugin(DisallowedUninstallBundlesPlugin::GetPlugin());
const bool REGISTER_DOMAIN_FILTER_RULE_PLUGIN =
    PluginManager::GetInstance()->AddPlugin(DomainFilterRulePlugin::GetPlugin());
#ifdef USERIAM_EDM_ENABLE
const bool REGISTER_FINGER_PRINT_AUTH_PLUGIN =
    PluginManager::GetInstance()->AddPlugin(std::make_shared<FingerprintAuthPlugin>());
const bool REGISTER_PASSWORD_POLICY_PLUGIN = PluginManager::GetInstance()->AddPlugin(PasswordPolicyPlugin::GetPlugin());
#endif
const bool REGISTER_FIREWALL_RULE_PLUGIN = PluginManager::GetInstance()->AddPlugin(FirewallRulePlugin::GetPlugin());
const bool REGISTER_GET_ALL_NETWORK_INTERFACES_PLUGIN =
    PluginManager::GetInstance()->AddPlugin(GetAllNetworkInterfacesPlugin::GetPlugin());
const bool REGISTER_GET_BLUETOOTH_INFO_PLUGIN =
    PluginManager::GetInstance()->AddPlugin(GetBluetoothInfoPlugin::GetPlugin());
const bool REGISTER_GET_DEVICE_INFO_PLUGIN = PluginManager::GetInstance()->AddPlugin(GetDeviceInfoPlugin::GetPlugin());
const bool REGISTER_GET_IP_OR_MAC_ADDRESS_PLUGIN =
    PluginManager::GetInstance()->AddPlugin(GetIpOrMacAddressPlugin::GetPlugin());
const bool REGISTER_GLOBAL_PROXY_PLUGIN = PluginManager::GetInstance()->AddPlugin(GlobalProxyPlugin::GetPlugin());
const bool REGISTER_INSTALL_PLUGIN = PluginManager::GetInstance()->AddPlugin(InstallPlugin::GetPlugin());
const bool REGISTER_IPTABLES_RULE_PLUGIN =
    PluginManager::GetInstance()->AddPlugin(std::make_shared<IptablesRulePlugin>());
const bool REGISTER_IS_WIFI_ACTIVE_PLUGIN = PluginManager::GetInstance()->AddPlugin(IsWifiActivePlugin::GetPlugin());
const bool REGISTER_LOCATION_POLICY_PLUGIN =
    PluginManager::GetInstance()->AddPlugin(LocationPolicyPlugin::GetPlugin());
const bool REGISTER_LOCK_SCREEN_PLUGIN = PluginManager::GetInstance()->AddPlugin(LockScreenPlugin::GetPlugin());
const bool REGISTER_MANAGE_AUTO_START_APPS_PLUGIN =
    PluginManager::GetInstance()->AddPlugin(std::make_shared<ManageAutoStartAppsPlugin>());
const bool REGISTER_NTP_SERVER_PLUGIN = PluginManager::GetInstance()->AddPlugin(NTPServerPlugin::GetPlugin());
const bool REGISTER_OPERATE_DEVICE_PLUGIN = PluginManager::GetInstance()->AddPlugin(OperateDevicePlugin::GetPlugin());
const bool REGISTER_POWER_POLICY_PLUGIN =
    PluginManager::GetInstance()->AddPlugin(std::make_shared<PowerPolicyPlugin>());
const bool REGISTER_RESET_FACTORY_PLUGIN = PluginManager::GetInstance()->AddPlugin(ResetFactoryPlugin::GetPlugin());
const bool REGISTER_SCREEN_OFF_TIME_PLUGIN = PluginManager::GetInstance()->AddPlugin(ScreenOffTimePlugin::GetPlugin());
const bool REGISTER_SET_BROWSER_POLICIES_PLUGIN =
    PluginManager::GetInstance()->AddPlugin(std::make_shared<SetBrowserPoliciesPlugin>());
const bool REGISTER_SET_WIFI_DISABLED_PLUGIN =
    PluginManager::GetInstance()->AddPlugin(SetWifiDisabledPlugin::GetPlugin());
const bool REGISTER_SET_WIFI_PROFILE_PLUGIN =
    PluginManager::GetInstance()->AddPlugin(SetWifiProfilePlugin::GetPlugin());
const bool REGISTER_UNINSTALL_PLUGIN = PluginManager::GetInstance()->AddPlugin(UninstallPlugin::GetPlugin());
const bool REGISTER_USB_READ_ONLY_PLUGIN =
    PluginManager::GetInstance()->AddPlugin(std::make_shared<UsbReadOnlyPlugin>());
const bool REGISTER_USER_CERT_PLUGIN = PluginManager::GetInstance()->AddPlugin(std::make_shared<UserCertPlugin>());
const bool REGISTER_MANAGE_KEEP_ALIVE_APPS_PLUGIN =
    PluginManager::GetInstance()->AddPlugin(std::make_shared<ManageKeepAliveAppsPlugin>());
#ifdef FEATURE_PC_ONLY
const bool REGISTER_INSTALL_LOCAL_ENTERPRISE_APP_ENABLED_PLUGIN =
    PluginManager::GetInstance()->AddPlugin(InstallLocalEnterpriseAppEnabledPlugin::GetPlugin());
#endif

void CommonFuzzer::OnRemoteRequestFuzzerTest(uint32_t code, const uint8_t* data, size_t size, MessageParcel& parcel)
{
    TEST::Utils::SetUid();
    sptr<EnterpriseDeviceMgrAbility> enterpriseDeviceMgrAbility = EnterpriseDeviceMgrAbility::GetInstance();
    enterpriseDeviceMgrAbility->OnStart();

    MessageParcel reply;
    MessageOption option;

    enterpriseDeviceMgrAbility->OnRemoteRequest(code, parcel, reply, option);
    TEST::Utils::ResetUid();
}

void CommonFuzzer::SetParcelContent(MessageParcel& parcel, const uint8_t* data, size_t size)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.example.edmtest");
    admin.SetAbilityName("com.example.edmtest.EnterpriseAdminAbility");
    parcel.WriteInterfaceToken(IEnterpriseDeviceMgrIdl::GetDescriptor());
    parcel.WriteParcelable(&admin);
    parcel.WriteBuffer(data, size);
}

uint32_t CommonFuzzer::GetU32Data(const uint8_t* ptr)
{
    return (ptr[NUM_INDEX_ZERO] << NUM_24) | (ptr[NUM_INDEX_FIRST] << NUM_16) | (ptr[NUM_INDEX_SECOND] << NUM_8) |
        ptr[NUM_INDEX_THIRD];
}

int32_t CommonFuzzer::GetU32Data(const uint8_t* ptr, int32_t& pos, size_t size)
{
    if (size <= pos || size - pos < sizeof(int32_t)) {
        return 0;
    }
    int32_t ret = 0;
    pos += sizeof(int32_t);
    for (int i = 0; i < sizeof(int32_t); i++) {
        ret |= ((int32_t)ptr[i] << (BYTE_SIZE * i));
    }
    return ret;
}

long CommonFuzzer::GetLong(const uint8_t* ptr, int32_t& pos, size_t size)
{
    if (size <= pos || size - pos < sizeof(long)) {
        return 0;
    }
    long ret = 0;
    pos += sizeof(long);
    for (int i = 0; i < sizeof(long); i++) {
        ret |= ((long)ptr[i] << (BYTE_SIZE * i));
    }
    return ret;
}

std::string CommonFuzzer::GetString(const uint8_t* ptr, int32_t& pos, int32_t stringSize, size_t size)
{
    if (size <= pos) {
        return "";
    }
    stringSize = (stringSize > MAX_STRING_SIZE) ? MAX_STRING_SIZE : stringSize;
    std::string ret(reinterpret_cast<const char*>(ptr + pos), stringSize);
    pos += stringSize;
    if (size - pos < stringSize) {
        pos = 0;
    }
    return ret;
}
} // namespace EDM
} // namespace OHOS