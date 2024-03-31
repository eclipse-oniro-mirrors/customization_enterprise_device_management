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

#include "message_parcel_utils.h"

#include "edm_log.h"
#include "securec.h"

namespace OHOS {
namespace EDM {
#ifdef WIFI_EDM_ENABLE
void MessageParcelUtils::WriteWifiDeviceConfig(Wifi::WifiDeviceConfig &config, MessageParcel &data)
{
    data.WriteInt32(config.networkId);
    data.WriteInt32(config.status);
    data.WriteString(config.bssid);
    data.WriteString(config.ssid);
    data.WriteInt32(config.band);
    data.WriteInt32(config.channel);
    data.WriteInt32(config.frequency);
    data.WriteInt32(config.level);
    data.WriteBool(config.isPasspoint);
    data.WriteBool(config.isEphemeral);
    data.WriteString(config.preSharedKey);
    data.WriteString(config.keyMgmt);
    for (int i = 0; i < WEPKEYS_SIZE; i++) {
        data.WriteString(config.wepKeys[i]);
    }
    data.WriteInt32(config.wepTxKeyIndex);
    data.WriteInt32(config.priority);
    data.WriteBool(config.hiddenSSID);
    data.WriteInt32(static_cast<int32_t>(config.wifiIpConfig.assignMethod));
    WriteIpAddress(data, config.wifiIpConfig.staticIpAddress.ipAddress.address);
    data.WriteInt32(config.wifiIpConfig.staticIpAddress.ipAddress.prefixLength);
    data.WriteInt32(config.wifiIpConfig.staticIpAddress.ipAddress.flags);
    data.WriteInt32(config.wifiIpConfig.staticIpAddress.ipAddress.scope);
    WriteIpAddress(data, config.wifiIpConfig.staticIpAddress.gateway);
    WriteIpAddress(data, config.wifiIpConfig.staticIpAddress.dnsServer1);
    WriteIpAddress(data, config.wifiIpConfig.staticIpAddress.dnsServer2);
    data.WriteString(config.wifiIpConfig.staticIpAddress.domains);
    data.WriteString(config.wifiEapConfig.eap);
    data.WriteString(config.wifiEapConfig.identity);
    data.WriteString(config.wifiEapConfig.password);
    data.WriteString(config.wifiEapConfig.clientCert);
    data.WriteString(config.wifiEapConfig.privateKey);
    data.WriteUInt8Vector(config.wifiEapConfig.certEntry);
    data.WriteCString(config.wifiEapConfig.certPassword);
    memset_s(config.wifiEapConfig.certPassword, sizeof(config.wifiEapConfig.certPassword), 0,
        sizeof(config.wifiEapConfig.certPassword));
    data.WriteInt32(static_cast<int32_t>(config.wifiEapConfig.phase2Method));
    data.WriteInt32(static_cast<int32_t>(config.wifiProxyconfig.configureMethod));
    data.WriteString(config.wifiProxyconfig.autoProxyConfig.pacWebAddress);
    data.WriteString(config.wifiProxyconfig.manualProxyConfig.serverHostName);
    data.WriteInt32(config.wifiProxyconfig.manualProxyConfig.serverPort);
    data.WriteString(config.wifiProxyconfig.manualProxyConfig.exclusionObjectList);
    data.WriteInt32(static_cast<int32_t>(config.wifiPrivacySetting));
}

void MessageParcelUtils::WriteIpAddress(MessageParcel &data, const Wifi::WifiIpAddress &address)
{
    data.WriteInt32(address.family);
    data.WriteUint32(address.addressIpv4);
    size_t size = address.addressIpv6.size();
    data.WriteUint32(size);
    for (size_t i = 0; i < size; i++) {
        data.WriteUint8(address.addressIpv6[i]);
    }
}

void MessageParcelUtils::ReadWifiDeviceConfig(MessageParcel &data, Wifi::WifiDeviceConfig &config)
{
    config.networkId = data.ReadInt32();
    config.status = data.ReadInt32();
    config.bssid = data.ReadString();
    config.ssid = data.ReadString();
    config.band = data.ReadInt32();
    config.channel = data.ReadInt32();
    config.frequency = data.ReadInt32();
    config.level = data.ReadInt32();
    config.isPasspoint = data.ReadBool();
    config.isEphemeral = data.ReadBool();
    config.preSharedKey = data.ReadString();
    config.keyMgmt = data.ReadString();
    for (int i = 0; i < WEPKEYS_SIZE; i++) {
        config.wepKeys[i] = data.ReadString();
    }
    config.wepTxKeyIndex = data.ReadInt32();
    config.priority = data.ReadInt32();
    config.hiddenSSID = data.ReadBool();
    ProcessAssignIpMethod(data.ReadInt32(), config.wifiIpConfig);
    ReadIpAddress(data, config.wifiIpConfig.staticIpAddress.ipAddress.address);
    config.wifiIpConfig.staticIpAddress.ipAddress.prefixLength = data.ReadInt32();
    config.wifiIpConfig.staticIpAddress.ipAddress.flags = data.ReadInt32();
    config.wifiIpConfig.staticIpAddress.ipAddress.scope = data.ReadInt32();
    ReadIpAddress(data, config.wifiIpConfig.staticIpAddress.gateway);
    ReadIpAddress(data, config.wifiIpConfig.staticIpAddress.dnsServer1);
    ReadIpAddress(data, config.wifiIpConfig.staticIpAddress.dnsServer2);
    config.wifiIpConfig.staticIpAddress.domains = data.ReadString();
    config.wifiEapConfig.eap = data.ReadString();
    config.wifiEapConfig.identity = data.ReadString();
    config.wifiEapConfig.password = data.ReadString();
    config.wifiEapConfig.clientCert = data.ReadString();
    config.wifiEapConfig.privateKey = data.ReadString();
    data.ReadUInt8Vector(&config.wifiEapConfig.certEntry);
    strncpy_s(config.wifiEapConfig.certPassword, sizeof(config.wifiEapConfig.certPassword), data.ReadCString(),
        sizeof(config.wifiEapConfig.certPassword) - 1);
    ProcessPhase2Method(data.ReadInt32(), config.wifiEapConfig);
    ProcessConfigureProxyMethod(data.ReadInt32(), config.wifiProxyconfig);
    config.wifiProxyconfig.autoProxyConfig.pacWebAddress = data.ReadString();
    config.wifiProxyconfig.manualProxyConfig.serverHostName = data.ReadString();
    config.wifiProxyconfig.manualProxyConfig.serverPort = data.ReadInt32();
    config.wifiProxyconfig.manualProxyConfig.exclusionObjectList = data.ReadString();
    ProcessPrivacyConfig(data.ReadInt32(), config);
}

void MessageParcelUtils::ProcessAssignIpMethod(int32_t ipMethod, Wifi::WifiIpConfig &ipConfig)
{
    switch (ipMethod) {
        case static_cast<int32_t>(Wifi::AssignIpMethod::DHCP):
            ipConfig.assignMethod = Wifi::AssignIpMethod::DHCP;
            break;
        case static_cast<int32_t>(Wifi::AssignIpMethod::STATIC):
            ipConfig.assignMethod = Wifi::AssignIpMethod::STATIC;
            break;
        default:
            ipConfig.assignMethod = Wifi::AssignIpMethod::UNASSIGNED;
            break;
    }
}

void MessageParcelUtils::ProcessPhase2Method(int32_t phase2, Wifi::WifiEapConfig &eapConfig)
{
    switch (phase2) {
        case static_cast<int32_t>(Wifi::Phase2Method::PAP):
            eapConfig.phase2Method = Wifi::Phase2Method::PAP;
            break;
        case static_cast<int32_t>(Wifi::Phase2Method::MSCHAP):
            eapConfig.phase2Method = Wifi::Phase2Method::MSCHAP;
            break;
        case static_cast<int32_t>(Wifi::Phase2Method::MSCHAPV2):
            eapConfig.phase2Method = Wifi::Phase2Method::MSCHAPV2;
            break;
        case static_cast<int32_t>(Wifi::Phase2Method::GTC):
            eapConfig.phase2Method = Wifi::Phase2Method::GTC;
            break;
        case static_cast<int32_t>(Wifi::Phase2Method::SIM):
            eapConfig.phase2Method = Wifi::Phase2Method::SIM;
            break;
        case static_cast<int32_t>(Wifi::Phase2Method::AKA):
            eapConfig.phase2Method = Wifi::Phase2Method::AKA;
            break;
        case static_cast<int32_t>(Wifi::Phase2Method::AKA_PRIME):
            eapConfig.phase2Method = Wifi::Phase2Method::AKA_PRIME;
            break;
        default:
            eapConfig.phase2Method = Wifi::Phase2Method::NONE;
            break;
    }
}

void MessageParcelUtils::ProcessConfigureProxyMethod(int32_t proxyMethod, Wifi::WifiProxyConfig &proxyConfig)
{
    switch (proxyMethod) {
        case static_cast<int32_t>(Wifi::ConfigureProxyMethod::AUTOCONFIGUE):
            proxyConfig.configureMethod = Wifi::ConfigureProxyMethod::AUTOCONFIGUE;
            break;
        case static_cast<int32_t>(Wifi::ConfigureProxyMethod::MANUALCONFIGUE):
            proxyConfig.configureMethod = Wifi::ConfigureProxyMethod::MANUALCONFIGUE;
            break;
        default:
            proxyConfig.configureMethod = Wifi::ConfigureProxyMethod::CLOSED;
            break;
    }
}

void MessageParcelUtils::ProcessPrivacyConfig(int32_t privacyConfig, Wifi::WifiDeviceConfig &config)
{
    if (privacyConfig == static_cast<int32_t>(Wifi::WifiPrivacyConfig::RANDOMMAC)) {
        config.wifiPrivacySetting = Wifi::WifiPrivacyConfig::RANDOMMAC;
    } else {
        config.wifiPrivacySetting = Wifi::WifiPrivacyConfig::DEVICEMAC;
    }
}

void MessageParcelUtils::ReadIpAddress(MessageParcel &data, Wifi::WifiIpAddress &address)
{
    constexpr int MAX_LIMIT_SIZE = 1024;
    address.family = data.ReadInt32();
    address.addressIpv4 = data.ReadUint32();
    size_t size = data.ReadUint32();
    if (size > MAX_LIMIT_SIZE) {
        EDMLOGE("Read ip address parameter error: %{public}zu", size);
        return;
    }
    for (size_t i = 0; i < size; i++) {
        address.addressIpv6.push_back(data.ReadUint8());
    }
}
#endif

void MessageParcelUtils::WriteInstallParam(const AppExecFwk::InstallParam &installParam, MessageParcel &data)
{
    data.WriteInt32(installParam.userId);
    data.WriteInt32(static_cast<int>(installParam.installFlag));
}

void MessageParcelUtils::WriteOperateDeviceParam(const OperateDeviceParam &param, MessageParcel &data)
{
    data.WriteString(param.operate);
    data.WriteString(param.addition);
    data.WriteInt32(param.userId);
}

void MessageParcelUtils::ReadOperateDeviceParam(MessageParcel &data, OperateDeviceParam &param)
{
    param.operate = data.ReadString();
    param.addition = data.ReadString();
    param.userId = data.ReadInt32();
}
} // namespace EDM
} // namespace OHOS