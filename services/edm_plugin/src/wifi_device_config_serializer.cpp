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

#include "wifi_device_config_serializer.h"
#include "message_parcel_utils.h"
#include "securec.h"

namespace OHOS {
namespace EDM {
bool WifiDeviceConfigSerializer::Deserialize(const std::string &jsonString, Wifi::WifiDeviceConfig &config)
{
    Json::Value wifiDeviceConfigJson;
    ConvertStrToJson(jsonString, wifiDeviceConfigJson);
    config.networkId = wifiDeviceConfigJson["networkId"].asInt();
    config.status = wifiDeviceConfigJson["status"].asInt();
    config.bssid = wifiDeviceConfigJson["bssid"].asString();
    config.ssid = wifiDeviceConfigJson["ssid"].asString();
    config.band = wifiDeviceConfigJson["band"].asInt();
    config.channel = wifiDeviceConfigJson["channel"].asInt();
    config.frequency = wifiDeviceConfigJson["frequency"].asInt();
    config.level = wifiDeviceConfigJson["level"].asInt();
    config.isPasspoint = wifiDeviceConfigJson["isPasspoint"].asBool();
    config.isEphemeral = wifiDeviceConfigJson["isEphemeral"].asBool();
    config.preSharedKey = wifiDeviceConfigJson["preSharedKey"].asString();
    config.keyMgmt = wifiDeviceConfigJson["keyMgmt"].asString();
    for (int i = 0; i < WEPKEYS_SIZE; i++) {
        config.wepKeys[i] = wifiDeviceConfigJson["wepKeys"][i].asString();
    }
    config.wepTxKeyIndex = wifiDeviceConfigJson["wepTxKeyIndex"].asInt();
    config.priority = wifiDeviceConfigJson["priority"].asInt();
    config.hiddenSSID = wifiDeviceConfigJson["hiddenSSID"].asBool();
    MessageParcelUtils::ProcessAssignIpMethod(wifiDeviceConfigJson["assignMethod"].asInt(), config.wifiIpConfig);
    config.wifiIpConfig.staticIpAddress.ipAddress.address = DeserializeIpAddress(wifiDeviceConfigJson["address"]);
    config.wifiIpConfig.staticIpAddress.ipAddress.prefixLength = wifiDeviceConfigJson["prefixLength"].asInt();
    config.wifiIpConfig.staticIpAddress.ipAddress.flags = wifiDeviceConfigJson["flags"].asInt();
    config.wifiIpConfig.staticIpAddress.ipAddress.scope = wifiDeviceConfigJson["scope"].asInt();
    config.wifiIpConfig.staticIpAddress.gateway = DeserializeIpAddress(wifiDeviceConfigJson["gateway"]);
    config.wifiIpConfig.staticIpAddress.dnsServer1  = DeserializeIpAddress(wifiDeviceConfigJson["dnsServer1"]);
    config.wifiIpConfig.staticIpAddress.dnsServer2  = DeserializeIpAddress(wifiDeviceConfigJson["dnsServer2"]);
    config.wifiIpConfig.staticIpAddress.domains = wifiDeviceConfigJson["domains"].asString();
    config.wifiEapConfig.eap = wifiDeviceConfigJson["eap"].asString();
    config.wifiEapConfig.identity = wifiDeviceConfigJson["identity"].asString();
    config.wifiEapConfig.password = wifiDeviceConfigJson["password"].asString();
    config.wifiEapConfig.clientCert = wifiDeviceConfigJson["clientCert"].asString();
    config.wifiEapConfig.privateKey = wifiDeviceConfigJson["privateKey"].asString();
    std::string certStr = wifiDeviceConfigJson["certEntry"].asString();
    config.wifiEapConfig.certEntry.assign(certStr.begin(), certStr.end());
    std::string certPassword = wifiDeviceConfigJson["certPassword"].asString();
    if (strncpy_s(config.wifiEapConfig.certPassword, sizeof(config.wifiEapConfig.certPassword), certPassword.c_str(),
        sizeof(config.wifiEapConfig.certPassword) - 1) != EOK) {
        EDMLOGE("ReadWifiDeviceConfig strncpy_s failed!");
    }
    MessageParcelUtils::ProcessPhase2Method(wifiDeviceConfigJson["phase2Method"].asInt(), config.wifiEapConfig);
    MessageParcelUtils::ProcessConfigureProxyMethod(wifiDeviceConfigJson["configureMethod"].asInt(),
        config.wifiProxyconfig);
    config.wifiProxyconfig.autoProxyConfig.pacWebAddress = wifiDeviceConfigJson["pacWebAddress"].asString();
    config.wifiProxyconfig.manualProxyConfig.serverHostName = wifiDeviceConfigJson["serverHostName"].asString();
    config.wifiProxyconfig.manualProxyConfig.serverPort = wifiDeviceConfigJson["serverPort"].asInt();
    config.wifiProxyconfig.manualProxyConfig.exclusionObjectList =
        wifiDeviceConfigJson["exclusionObjectList"].asString();
    MessageParcelUtils::ProcessPrivacyConfig(wifiDeviceConfigJson["wifiPrivacySetting"].asInt(), config);
    return true;
}

void WifiDeviceConfigSerializer::ConvertStrToJson(const std::string &str, Json::Value &json)
{
    Json::String err;
    Json::CharReaderBuilder builder;
    std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    reader->parse(str.c_str(), str.c_str() + str.length(), &json, &err);
}

Wifi::WifiIpAddress WifiDeviceConfigSerializer::DeserializeIpAddress(const Json::Value &ipAddressJson)
{
    Wifi::WifiIpAddress address;
    address.family = ipAddressJson["family"].asInt();
    address.addressIpv4 = ipAddressJson["addressIpv4"].asUInt();
    std::string ipv6Str = ipAddressJson["addressIpv6"].asString();
    address.addressIpv6.assign(ipv6Str.begin(), ipv6Str.end());
    return address;
}

bool WifiDeviceConfigSerializer::Serialize(const Wifi::WifiDeviceConfig &config, std::string &jsonString)
{
    Json::StreamWriterBuilder builder;
    builder.settings_["indentation"] = "";
    Json::Value configJson;
    configJson["networkId"] = config.networkId;
    configJson["status"] = config.status;
    configJson["bssid"] = config.bssid;
    configJson["ssid"] = config.ssid;
    configJson["band"] = config.band;
    configJson["channel"] = config.channel;
    configJson["frequency"] = config.frequency;
    configJson["level"] = config.level;
    configJson["isPasspoint"] = config.isPasspoint;
    configJson["isEphemeral"] = config.isEphemeral;
    configJson["preSharedKey"] = config.preSharedKey;
    configJson["keyMgmt"] = config.keyMgmt;
    Json::Value wepKeysJson;
    for (int i = 0; i < WEPKEYS_SIZE; i++) {
        wepKeysJson.append(config.wepKeys[i]);
    }
    configJson["wepKeys"] = wepKeysJson;
    configJson["wepTxKeyIndex"] = config.wepTxKeyIndex;
    configJson["priority"] = config.priority;
    configJson["hiddenSSID"] = config.hiddenSSID;
    configJson["assignMethod"] = static_cast<int32_t>(config.wifiIpConfig.assignMethod);
    configJson["address"] = SerializerIpAddress(config.wifiIpConfig.staticIpAddress.ipAddress.address);
    configJson["prefixLength"] = config.wifiIpConfig.staticIpAddress.ipAddress.prefixLength;
    configJson["flags"] = config.wifiIpConfig.staticIpAddress.ipAddress.flags;
    configJson["scope"] = config.wifiIpConfig.staticIpAddress.ipAddress.scope;
    configJson["gateway"] = SerializerIpAddress(config.wifiIpConfig.staticIpAddress.gateway);
    configJson["dnsServer1"] = SerializerIpAddress(config.wifiIpConfig.staticIpAddress.dnsServer1);
    configJson["dnsServer2"] = SerializerIpAddress(config.wifiIpConfig.staticIpAddress.dnsServer2);
    configJson["domains"] = config.wifiIpConfig.staticIpAddress.domains;
    configJson["eap"] = config.wifiEapConfig.eap;
    configJson["identity"] = config.wifiEapConfig.identity;
    configJson["password"] = config.wifiEapConfig.password;
    configJson["clientCert"] = config.wifiEapConfig.clientCert;
    configJson["privateKey"] = config.wifiEapConfig.privateKey;
    std::string certEntryStr(config.wifiEapConfig.certEntry.begin(), config.wifiEapConfig.certEntry.end());
    configJson["certEntry"] = certEntryStr;
    configJson["certPassword"] = std::string(config.wifiEapConfig.certPassword);
    configJson["phase2Method"] = static_cast<int32_t>(config.wifiEapConfig.phase2Method);
    configJson["configureMethod"] = static_cast<int32_t>(config.wifiProxyconfig.configureMethod);
    configJson["pacWebAddress"] = config.wifiProxyconfig.autoProxyConfig.pacWebAddress;
    configJson["serverHostName"] = config.wifiProxyconfig.manualProxyConfig.serverHostName;
    configJson["serverPort"] = config.wifiProxyconfig.manualProxyConfig.serverPort;
    configJson["exclusionObjectList"] = config.wifiProxyconfig.manualProxyConfig.exclusionObjectList;
    configJson["wifiPrivacySetting"] = static_cast<int32_t>(config.wifiPrivacySetting);
    jsonString = Json::writeString(builder, configJson);
    return true;
}

Json::Value WifiDeviceConfigSerializer::SerializerIpAddress(const Wifi::WifiIpAddress &address)
{
    Json::Value ipAddressJson;
    ipAddressJson["family"] = address.family;
    ipAddressJson["addressIpv4"] = address.addressIpv4;
    Json::Value addressIpv6Json;
    std::string ipv6Str(address.addressIpv6.begin(), address.addressIpv6.end());
    ipAddressJson["addressIpv6"] = ipv6Str;
    return ipAddressJson;
}

bool WifiDeviceConfigSerializer::GetPolicy(MessageParcel &data, Wifi::WifiDeviceConfig &result)
{
    MessageParcelUtils::ReadWifiDeviceConfig(data, result);
    return true;
}

bool WifiDeviceConfigSerializer::WritePolicy(MessageParcel &reply, Wifi::WifiDeviceConfig &result)
{
    MessageParcelUtils::WriteWifiDeviceConfig(result, reply);
    return true;
}

bool WifiDeviceConfigSerializer::MergePolicy(std::vector<Wifi::WifiDeviceConfig> &data, Wifi::WifiDeviceConfig &result)
{
    if (!data.empty()) {
        result = *(data.rbegin());
    }
    return true;
}
} // namespace EDM
} // namespace OHOS