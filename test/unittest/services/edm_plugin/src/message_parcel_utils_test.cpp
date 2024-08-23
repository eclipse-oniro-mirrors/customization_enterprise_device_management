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
 
#include <gtest/gtest.h>

#include "edm_utils.h"
#include "bundle_constants.h"
#include "message_parcel_utils.h"
#ifdef WIFI_EDM_ENABLE
#include "wifi_msg.h"
#endif
using namespace testing::ext;
using namespace OHOS::EDM;

namespace OHOS {
namespace EDM {
namespace TEST {

class MessageParcelUtilsTest : public testing::Test {};
#ifdef WIFI_EDM_ENABLE
/**
 * @tc.name: TestReadWifiDeviceConfig
 * @tc.desc: Test MessageParcelUtils::ReadWifiDeviceConfig
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelUtilsTest, TestReadWifiDeviceConfig, TestSize.Level1)
{
    MessageParcel data;
    Wifi::WifiDeviceConfig config;
    WifiPassword pwd;
    config.networkId = -1;
    config.status = 0;
    config.bssid = "";
    config.ssid = "";
    config.band = 0;
    config.channel = 0;
    config.frequency = 0;
    config.level = 0;
    config.isPasspoint = true;
    config.isEphemeral = true;
    config.keyMgmt = "";
    config.wepTxKeyIndex = 0;
    config.priority = 0;
    config.hiddenSSID = true;
    config.wifiIpConfig.assignMethod = Wifi::AssignIpMethod::DHCP;
    config.wifiIpConfig.staticIpAddress.ipAddress.address.family = -1;
    config.wifiIpConfig.staticIpAddress.ipAddress.address.addressIpv4 = 0;
    config.wifiIpConfig.staticIpAddress.ipAddress.prefixLength = 0;
    config.wifiIpConfig.staticIpAddress.ipAddress.flags = 0;
    config.wifiIpConfig.staticIpAddress.ipAddress.scope = 0;
    config.wifiIpConfig.staticIpAddress.gateway.family = -1;
    config.wifiIpConfig.staticIpAddress.gateway.addressIpv4 = 0;
    config.wifiIpConfig.staticIpAddress.dnsServer1.family = -1;
    config.wifiIpConfig.staticIpAddress.dnsServer1.addressIpv4 = 0;
    config.wifiIpConfig.staticIpAddress.dnsServer2.family = -1;
    config.wifiIpConfig.staticIpAddress.dnsServer2.addressIpv4 = 0;
    config.wifiIpConfig.staticIpAddress.domains = "";
    config.wifiEapConfig.eap = "";
    config.wifiEapConfig.identity = "";
    config.wifiEapConfig.clientCert = "";
    config.wifiEapConfig.privateKey = "";
    std::vector<uint8_t> lists{1, 3, 56};
    config.wifiEapConfig.certEntry = lists;
    config.wifiEapConfig.phase2Method = Wifi::Phase2Method::NONE;
    config.wifiProxyconfig.configureMethod = Wifi::ConfigureProxyMethod::CLOSED;
    config.wifiProxyconfig.autoProxyConfig.pacWebAddress = "";
    config.wifiProxyconfig.manualProxyConfig.serverPort = 1;
    config.wifiProxyconfig.manualProxyConfig.exclusionObjectList = "";
    config.wifiPrivacySetting = Wifi::WifiPrivacyConfig::RANDOMMAC;
    MessageParcelUtils::WriteWifiDeviceConfig(config, data, pwd);
    
    Wifi::WifiDeviceConfig config2;
    MessageParcelUtils::ReadWifiDeviceConfig(data, config2);
    ASSERT_TRUE(config2.networkId == -1);
    ASSERT_TRUE(config2.status == 0);
    ASSERT_TRUE(config2.bssid == "");
    ASSERT_TRUE(config2.ssid == "");
    ASSERT_TRUE(config2.band == 0);
    ASSERT_TRUE(config2.channel == 0);
    ASSERT_TRUE(config2.frequency == 0);
    ASSERT_TRUE(config2.level == 0);
    ASSERT_TRUE(config2.isPasspoint == true);
    ASSERT_TRUE(config2.isEphemeral == true);
    ASSERT_TRUE(config2.keyMgmt == "");
    ASSERT_TRUE(config2.wepTxKeyIndex == 0);
    ASSERT_TRUE(config2.priority == 0);
    ASSERT_TRUE(config2.hiddenSSID == true);
    ASSERT_TRUE(config2.wifiIpConfig.assignMethod == Wifi::AssignIpMethod::DHCP);
    ASSERT_TRUE(config2.wifiIpConfig.staticIpAddress.ipAddress.address.family == -1);
    ASSERT_TRUE(config2.wifiIpConfig.staticIpAddress.ipAddress.address.addressIpv4 == 0);
    ASSERT_TRUE(config2.wifiIpConfig.staticIpAddress.ipAddress.prefixLength == 0);
    ASSERT_TRUE(config2.wifiIpConfig.staticIpAddress.ipAddress.flags == 0);
    ASSERT_TRUE(config2.wifiIpConfig.staticIpAddress.ipAddress.scope == 0);
    ASSERT_TRUE(config2.wifiIpConfig.staticIpAddress.gateway.family == -1);
    ASSERT_TRUE(config2.wifiIpConfig.staticIpAddress.gateway.addressIpv4 == 0);
    ASSERT_TRUE(config2.wifiIpConfig.staticIpAddress.dnsServer1.family == -1);
    ASSERT_TRUE(config2.wifiIpConfig.staticIpAddress.dnsServer1.addressIpv4 == 0);
    ASSERT_TRUE(config2.wifiIpConfig.staticIpAddress.dnsServer2.family == -1);
    ASSERT_TRUE(config2.wifiIpConfig.staticIpAddress.dnsServer2.addressIpv4 == 0);
    ASSERT_TRUE(config2.wifiIpConfig.staticIpAddress.domains == "");
    ASSERT_TRUE(config2.wifiEapConfig.eap == "");
    ASSERT_TRUE(config2.wifiEapConfig.identity == "");
    ASSERT_TRUE(config2.wifiEapConfig.clientCert == "");
    ASSERT_TRUE(config2.wifiEapConfig.privateKey == "");
    ASSERT_TRUE(config2.wifiEapConfig.certEntry == lists);
    ASSERT_TRUE(config2.wifiEapConfig.phase2Method == Wifi::Phase2Method::NONE);
    ASSERT_TRUE(config2.wifiProxyconfig.configureMethod == Wifi::ConfigureProxyMethod::CLOSED);
    ASSERT_TRUE(config2.wifiProxyconfig.autoProxyConfig.pacWebAddress == "");
    ASSERT_TRUE(config2.wifiProxyconfig.manualProxyConfig.serverPort == 1);
    ASSERT_TRUE(config2.wifiProxyconfig.manualProxyConfig.exclusionObjectList == "");
    ASSERT_TRUE(config2.wifiPrivacySetting == Wifi::WifiPrivacyConfig::RANDOMMAC);
}
	
/**
 * @tc.name: TestProcessAssignIpMethod
 * @tc.desc: Test MessageParcelUtils::ProcessAssignIpMethod
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelUtilsTest, TestProcessAssignIpMethod, TestSize.Level1)
{
    Wifi::WifiIpConfig ipConfig;
    MessageParcelUtils::ProcessAssignIpMethod(static_cast<int32_t>(Wifi::AssignIpMethod::DHCP), ipConfig);
    ASSERT_TRUE(ipConfig.assignMethod == Wifi::AssignIpMethod::DHCP);
    MessageParcelUtils::ProcessAssignIpMethod(static_cast<int32_t>(Wifi::AssignIpMethod::STATIC), ipConfig);
    ASSERT_TRUE(ipConfig.assignMethod == Wifi::AssignIpMethod::STATIC);
    MessageParcelUtils::ProcessAssignIpMethod(static_cast<int32_t>(Wifi::AssignIpMethod::UNASSIGNED), ipConfig);
    ASSERT_TRUE(ipConfig.assignMethod == Wifi::AssignIpMethod::UNASSIGNED);
}

/**
 * @tc.name: TestProcessPhase2Method
 * @tc.desc: Test MessageParcelUtils::ProcessPhase2Method
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelUtilsTest, TestProcessPhase2Method, TestSize.Level1)
{
    Wifi::WifiEapConfig eapConfig;
    MessageParcelUtils::ProcessPhase2Method(static_cast<int32_t>(Wifi::Phase2Method::PAP), eapConfig);
    ASSERT_TRUE(eapConfig.phase2Method == Wifi::Phase2Method::PAP);
    MessageParcelUtils::ProcessPhase2Method(static_cast<int32_t>(Wifi::Phase2Method::MSCHAP), eapConfig);
    ASSERT_TRUE(eapConfig.phase2Method == Wifi::Phase2Method::MSCHAP);
    MessageParcelUtils::ProcessPhase2Method(static_cast<int32_t>(Wifi::Phase2Method::MSCHAPV2), eapConfig);
    ASSERT_TRUE(eapConfig.phase2Method == Wifi::Phase2Method::MSCHAPV2);
    MessageParcelUtils::ProcessPhase2Method(static_cast<int32_t>(Wifi::Phase2Method::GTC), eapConfig);
    ASSERT_TRUE(eapConfig.phase2Method == Wifi::Phase2Method::GTC);
    MessageParcelUtils::ProcessPhase2Method(static_cast<int32_t>(Wifi::Phase2Method::SIM), eapConfig);
    ASSERT_TRUE(eapConfig.phase2Method == Wifi::Phase2Method::SIM);
    MessageParcelUtils::ProcessPhase2Method(static_cast<int32_t>(Wifi::Phase2Method::AKA), eapConfig);
    ASSERT_TRUE(eapConfig.phase2Method == Wifi::Phase2Method::AKA);
    MessageParcelUtils::ProcessPhase2Method(static_cast<int32_t>(Wifi::Phase2Method::AKA_PRIME), eapConfig);
    ASSERT_TRUE(eapConfig.phase2Method == Wifi::Phase2Method::AKA_PRIME);
    MessageParcelUtils::ProcessPhase2Method(static_cast<int32_t>(Wifi::Phase2Method::NONE), eapConfig);
    ASSERT_TRUE(eapConfig.phase2Method == Wifi::Phase2Method::NONE);
}

/**
 * @tc.name: TestProcessConfigureProxyMethod
 * @tc.desc: Test MessageParcelUtils::ProcessConfigureProxyMethod
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelUtilsTest, TestProcessConfigureProxyMethod, TestSize.Level1)
{
    Wifi::WifiProxyConfig proxyConfig;
    MessageParcelUtils::ProcessConfigureProxyMethod(
        static_cast<int32_t>(Wifi::ConfigureProxyMethod::AUTOCONFIGUE), proxyConfig);
    ASSERT_TRUE(proxyConfig.configureMethod == Wifi::ConfigureProxyMethod::AUTOCONFIGUE);
    MessageParcelUtils::ProcessConfigureProxyMethod(
        static_cast<int32_t>(Wifi::ConfigureProxyMethod::MANUALCONFIGUE), proxyConfig);
    ASSERT_TRUE(proxyConfig.configureMethod == Wifi::ConfigureProxyMethod::MANUALCONFIGUE);
    MessageParcelUtils::ProcessConfigureProxyMethod(static_cast<int32_t>(Wifi::ConfigureProxyMethod::CLOSED),
        proxyConfig);
    ASSERT_TRUE(proxyConfig.configureMethod == Wifi::ConfigureProxyMethod::CLOSED);
}

/**
 * @tc.name: TestProcessPrivacyConfig
 * @tc.desc: Test MessageParcelUtils::ProcessPrivacyConfig
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelUtilsTest, TestProcessPrivacyConfig, TestSize.Level1)
{
    Wifi::WifiDeviceConfig config;
    MessageParcelUtils::ProcessPrivacyConfig(static_cast<int32_t>(Wifi::WifiPrivacyConfig::RANDOMMAC), config);
    ASSERT_TRUE(config.wifiPrivacySetting == Wifi::WifiPrivacyConfig::RANDOMMAC);
    MessageParcelUtils::ProcessPrivacyConfig(static_cast<int32_t>(Wifi::WifiPrivacyConfig::DEVICEMAC), config);
    ASSERT_TRUE(config.wifiPrivacySetting == Wifi::WifiPrivacyConfig::DEVICEMAC);
}

/**
 * @tc.name: TestReadIpAddress
 * @tc.desc: Test MessageParcelUtils::ReadIpAddress
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelUtilsTest, TestReadIpAddress, TestSize.Level1)
{
    MessageParcel data;
    Wifi::WifiIpAddress address;
    address.family = -1;
    address.addressIpv4 = 0;
    MessageParcelUtils::WriteIpAddress(data, address);
    
    Wifi::WifiIpAddress address2;
    MessageParcelUtils::ReadIpAddress(data, address2);
    ASSERT_TRUE(address2.family == -1);
    ASSERT_TRUE(address2.addressIpv4 == 0);
}

/**
 * @tc.name: TestWriteInstallParam
 * @tc.desc: Test MessageParcelUtils::WriteInstallParam
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelUtilsTest, TestWriteInstallParam, TestSize.Level1)
{
    MessageParcel data;
    AppExecFwk::InstallParam installParam;
    installParam.userId = AppExecFwk::Constants::UNSPECIFIED_USERID;
    installParam.installFlag = AppExecFwk::InstallFlag::NORMAL;
    MessageParcelUtils::WriteInstallParam(installParam, data);
    AppExecFwk::InstallParam installParam2;
    installParam2.userId = data.ReadInt32();
    installParam2.installFlag = (static_cast<AppExecFwk::InstallFlag>(data.ReadInt32()));
    ASSERT_TRUE(installParam2.userId == AppExecFwk::Constants::UNSPECIFIED_USERID);
    ASSERT_TRUE(installParam2.installFlag == AppExecFwk::InstallFlag::NORMAL);
}
#endif

/**
 * @tc.name: TestReadOperateDeviceParam
 * @tc.desc: Test MessageParcelUtils::ReadOperateDeviceParam
 * @tc.type: FUNC
 */
HWTEST_F(MessageParcelUtilsTest, TestReadOperateDeviceParam, TestSize.Level1)
{
    MessageParcel data;
    OperateDeviceParam param;
    param.operate = "";
    param.addition = "";
    param.userId = -1;
    MessageParcelUtils::WriteOperateDeviceParam(param, data);
    OperateDeviceParam param2;
    MessageParcelUtils::ReadOperateDeviceParam(data, param2);
    ASSERT_TRUE(param2.operate == "");
    ASSERT_TRUE(param2.addition == "");
    ASSERT_TRUE(param2.userId == -1);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS