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

#include "network_manager_proxy.h"

#include <gtest/gtest.h>
#include <system_ability_definition.h>

#include <string>
#include <vector>

#include "edm_sys_manager_mock.h"
#include "enterprise_device_mgr_stub_mock.h"
#include "iptables_utils.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string ADMIN_PACKAGENAME = "com.edm.test.demo";
class NetworkManagerProxyTest : public testing::Test {
protected:
    void SetUp() override;

    void TearDown() override;

    static void TearDownTestSuite(void);
    std::shared_ptr<NetworkManagerProxy> networkManagerProxy = nullptr;
    std::shared_ptr<EdmSysManager> edmSysManager_ = nullptr;
    sptr<EnterpriseDeviceMgrStubMock> object_ = nullptr;
};

void NetworkManagerProxyTest::SetUp()
{
    networkManagerProxy = NetworkManagerProxy::GetNetworkManagerProxy();
    edmSysManager_ = std::make_shared<EdmSysManager>();
    object_ = new (std::nothrow) EnterpriseDeviceMgrStubMock();
    edmSysManager_->RegisterSystemAbilityOfRemoteObject(ENTERPRISE_DEVICE_MANAGER_SA_ID, object_);
    Utils::SetEdmServiceEnable();
}

void NetworkManagerProxyTest::TearDown()
{
    networkManagerProxy.reset();
    edmSysManager_->UnregisterSystemAbilityOfRemoteObject(ENTERPRISE_DEVICE_MANAGER_SA_ID);
    object_ = nullptr;
    Utils::SetEdmServiceDisable();
}

void NetworkManagerProxyTest::TearDownTestSuite()
{
    ASSERT_FALSE(Utils::GetEdmServiceState());
    std::cout << "EdmServiceState : " << Utils::GetEdmServiceState() << std::endl;
}

/**
 * @tc.name: TestGetAllNetworkInterfacesSuc
 * @tc.desc: Test GetAllNetworkInterfaces func.
 * @tc.type: FUNC
 */
HWTEST_F(NetworkManagerProxyTest, TestGetAllNetworkInterfacesSuc, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeArrayStringSendRequestGetPolicy));
    std::vector<std::string> networkInterfaces;
    int32_t ret = networkManagerProxy->GetAllNetworkInterfaces(admin, networkInterfaces);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(networkInterfaces.size() == 1);
    ASSERT_TRUE(networkInterfaces[0] == RETURN_STRING);
}

/**
 * @tc.name: TestGetAllNetworkInterfacesFail
 * @tc.desc: Test GetAllNetworkInterfaces func.
 * @tc.type: FUNC
 */
HWTEST_F(NetworkManagerProxyTest, TestGetAllNetworkInterfacesFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    std::vector<std::string> networkInterfaces;
    int32_t ret = networkManagerProxy->GetAllNetworkInterfaces(admin, networkInterfaces);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetIpOrMacAddressSuc
 * @tc.desc: Test GetIpOrMacAddress func.
 * @tc.type: FUNC
 */
HWTEST_F(NetworkManagerProxyTest, TestGetIpOrMacAddressSuc, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestGetPolicy));
    std::string info;
    int32_t ret = networkManagerProxy->GetIpOrMacAddress(admin, "eth0", EdmInterfaceCode::GET_MAC, info);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(info == RETURN_STRING);
}

/**
 * @tc.name: TestGetIpOrMacAddressFail
 * @tc.desc: Test GetIpOrMacAddress func.
 * @tc.type: FUNC
 */
HWTEST_F(NetworkManagerProxyTest, TestGetIpOrMacAddressFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    std::string info;
    int32_t ret = networkManagerProxy->GetIpOrMacAddress(admin, "eth0", EdmInterfaceCode::GET_MAC, info);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestIsNetworkInterfaceDisabledSuc
 * @tc.desc: Test IsNetworkInterfaceDisabled func.
 * @tc.type: FUNC
 */
HWTEST_F(NetworkManagerProxyTest, TestIsNetworkInterfaceDisabledSuc, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeBoolSendRequestGetPolicy));
    bool status = false;
    int32_t ret = networkManagerProxy->IsNetworkInterfaceDisabled(admin, "eth0", status);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(status);
}

/**
 * @tc.name: TestIsNetworkInterfaceDisabledFail
 * @tc.desc: Test IsNetworkInterfaceDisabled func.
 * @tc.type: FUNC
 */
HWTEST_F(NetworkManagerProxyTest, TestIsNetworkInterfaceDisabledFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    bool status = false;
    int32_t ret = networkManagerProxy->IsNetworkInterfaceDisabled(admin, "eth0", status);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
    ASSERT_FALSE(status);
}

/**
 * @tc.name: TestSetNetworkInterfaceDisabledSuc
 * @tc.desc: Test SetNetworkInterfaceDisabled func.
 * @tc.type: FUNC
 */
HWTEST_F(NetworkManagerProxyTest, TestSetNetworkInterfaceDisabledSuc, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    int32_t ret = networkManagerProxy->SetNetworkInterfaceDisabled(admin, "eth0", true);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestSetNetworkInterfaceDisabledFail
 * @tc.desc: Test SetNetworkInterfaceDisabled func.
 * @tc.type: FUNC
 */
HWTEST_F(NetworkManagerProxyTest, TestSetNetworkInterfaceDisabledFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    int32_t ret = networkManagerProxy->SetNetworkInterfaceDisabled(admin, "eth0", true);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestAddIptablesFilterRuleSuc
 * @tc.desc: Test AddIptablesFilterRule func.
 * @tc.type: FUNC
 */
HWTEST_F(NetworkManagerProxyTest, TestAddIptablesFilterRuleSuc, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    IPTABLES::AddFilter addFilter;
    int32_t ret = networkManagerProxy->AddIptablesFilterRule(admin, addFilter);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestAddIptablesFilterRuleFail
 * @tc.desc: Test AddIptablesFilterRule func.
 * @tc.type: FUNC
 */
HWTEST_F(NetworkManagerProxyTest, TestAddIptablesFilterRuleFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    IPTABLES::AddFilter addFilter;
    int32_t ret = networkManagerProxy->AddIptablesFilterRule(admin, addFilter);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestRemoveIptablesFilterRuleSuc
 * @tc.desc: Test RemoveIptablesFilterRule func.
 * @tc.type: FUNC
 */
HWTEST_F(NetworkManagerProxyTest, TestRemoveIptablesFilterRuleSuc, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    IPTABLES::RemoveFilter removeFilter;
    int32_t ret = networkManagerProxy->RemoveIptablesFilterRule(admin, removeFilter);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestRemoveIptablesFilterRuleFail
 * @tc.desc: Test RemoveIptablesFilterRule func.
 * @tc.type: FUNC
 */
HWTEST_F(NetworkManagerProxyTest, TestRemoveIptablesFilterRuleFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    IPTABLES::RemoveFilter removeFilter;
    int32_t ret = networkManagerProxy->RemoveIptablesFilterRule(admin, removeFilter);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestListIptablesFilterRulesSuc
 * @tc.desc: Test ListIptablesFilterRules func.
 * @tc.type: FUNC
 */
HWTEST_F(NetworkManagerProxyTest, TestListIptablesFilterRulesSuc, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestGetPolicy));
    std::string result;
    int32_t ret = networkManagerProxy->ListIptablesFilterRules(admin, result);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestListIptablesFilterRulesFail
 * @tc.desc: Test ListIptablesFilterRules func.
 * @tc.type: FUNC
 */
HWTEST_F(NetworkManagerProxyTest, TestListIptablesFilterRulesFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    std::string result;
    int32_t ret = networkManagerProxy->ListIptablesFilterRules(admin, result);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestSetGlobalHttpProxySuc
 * @tc.desc: Test SetGlobalHttpProxy func.
 * @tc.type: FUNC
 */
HWTEST_F(NetworkManagerProxyTest, TestSetGlobalHttpProxySuc, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    OHOS::NetManagerStandard::HttpProxy httpProxy;
    httpProxy.SetHost("baidu.com");
    httpProxy.SetPort(1234);
    std::list<std::string> list = {"192.168.1.100"};
    httpProxy.SetExclusionList(list);
    int32_t ret = networkManagerProxy->SetGlobalHttpProxy(admin, httpProxy);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestSetGlobalHttpProxyFail
 * @tc.desc: Test SetGlobalHttpProxy func.
 * @tc.type: FUNC
 */
HWTEST_F(NetworkManagerProxyTest, TestSetGlobalHttpProxyFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    OHOS::NetManagerStandard::HttpProxy httpProxy;
    httpProxy.SetHost("baidu.com");
    httpProxy.SetPort(1234);
    std::list<std::string> list = {"192.168.1.100"};
    httpProxy.SetExclusionList(list);
    int32_t ret = networkManagerProxy->SetGlobalHttpProxy(admin, httpProxy);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetGlobalHttpProxySuc
 * @tc.desc: Test GetGlobalHttpProxy func.
 * @tc.type: FUNC
 */
HWTEST_F(NetworkManagerProxyTest, TestGetGlobalHttpProxySuc, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeHttpProxySendRequestGetPolicy));
    NetManagerStandard::HttpProxy httpProxy;
    int32_t ret = networkManagerProxy->GetGlobalHttpProxy(&admin, httpProxy);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestGetGlobalHttpProxyFail
 * @tc.desc: Test GetGlobalHttpProxy func.
 * @tc.type: FUNC
 */
HWTEST_F(NetworkManagerProxyTest, TestGetGlobalHttpProxyFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    NetManagerStandard::HttpProxy httpProxy;
    int32_t ret = networkManagerProxy->GetGlobalHttpProxy(&admin, httpProxy);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestAddFirewallRuleSuc
 * @tc.desc: Test AddFirewallRule func.
 * @tc.type: FUNC
 */
HWTEST_F(NetworkManagerProxyTest, TestAddFirewallRuleSuc, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    IPTABLES::FirewallRule rule{IPTABLES::Direction::INVALID, IPTABLES::Action::INVALID, IPTABLES::Protocol::INVALID,
        "", "", "", "", ""};
    int32_t ret = networkManagerProxy->AddFirewallRule(admin, rule);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestAddFirewallRuleFail
 * @tc.desc: Test AddFirewallRule func.
 * @tc.type: FUNC
 */
HWTEST_F(NetworkManagerProxyTest, TestAddFirewallRuleFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    IPTABLES::FirewallRule rule{IPTABLES::Direction::INVALID, IPTABLES::Action::INVALID, IPTABLES::Protocol::INVALID,
        "", "", "", "", ""};
    int32_t ret = networkManagerProxy->AddFirewallRule(admin, rule);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestRemoveFirewallRuleSuc
 * @tc.desc: Test RemoveFirewallRule func.
 * @tc.type: FUNC
 */
HWTEST_F(NetworkManagerProxyTest, TestRemoveFirewallRuleSuc, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    IPTABLES::FirewallRule rule{IPTABLES::Direction::INVALID, IPTABLES::Action::INVALID, IPTABLES::Protocol::INVALID,
        "", "", "", "", ""};
    int32_t ret = networkManagerProxy->RemoveFirewallRule(admin, rule);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestRemoveFirewallRuleFail
 * @tc.desc: Test RemoveFirewallRule func.
 * @tc.type: FUNC
 */
HWTEST_F(NetworkManagerProxyTest, TestRemoveFirewallRuleFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    IPTABLES::FirewallRule rule{IPTABLES::Direction::INVALID, IPTABLES::Action::INVALID, IPTABLES::Protocol::INVALID,
        "", "", "", "", ""};
    int32_t ret = networkManagerProxy->RemoveFirewallRule(admin, rule);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetFirewallRulesSuc
 * @tc.desc: Test GetFirewallRules func.
 * @tc.type: FUNC
 */
HWTEST_F(NetworkManagerProxyTest, TestGetFirewallRulesSuc, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);

    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeBoolSendRequestGetFirewallRule));
    std::vector<IPTABLES::FirewallRule> result;
    int32_t ret = networkManagerProxy->GetFirewallRules(admin, result);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(result.size() == 1);
}

/**
 * @tc.name: TestGetFirewallRulesFail
 * @tc.desc: Test GetFirewallRules func.
 * @tc.type: FUNC
 */
HWTEST_F(NetworkManagerProxyTest, TestGetFirewallRulesFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    std::vector<IPTABLES::FirewallRule> result;
    int32_t ret = networkManagerProxy->GetFirewallRules(admin, result);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestAddAddDomainFilterRuleSuc
 * @tc.desc: Test AddDomainFilterRule func.
 * @tc.type: FUNC
 */
HWTEST_F(NetworkManagerProxyTest, TestAddAddDomainFilterRuleSuc, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    IPTABLES::DomainFilterRule rule{IPTABLES::Action::INVALID, "321", "www.example.com"};
    int32_t ret = networkManagerProxy->AddDomainFilterRule(admin, rule);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestAddDomainFilterRuleFail
 * @tc.desc: Test AddDomainFilterRule func.
 * @tc.type: FUNC
 */
HWTEST_F(NetworkManagerProxyTest, TestAddDomainFilterRuleFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    IPTABLES::DomainFilterRule rule{IPTABLES::Action::INVALID, "321", "www.example.com"};
    int32_t ret = networkManagerProxy->AddDomainFilterRule(admin, rule);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestRemoveDomainFilterRuleSuc
 * @tc.desc: Test RemoveDomainFilterRule func.
 * @tc.type: FUNC
 */
HWTEST_F(NetworkManagerProxyTest, TestRemoveDomainFilterRuleSuc, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    IPTABLES::DomainFilterRule rule{IPTABLES::Action::INVALID, "321", "www.example.com"};
    int32_t ret = networkManagerProxy->RemoveDomainFilterRule(admin, rule);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestRemoveDomainFilterRuleFail
 * @tc.desc: Test RemoveDomainFilterRule func.
 * @tc.type: FUNC
 */
HWTEST_F(NetworkManagerProxyTest, TestRemoveDomainFilterRuleFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    IPTABLES::DomainFilterRule rule{IPTABLES::Action::INVALID, "321", "www.example.com"};
    int32_t ret = networkManagerProxy->RemoveDomainFilterRule(admin, rule);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetDomainFilterRulesSuc
 * @tc.desc: Test GetDomainFilterRules func.
 * @tc.type: FUNC
 */
HWTEST_F(NetworkManagerProxyTest, TestGetDomainFilterRulesSuc, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);

    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestGetDomainFilterRules));
    std::vector<IPTABLES::DomainFilterRule> result;
    int32_t ret = networkManagerProxy->GetDomainFilterRules(admin, result);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(result.size() == 1);
}

/**
 * @tc.name: TestGetDomainFilterRulesFail
 * @tc.desc: Test GetDomainFilterRules func.
 * @tc.type: FUNC
 */
HWTEST_F(NetworkManagerProxyTest, TestGetDomainFilterRulesFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    std::vector<IPTABLES::DomainFilterRule> result;
    int32_t ret = networkManagerProxy->GetDomainFilterRules(admin, result);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
