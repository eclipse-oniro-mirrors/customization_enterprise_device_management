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

#include <gtest/gtest.h>

#define private public
#define protected public
#include "generic_policy_query.h"
#include "policy_query_config.h"
#undef protected
#undef private

#include "edm_ipc_interface_code.h"
#include "iplugin.h"
#include "edm_constants.h"
#include "utils.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::EDM;

namespace OHOS {
namespace EDM {
namespace TEST {

class GenericPolicyQueryTest : public testing::Test {
protected:
    void SetUp() override {}

    void TearDown() override {}

    static void SetUpTestSuite(void)
    {
        Utils::SetEdmInitialEnv();
    }

    static void TearDownTestSuite(void)
    {
        Utils::ResetTokenTypeAndUid();
        ASSERT_TRUE(Utils::IsOriginalUTEnv());
        std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
    }
};

HWTEST_F(GenericPolicyQueryTest, TestGenericPolicyQuery_GetPolicyName, TestSize.Level1)
{
    PolicyQueryConfig config;
    config.policyName = "test_bool_policy";
    config.dataType = PolicyDataType::BOOL;
    config.permissionConfig = PermissionConfig::RestrictionPermission(true);
    config.isPolicySaved = true;
    config.apiType = IPlugin::ApiType::PUBLIC;
    
    auto query = std::make_shared<GenericPolicyQuery>(config);
    ASSERT_EQ(query->GetPolicyName(), "test_bool_policy");
}

HWTEST_F(GenericPolicyQueryTest, TestGenericPolicyQuery_QueryPolicy_True, TestSize.Level1)
{
    PolicyQueryConfig config;
    config.policyName = "test_bool_policy";
    config.dataType = PolicyDataType::BOOL;
    config.permissionConfig = PermissionConfig::RestrictionPermission(true);
    config.isPolicySaved = true;
    config.apiType = IPlugin::ApiType::PUBLIC;
    
    auto query = std::make_shared<GenericPolicyQuery>(config);
    std::string policyData = "true";
    MessageParcel data;
    MessageParcel reply;
    
    ErrCode ret = query->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(reply.ReadInt32(), ERR_OK);
    ASSERT_TRUE(reply.ReadBool());
}

HWTEST_F(GenericPolicyQueryTest, TestGenericPolicyQuery_QueryPolicy_False, TestSize.Level1)
{
    PolicyQueryConfig config;
    config.policyName = "test_bool_policy";
    config.dataType = PolicyDataType::BOOL;
    config.permissionConfig = PermissionConfig::RestrictionPermission(true);
    config.isPolicySaved = true;
    config.apiType = IPlugin::ApiType::PUBLIC;
    
    auto query = std::make_shared<GenericPolicyQuery>(config);
    std::string policyData = "false";
    MessageParcel data;
    MessageParcel reply;
    
    ErrCode ret = query->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(reply.ReadInt32(), ERR_OK);
    ASSERT_FALSE(reply.ReadBool());
}

HWTEST_F(GenericPolicyQueryTest, TestGenericPolicyQuery_IsPolicySaved, TestSize.Level1)
{
    PolicyQueryConfig config;
    config.policyName = "test_bool_policy";
    config.dataType = PolicyDataType::BOOL;
    config.permissionConfig = PermissionConfig::RestrictionPermission(true);
    config.isPolicySaved = true;
    config.apiType = IPlugin::ApiType::PUBLIC;
    
    auto query = std::make_shared<GenericPolicyQuery>(config);
    ASSERT_TRUE(query->IsPolicySaved());
}

HWTEST_F(GenericPolicyQueryTest, TestGenericPolicyQuery_GetApiType, TestSize.Level1)
{
    PolicyQueryConfig config;
    config.policyName = "test_bool_policy";
    config.dataType = PolicyDataType::BOOL;
    config.permissionConfig = PermissionConfig::RestrictionPermission(true);
    config.isPolicySaved = true;
    config.apiType = IPlugin::ApiType::PUBLIC;
    
    auto query = std::make_shared<GenericPolicyQuery>(config);
    ASSERT_EQ(query->GetApiType(), IPlugin::ApiType::PUBLIC);
}

HWTEST_F(GenericPolicyQueryTest, TestGenericPolicyQuery_ArrayStringQueryPolicy, TestSize.Level1)
{
    PolicyQueryConfig config;
    config.policyName = "test_array_policy";
    config.dataType = PolicyDataType::ARRAY_STRING;
    config.permissionConfig = PermissionConfig::SpecificPermission("test.permission");
    config.isPolicySaved = true;
    config.apiType = IPlugin::ApiType::PUBLIC;
    
    auto query = std::make_shared<GenericPolicyQuery>(config);
    std::string policyData = "[\"bundle1\", \"bundle2\"]";
    MessageParcel data;
    MessageParcel reply;
    
    ErrCode ret = query->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(reply.ReadInt32(), ERR_OK);
}

HWTEST_F(GenericPolicyQueryTest, TestGenericPolicyQuery_StringQueryPolicy, TestSize.Level1)
{
    PolicyQueryConfig config;
    config.policyName = "test_string_policy";
    config.dataType = PolicyDataType::STRING;
    config.permissionConfig = PermissionConfig::SpecificPermission("test.permission");
    config.isPolicySaved = true;
    config.apiType = IPlugin::ApiType::PUBLIC;
    
    auto query = std::make_shared<GenericPolicyQuery>(config);
    std::string policyData = "ntp.server.example.com";
    MessageParcel data;
    MessageParcel reply;
    
    ErrCode ret = query->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(reply.ReadInt32(), ERR_OK);
    ASSERT_EQ(reply.ReadString(), "ntp.server.example.com");
}

HWTEST_F(GenericPolicyQueryTest, TestGenericPolicyQuery_IntQueryPolicy, TestSize.Level1)
{
    PolicyQueryConfig config;
    config.policyName = "test_int_policy";
    config.dataType = PolicyDataType::INT;
    config.permissionConfig = PermissionConfig::SpecificPermission("test.permission");
    config.isPolicySaved = true;
    config.apiType = IPlugin::ApiType::PUBLIC;
    
    auto query = std::make_shared<GenericPolicyQuery>(config);
    std::string policyData = "42";
    MessageParcel data;
    MessageParcel reply;
    
    ErrCode ret = query->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(reply.ReadInt32(), ERR_OK);
    ASSERT_EQ(reply.ReadInt32(), 42);
}

HWTEST_F(GenericPolicyQueryTest, TestGenericPolicyQuery_GetPermission, TestSize.Level1)
{
    PolicyQueryConfig config;
    config.policyName = "test_bool_policy";
    config.dataType = PolicyDataType::BOOL;
    config.permissionConfig = PermissionConfig::RestrictionPermission(true);
    config.isPolicySaved = true;
    config.apiType = IPlugin::ApiType::PUBLIC;
    
    auto query = std::make_shared<GenericPolicyQuery>(config);
    std::string permission = query->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "");
    ASSERT_EQ(permission, "ohos.permission.ENTERPRISE_MANAGE_RESTRICTIONS");
    
    permission = query->GetPermission(IPlugin::PermissionType::BYOD_DEVICE_ADMIN, "");
    ASSERT_EQ(permission, "ohos.permission.PERSONAL_MANAGE_RESTRICTIONS");
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS