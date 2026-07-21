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
#include <vector>

#define private public
#define protected public
#include "policy_query_factory.h"
#include "policy_query_config_table.h"
#include "generic_policy_query.h"
#undef protected
#undef private

#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "iplugin.h"
#include "policy_query_config.h"
#include "utils.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::EDM;

namespace OHOS {
namespace EDM {
namespace TEST {

class PolicyQueryFactoryTest : public testing::Test {
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

HWTEST_F(PolicyQueryFactoryTest, TestCreateQuery_AllEnabledEntriesNonNull, TestSize.Level1)
{
    auto entries = PolicyQueryConfigTable::GetAllEntries();
    size_t count = PolicyQueryConfigTable::GetConfigCount();
    for (size_t i = 0; i < count; i++) {
        if (!entries[i].config.isFeatureEnabled) {
            continue;
        }
        auto query = PolicyQueryFactory::CreateQuery(entries[i].code);
        ASSERT_NE(query, nullptr) << "CreateQuery returned nullptr for code " << entries[i].code;
    }
}

HWTEST_F(PolicyQueryFactoryTest, TestCreateQuery_AllPolicyNamesMatch, TestSize.Level1)
{
    auto entries = PolicyQueryConfigTable::GetAllEntries();
    size_t count = PolicyQueryConfigTable::GetConfigCount();
    for (size_t i = 0; i < count; i++) {
        if (!entries[i].config.isFeatureEnabled) {
            continue;
        }
        auto query = PolicyQueryFactory::CreateQuery(entries[i].code);
        ASSERT_NE(query, nullptr);
        ASSERT_EQ(query->GetPolicyName(), entries[i].config.policyName)
            << "policyName mismatch for code " << entries[i].code;
    }
}

HWTEST_F(PolicyQueryFactoryTest, TestCreateQuery_AllPermissionsMatch, TestSize.Level1)
{
    auto entries = PolicyQueryConfigTable::GetAllEntries();
    size_t count = PolicyQueryConfigTable::GetConfigCount();
    for (size_t i = 0; i < count; i++) {
        if (!entries[i].config.isFeatureEnabled) {
            continue;
        }
        auto query = PolicyQueryFactory::CreateQuery(entries[i].code);
        ASSERT_NE(query, nullptr);
        std::string configPerm = entries[i].config.permissionConfig.GetPermission(
            IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "");
        std::string queryPerm = query->GetPermission(
            IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "");
        ASSERT_EQ(queryPerm, configPerm)
            << "SUPER permission mismatch for code " << entries[i].code;

        std::string configByodPerm = entries[i].config.permissionConfig.GetPermission(
            IPlugin::PermissionType::BYOD_DEVICE_ADMIN, "");
        std::string queryByodPerm = query->GetPermission(
            IPlugin::PermissionType::BYOD_DEVICE_ADMIN, "");
        ASSERT_EQ(queryByodPerm, configByodPerm)
            << "BYOD permission mismatch for code " << entries[i].code;
    }
}

HWTEST_F(PolicyQueryFactoryTest, TestCreateQuery_AllIsPolicySavedMatch, TestSize.Level1)
{
    auto entries = PolicyQueryConfigTable::GetAllEntries();
    size_t count = PolicyQueryConfigTable::GetConfigCount();
    for (size_t i = 0; i < count; i++) {
        if (!entries[i].config.isFeatureEnabled) {
            continue;
        }
        auto query = PolicyQueryFactory::CreateQuery(entries[i].code);
        ASSERT_NE(query, nullptr);
        ASSERT_EQ(query->IsPolicySaved(), entries[i].config.isPolicySaved)
            << "isPolicySaved mismatch for code " << entries[i].code;
    }
}

HWTEST_F(PolicyQueryFactoryTest, TestCreateQuery_AllApiTypesMatch, TestSize.Level1)
{
    auto entries = PolicyQueryConfigTable::GetAllEntries();
    size_t count = PolicyQueryConfigTable::GetConfigCount();
    for (size_t i = 0; i < count; i++) {
        if (!entries[i].config.isFeatureEnabled) {
            continue;
        }
        auto query = PolicyQueryFactory::CreateQuery(entries[i].code);
        ASSERT_NE(query, nullptr);
        ASSERT_EQ(query->GetApiType(), entries[i].config.apiType)
            << "apiType mismatch for code " << entries[i].code;
    }
}

HWTEST_F(PolicyQueryFactoryTest, TestCheckFeatureEnabled_AllEnabledEntries, TestSize.Level1)
{
    auto entries = PolicyQueryConfigTable::GetAllEntries();
    size_t count = PolicyQueryConfigTable::GetConfigCount();
    for (size_t i = 0; i < count; i++) {
        if (entries[i].config.isFeatureEnabled) {
            ErrCode ret = PolicyQueryFactory::CheckFeatureEnabled(entries[i].code);
            ASSERT_EQ(ret, ERR_OK) << "CheckFeatureEnabled should return ERR_OK for enabled code " << entries[i].code;
        }
    }
}

HWTEST_F(PolicyQueryFactoryTest, TestCheckFeatureEnabled_DisabledEntries, TestSize.Level1)
{
    auto entries = PolicyQueryConfigTable::GetAllEntries();
    size_t count = PolicyQueryConfigTable::GetConfigCount();
    for (size_t i = 0; i < count; i++) {
        if (!entries[i].config.isFeatureEnabled) {
            ErrCode ret = PolicyQueryFactory::CheckFeatureEnabled(entries[i].code);
            ASSERT_EQ(ret, EdmReturnErrCode::INTERFACE_UNSUPPORTED)
                << "disabled code should return INTERFACE_UNSUPPORTED for code " << entries[i].code;
        }
    }
}

HWTEST_F(PolicyQueryFactoryTest, TestCheckFeatureEnabled_UnknownCode, TestSize.Level1)
{
    ErrCode ret = PolicyQueryFactory::CheckFeatureEnabled(99999);
    ASSERT_EQ(ret, ERR_CANNOT_FIND_QUERY_FAILED);
}

HWTEST_F(PolicyQueryFactoryTest, TestCreateQuery_UnknownCodeReturnsNull, TestSize.Level1)
{
    auto query = PolicyQueryFactory::CreateQuery(99999);
    ASSERT_EQ(query, nullptr);
}

HWTEST_F(PolicyQueryFactoryTest, TestCreateQuery_CacheBehavior, TestSize.Level1)
{
    auto query1 = PolicyQueryFactory::CreateQuery(EdmInterfaceCode::DISALLOWED_P2P);
    auto query2 = PolicyQueryFactory::CreateQuery(EdmInterfaceCode::DISALLOWED_P2P);
    ASSERT_NE(query1, nullptr);
    ASSERT_NE(query2, nullptr);
    ASSERT_EQ(query1, query2);
}

HWTEST_F(PolicyQueryFactoryTest, TestCreateQuery_CacheBehaviorForEnabledEntries, TestSize.Level1)
{
    auto entries = PolicyQueryConfigTable::GetAllEntries();
    size_t count = PolicyQueryConfigTable::GetConfigCount();
    for (size_t i = 0; i < count; i++) {
        if (!entries[i].config.isFeatureEnabled) {
            continue;
        }
        auto query1 = PolicyQueryFactory::CreateQuery(entries[i].code);
        auto query2 = PolicyQueryFactory::CreateQuery(entries[i].code);
        ASSERT_NE(query1, nullptr);
        ASSERT_NE(query2, nullptr);
        ASSERT_EQ(query1, query2) << "cache should return same pointer for code " << entries[i].code;
    }
}

HWTEST_F(PolicyQueryFactoryTest, TestCreateQuery_BoolPolicyQueryPolicyData, TestSize.Level1)
{
    auto query = PolicyQueryFactory::CreateQuery(EdmInterfaceCode::DISALLOWED_P2P);
    ASSERT_NE(query, nullptr);
    std::string policyData = "true";
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = query->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(reply.ReadInt32(), ERR_OK);
    ASSERT_TRUE(reply.ReadBool());
}

HWTEST_F(PolicyQueryFactoryTest, TestCreateQuery_BoolPolicyQueryPolicyDataFalse, TestSize.Level1)
{
    auto query = PolicyQueryFactory::CreateQuery(EdmInterfaceCode::DISALLOWED_P2P);
    ASSERT_NE(query, nullptr);
    std::string policyData = "false";
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = query->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(reply.ReadInt32(), ERR_OK);
    ASSERT_FALSE(reply.ReadBool());
}

HWTEST_F(PolicyQueryFactoryTest, TestCreateQuery_ArrayStringPolicyQueryPolicyData, TestSize.Level1)
{
    auto query = PolicyQueryFactory::CreateQuery(EdmInterfaceCode::ALLOWED_INSTALL_BUNDLES);
    ASSERT_NE(query, nullptr);
    std::string policyData = "[\"com.example.app1\", \"com.example.app2\"]";
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = query->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(reply.ReadInt32(), ERR_OK);
}

HWTEST_F(PolicyQueryFactoryTest, TestCreateQuery_StringPolicyQueryPolicyData, TestSize.Level1)
{
    auto query = PolicyQueryFactory::CreateQuery(EdmInterfaceCode::NTP_SERVER);
    ASSERT_NE(query, nullptr);
    std::string policyData = "ntp.server.example.com";
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = query->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(reply.ReadInt32(), ERR_OK);
    ASSERT_EQ(reply.ReadString(), "ntp.server.example.com");
}

HWTEST_F(PolicyQueryFactoryTest, TestCreateQuery_IntPolicyQueryPolicyData, TestSize.Level1)
{
    auto query = PolicyQueryFactory::CreateQuery(EdmInterfaceCode::ALLOWED_INSTALL_APP_TYPE);
    ASSERT_NE(query, nullptr);
    std::string policyData = "3";
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = query->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(reply.ReadInt32(), ERR_OK);
    ASSERT_EQ(reply.ReadInt32(), 3);
}

HWTEST_F(PolicyQueryFactoryTest, TestGetPermission_RestrictionPolicy, TestSize.Level1)
{
    auto query = PolicyQueryFactory::CreateQuery(EdmInterfaceCode::DISALLOWED_P2P);
    ASSERT_NE(query, nullptr);
    std::string permission = query->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "");
    ASSERT_EQ(permission, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    permission = query->GetPermission(IPlugin::PermissionType::BYOD_DEVICE_ADMIN, "");
    ASSERT_EQ(permission, EdmPermission::PERMISSION_PERSONAL_MANAGE_RESTRICTIONS);
}

HWTEST_F(PolicyQueryFactoryTest, TestGetPermission_RestrictionNoByodPolicy, TestSize.Level1)
{
    auto query = PolicyQueryFactory::CreateQuery(EdmInterfaceCode::DISABLED_APP_CLONE);
    ASSERT_NE(query, nullptr);
    std::string permission = query->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "");
    ASSERT_EQ(permission, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    permission = query->GetPermission(IPlugin::PermissionType::BYOD_DEVICE_ADMIN, "");
    ASSERT_EQ(permission, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
}

HWTEST_F(PolicyQueryFactoryTest, TestGetPermission_SpecificPermissionPolicy, TestSize.Level1)
{
    auto query = PolicyQueryFactory::CreateQuery(EdmInterfaceCode::ALLOWED_INSTALL_BUNDLES);
    ASSERT_NE(query, nullptr);
    std::string permission = query->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "");
    ASSERT_EQ(permission, EdmPermission::PERMISSION_ENTERPRISE_SET_BUNDLE_INSTALL_POLICY);
    permission = query->GetPermission(IPlugin::PermissionType::BYOD_DEVICE_ADMIN, "");
    ASSERT_EQ(permission, EdmPermission::PERMISSION_ENTERPRISE_SET_BUNDLE_INSTALL_POLICY);
}

HWTEST_F(PolicyQueryFactoryTest, TestGetPermission_TagPermissionPolicy, TestSize.Level1)
{
    auto query = PolicyQueryFactory::CreateQuery(EdmInterfaceCode::DISALLOW_MODIFY_DATETIME);
    ASSERT_NE(query, nullptr);
    std::string permission = query->GetPermission(
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "version_11");
    ASSERT_EQ(permission, EdmPermission::PERMISSION_ENTERPRISE_SET_DATETIME);
    permission = query->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "");
    ASSERT_EQ(permission, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
}

HWTEST_F(PolicyQueryFactoryTest, TestGetPermission_AllByodPermissions, TestSize.Level1)
{
    auto entries = PolicyQueryConfigTable::GetAllEntries();
    size_t count = PolicyQueryConfigTable::GetConfigCount();
    for (size_t i = 0; i < count; i++) {
        if (!entries[i].config.isFeatureEnabled) {
            continue;
        }
        auto query = PolicyQueryFactory::CreateQuery(entries[i].code);
        ASSERT_NE(query, nullptr);
        std::string queryByodPerm = query->GetPermission(
            IPlugin::PermissionType::BYOD_DEVICE_ADMIN, "");
        std::string configByodPerm = entries[i].config.permissionConfig.GetPermission(
            IPlugin::PermissionType::BYOD_DEVICE_ADMIN, "");
        ASSERT_EQ(queryByodPerm, configByodPerm)
            << "BYOD permission mismatch for code " << entries[i].code;
    }
}

HWTEST_F(PolicyQueryFactoryTest, TestGetPermission_AllTagPermissions, TestSize.Level1)
{
    auto entries = PolicyQueryConfigTable::GetAllEntries();
    size_t count = PolicyQueryConfigTable::GetConfigCount();
    for (size_t i = 0; i < count; i++) {
        if (!entries[i].config.isFeatureEnabled) {
            continue;
        }
        if (entries[i].config.permissionConfig.pattern != PermissionPattern::TAG) {
            continue;
        }
#ifdef USERIAM_EDM_ENABLE
        if (entries[i].code == EdmInterfaceCode::PASSWORD_POLICY) {
            continue;
        }
#endif
        auto query = PolicyQueryFactory::CreateQuery(entries[i].code);
        ASSERT_NE(query, nullptr);
        std::string queryTagPerm = query->GetPermission(
            IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "version_11");
        std::string configTagPerm = entries[i].config.permissionConfig.GetPermission(
            IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "version_11");
        ASSERT_EQ(queryTagPerm, configTagPerm)
            << "tag permission mismatch for code " << entries[i].code;
    }
}

HWTEST_F(PolicyQueryFactoryTest, TestIsPolicySaved_TrueForDeviceInfo, TestSize.Level1)
{
    auto query = PolicyQueryFactory::CreateQuery(EdmInterfaceCode::GET_DISPLAY_VERSION);
    ASSERT_NE(query, nullptr);
    ASSERT_TRUE(query->IsPolicySaved());
}

HWTEST_F(PolicyQueryFactoryTest, TestIsPolicySaved_TrueForSavedPolicies, TestSize.Level1)
{
    auto query = PolicyQueryFactory::CreateQuery(EdmInterfaceCode::DISALLOWED_P2P);
    ASSERT_NE(query, nullptr);
    ASSERT_TRUE(query->IsPolicySaved());
}

HWTEST_F(PolicyQueryFactoryTest, TestGetApiType_SystemApiForDeviceInfo, TestSize.Level1)
{
    auto query = PolicyQueryFactory::CreateQuery(EdmInterfaceCode::GET_DISPLAY_VERSION);
    ASSERT_NE(query, nullptr);
    ASSERT_EQ(query->GetApiType(), IPlugin::ApiType::SYSTEM);
}

HWTEST_F(PolicyQueryFactoryTest, TestGetApiType_PublicApiForMostPolicies, TestSize.Level1)
{
    auto query = PolicyQueryFactory::CreateQuery(EdmInterfaceCode::DISALLOWED_P2P);
    ASSERT_NE(query, nullptr);
    ASSERT_EQ(query->GetApiType(), IPlugin::ApiType::PUBLIC);
}

HWTEST_F(PolicyQueryFactoryTest, TestCreateQuery_AllBoolEntriesQueryPolicy, TestSize.Level1)
{
    auto entries = PolicyQueryConfigTable::GetAllEntries();
    size_t count = PolicyQueryConfigTable::GetConfigCount();
    for (size_t i = 0; i < count; i++) {
        if (!entries[i].config.isFeatureEnabled) {
            continue;
        }
        if (entries[i].config.dataType != PolicyDataType::BOOL) {
            continue;
        }
        auto query = PolicyQueryFactory::CreateQuery(entries[i].code);
        ASSERT_NE(query, nullptr) << "BOOL query is null for code " << entries[i].code;
        std::string policyData = "true";
        MessageParcel data;
        MessageParcel reply;
        ErrCode ret = query->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
        ASSERT_EQ(ret, ERR_OK) << "BOOL QueryPolicy failed for code " << entries[i].code;
    }
}

HWTEST_F(PolicyQueryFactoryTest, TestCreateQuery_AllArrayStringEntriesQueryPolicy, TestSize.Level1)
{
    auto entries = PolicyQueryConfigTable::GetAllEntries();
    size_t count = PolicyQueryConfigTable::GetConfigCount();
    for (size_t i = 0; i < count; i++) {
        if (!entries[i].config.isFeatureEnabled) {
            continue;
        }
        if (entries[i].config.dataType != PolicyDataType::ARRAY_STRING) {
            continue;
        }
        auto query = PolicyQueryFactory::CreateQuery(entries[i].code);
        ASSERT_NE(query, nullptr) << "ARRAY_STRING query is null for code " << entries[i].code;
        std::string policyData = "[\"item1\"]";
        MessageParcel data;
        MessageParcel reply;
        ErrCode ret = query->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
        ASSERT_EQ(ret, ERR_OK) << "ARRAY_STRING QueryPolicy failed for code " << entries[i].code;
    }
}

HWTEST_F(PolicyQueryFactoryTest, TestCreateQuery_AllIntEntriesQueryPolicy, TestSize.Level1)
{
    auto entries = PolicyQueryConfigTable::GetAllEntries();
    size_t count = PolicyQueryConfigTable::GetConfigCount();
    for (size_t i = 0; i < count; i++) {
        if (!entries[i].config.isFeatureEnabled) {
            continue;
        }
        if (entries[i].config.dataType != PolicyDataType::INT) {
            continue;
        }
        auto query = PolicyQueryFactory::CreateQuery(entries[i].code);
        ASSERT_NE(query, nullptr) << "INT query is null for code " << entries[i].code;
        std::string policyData = "1";
        MessageParcel data;
        MessageParcel reply;
        ErrCode ret = query->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
        ASSERT_EQ(ret, ERR_OK) << "INT QueryPolicy failed for code " << entries[i].code;
    }
}

HWTEST_F(PolicyQueryFactoryTest, TestCreateQuery_AllStringEntriesQueryPolicy, TestSize.Level1)
{
    auto entries = PolicyQueryConfigTable::GetAllEntries();
    size_t count = PolicyQueryConfigTable::GetConfigCount();
    for (size_t i = 0; i < count; i++) {
        if (!entries[i].config.isFeatureEnabled) {
            continue;
        }
        if (entries[i].config.dataType != PolicyDataType::STRING) {
            continue;
        }
        auto query = PolicyQueryFactory::CreateQuery(entries[i].code);
        ASSERT_NE(query, nullptr) << "STRING query is null for code " << entries[i].code;
        std::string policyData = "test_value";
        MessageParcel data;
        MessageParcel reply;
        ErrCode ret = query->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
        ASSERT_EQ(ret, ERR_OK) << "STRING QueryPolicy failed for code " << entries[i].code;
    }
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
