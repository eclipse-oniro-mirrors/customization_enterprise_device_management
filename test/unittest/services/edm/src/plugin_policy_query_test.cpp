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

#define protected public
#include "ipolicy_query.h"
#undef protected

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "iplugin.h"
#include "policy_query_factory.h"
#include "policy_query_config_table.h"
#include "policy_query_config.h"
#include "generic_policy_query.h"
#include "utils.h"

#ifdef USERIAM_EDM_ENABLE
#include "password_policy_query.h"
#include "fingerprint_auth_query.h"
#endif

#ifdef PASTEBOARD_EDM_ENABLE
#include "clipboard_policy_query.h"
#endif

#include "get_device_encryption_status_query.h"
#include "get_display_version_query.h"
#include "get_security_patch_tag_query.h"
#include "permission_managed_state_query.h"
#include "installed_bundle_info_list_query.h"
#include "get_installed_bundle_storage_stats_query.h"
#include "query_bundle_stats_infos_query.h"

#ifdef LOCATION_EDM_ENABLE
#include "location_policy_query.h"
#endif

#ifdef COMMON_EVENT_SERVICE_EDM_ENABLE
#include "set_browser_policies_query.h"
#endif

#ifdef TELEPHONY_EDM_ENABLE
#include "telephony_call_policy_query.h"
#endif

#ifdef FEATURE_PC_ONLY
#include "install_local_enterprise_app_enabled_query.h"
#include "install_local_enterprise_app_enabled_for_account_query.h"
#include "get_auto_unlock_after_reboot_query.h"
#endif

#ifndef FEATURE_PC_ONLY
#include "hide_launcher_icon_query.h"
#endif

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::EDM;

namespace OHOS {
namespace EDM {
namespace TEST {

class PluginPolicyQueryTest : public testing::Test {
protected:
    void SetUp() override;
    void TearDown() override;
    static void SetUpTestSuite(void);
    static void TearDownTestSuite(void);
};

void PluginPolicyQueryTest::SetUp() {}
void PluginPolicyQueryTest::TearDown() {}

void PluginPolicyQueryTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void PluginPolicyQueryTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
}

HWTEST_F(PluginPolicyQueryTest, TestAllBoolEntriesQueryPolicyTrue, TestSize.Level1)
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
        ASSERT_EQ(ret, ERR_OK) << "BOOL QueryPolicy(true) failed for code " << entries[i].code;
        int32_t flag = reply.ReadInt32();
        ASSERT_EQ(flag, ERR_OK) << "BOOL reply flag not ERR_OK for code " << entries[i].code;
        bool value = reply.ReadBool();
        ASSERT_TRUE(value) << "BOOL reply value not true for code " << entries[i].code;
    }
}

HWTEST_F(PluginPolicyQueryTest, TestAllBoolEntriesQueryPolicyFalse, TestSize.Level1)
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
        std::string policyData = "false";
        MessageParcel data;
        MessageParcel reply;
        ErrCode ret = query->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
        ASSERT_EQ(ret, ERR_OK) << "BOOL QueryPolicy(false) failed for code " << entries[i].code;
        int32_t flag = reply.ReadInt32();
        ASSERT_EQ(flag, ERR_OK) << "BOOL reply flag not ERR_OK for code " << entries[i].code;
        bool value = reply.ReadBool();
        ASSERT_FALSE(value) << "BOOL reply value not false for code " << entries[i].code;
    }
}

HWTEST_F(PluginPolicyQueryTest, TestAllArrayStringEntriesQueryPolicy, TestSize.Level1)
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
        std::string policyData = "[\"com.example.app1\", \"com.example.app2\"]";
        MessageParcel data;
        MessageParcel reply;
        ErrCode ret = query->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
        ASSERT_EQ(ret, ERR_OK) << "ARRAY_STRING QueryPolicy failed for code " << entries[i].code;
        int32_t flag = reply.ReadInt32();
        ASSERT_EQ(flag, ERR_OK) << "ARRAY_STRING reply flag not ERR_OK for code " << entries[i].code;
    }
}

HWTEST_F(PluginPolicyQueryTest, TestAllArrayStringEntriesQueryPolicyEmpty, TestSize.Level1)
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
        ASSERT_NE(query, nullptr);
        std::string policyData = "[]";
        MessageParcel data;
        MessageParcel reply;
        ErrCode ret = query->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
        ASSERT_EQ(ret, ERR_OK) << "ARRAY_STRING QueryPolicy(empty) failed for code " << entries[i].code;
    }
}

HWTEST_F(PluginPolicyQueryTest, TestAllIntEntriesQueryPolicy, TestSize.Level1)
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
        int32_t flag = reply.ReadInt32();
        ASSERT_EQ(flag, ERR_OK) << "INT reply flag not ERR_OK for code " << entries[i].code;
        int32_t value = reply.ReadInt32();
        ASSERT_EQ(value, 1) << "INT reply value not 1 for code " << entries[i].code;
    }
}

HWTEST_F(PluginPolicyQueryTest, TestAllIntEntriesQueryPolicyZero, TestSize.Level1)
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
        ASSERT_NE(query, nullptr);
        std::string policyData = "0";
        MessageParcel data;
        MessageParcel reply;
        ErrCode ret = query->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
        ASSERT_EQ(ret, ERR_OK) << "INT QueryPolicy(0) failed for code " << entries[i].code;
    }
}

HWTEST_F(PluginPolicyQueryTest, TestAllStringEntriesQueryPolicy, TestSize.Level1)
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
        std::string policyData = "test_string_value";
        MessageParcel data;
        MessageParcel reply;
        ErrCode ret = query->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
        ASSERT_EQ(ret, ERR_OK) << "STRING QueryPolicy failed for code " << entries[i].code;
        int32_t flag = reply.ReadInt32();
        ASSERT_EQ(flag, ERR_OK) << "STRING reply flag not ERR_OK for code " << entries[i].code;
        std::string value = reply.ReadString();
        ASSERT_EQ(value, "test_string_value") << "STRING reply value mismatch for code " << entries[i].code;
    }
}

HWTEST_F(PluginPolicyQueryTest, TestAllCustomEntriesCreateQueryNonNull, TestSize.Level1)
{
    auto entries = PolicyQueryConfigTable::GetAllEntries();
    size_t count = PolicyQueryConfigTable::GetConfigCount();
    for (size_t i = 0; i < count; i++) {
        if (!entries[i].config.isFeatureEnabled) {
            continue;
        }
        if (entries[i].config.dataType != PolicyDataType::CUSTOM) {
            continue;
        }
        auto query = PolicyQueryFactory::CreateQuery(entries[i].code);
        ASSERT_NE(query, nullptr) << "CUSTOM query is null for code " << entries[i].code;
    }
}

HWTEST_F(PluginPolicyQueryTest, TestAllCustomEntriesPolicyNameMatch, TestSize.Level1)
{
    auto entries = PolicyQueryConfigTable::GetAllEntries();
    size_t count = PolicyQueryConfigTable::GetConfigCount();
    for (size_t i = 0; i < count; i++) {
        if (!entries[i].config.isFeatureEnabled) {
            continue;
        }
        if (entries[i].config.dataType != PolicyDataType::CUSTOM) {
            continue;
        }
        auto query = PolicyQueryFactory::CreateQuery(entries[i].code);
        ASSERT_NE(query, nullptr);
        ASSERT_EQ(query->GetPolicyName(), entries[i].config.policyName)
            << "CUSTOM policyName mismatch for code " << entries[i].code;
    }
}

HWTEST_F(PluginPolicyQueryTest, TestAllCustomEntriesPermissionMatch, TestSize.Level1)
{
    auto entries = PolicyQueryConfigTable::GetAllEntries();
    size_t count = PolicyQueryConfigTable::GetConfigCount();
    for (size_t i = 0; i < count; i++) {
        if (!entries[i].config.isFeatureEnabled) {
            continue;
        }
        if (entries[i].config.dataType != PolicyDataType::CUSTOM) {
            continue;
        }
        auto query = PolicyQueryFactory::CreateQuery(entries[i].code);
        ASSERT_NE(query, nullptr);
        std::string queryPerm = query->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "");
        std::string configPerm = entries[i].config.permissionConfig.GetPermission(
            IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "");
        ASSERT_EQ(queryPerm, configPerm)
            << "CUSTOM SUPER permission mismatch for code " << entries[i].code;
    }
}

HWTEST_F(PluginPolicyQueryTest, TestFactoryUnsupportedCode, TestSize.Level1)
{
    auto query = PolicyQueryFactory::CreateQuery(99999);
    ASSERT_TRUE(query == nullptr);
}

HWTEST_F(PluginPolicyQueryTest, TestCheckFeatureEnabled, TestSize.Level1)
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

HWTEST_F(PluginPolicyQueryTest, TestCheckFeatureUnsupportedCode, TestSize.Level1)
{
    ErrCode ret = PolicyQueryFactory::CheckFeatureEnabled(99999);
    ASSERT_TRUE(ret == ERR_CANNOT_FIND_QUERY_FAILED);
}

HWTEST_F(PluginPolicyQueryTest, TestConfigTableHasEntries, TestSize.Level1)
{
    ASSERT_TRUE(PolicyQueryConfigTable::GetConfigCount() > 0);
    ASSERT_TRUE(PolicyQueryConfigTable::FindConfig(EdmInterfaceCode::ALLOWED_INSTALL_BUNDLES) != nullptr);
}

HWTEST_F(PluginPolicyQueryTest, TestAllRestrictionPermissionByodEntries, TestSize.Level1)
{
    auto entries = PolicyQueryConfigTable::GetAllEntries();
    size_t count = PolicyQueryConfigTable::GetConfigCount();
    for (size_t i = 0; i < count; i++) {
        if (!entries[i].config.isFeatureEnabled) {
            continue;
        }
        if (entries[i].config.permissionConfig.pattern == PermissionPattern::RESTRICTION && entries[i].config.permissionConfig.hasByod) {
            auto query = PolicyQueryFactory::CreateQuery(entries[i].code);
            ASSERT_NE(query, nullptr);
            std::string byodPerm = query->GetPermission(IPlugin::PermissionType::BYOD_DEVICE_ADMIN, "");
            ASSERT_EQ(byodPerm, EdmPermission::PERMISSION_PERSONAL_MANAGE_RESTRICTIONS)
                << "RestrictionPermission(true) BYOD should be PERSONAL for code " << entries[i].code;
        }
    }
}

HWTEST_F(PluginPolicyQueryTest, TestAllRestrictionNoByodEntries, TestSize.Level1)
{
    auto entries = PolicyQueryConfigTable::GetAllEntries();
    size_t count = PolicyQueryConfigTable::GetConfigCount();
    for (size_t i = 0; i < count; i++) {
        if (!entries[i].config.isFeatureEnabled) {
            continue;
        }
        if (entries[i].config.permissionConfig.pattern == PermissionPattern::RESTRICTION
            && !entries[i].config.permissionConfig.hasByod) {
            auto query = PolicyQueryFactory::CreateQuery(entries[i].code);
            ASSERT_NE(query, nullptr);
            std::string byodPerm = query->GetPermission(IPlugin::PermissionType::BYOD_DEVICE_ADMIN, "");
            ASSERT_EQ(byodPerm, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS)
                << "RestrictionPermission(no-byod) BYOD should be MANAGE_RESTRICTIONS for code " << entries[i].code;
        }
    }
}

HWTEST_F(PluginPolicyQueryTest, TestAllSpecificPermissionEntries, TestSize.Level1)
{
    auto entries = PolicyQueryConfigTable::GetAllEntries();
    size_t count = PolicyQueryConfigTable::GetConfigCount();
    for (size_t i = 0; i < count; i++) {
        if (!entries[i].config.isFeatureEnabled) {
            continue;
        }
        if (entries[i].config.permissionConfig.pattern != PermissionPattern::SPECIFIC) {
            continue;
        }
        auto query = PolicyQueryFactory::CreateQuery(entries[i].code);
        ASSERT_NE(query, nullptr);
        std::string superPerm = query->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "");
        ASSERT_EQ(superPerm, std::string(entries[i].config.permissionConfig.specificPermission))
            << "SpecificPermission SUPER mismatch for code " << entries[i].code;
        std::string byodPerm = query->GetPermission(IPlugin::PermissionType::BYOD_DEVICE_ADMIN, "");
        ASSERT_EQ(byodPerm, std::string(entries[i].config.permissionConfig.specificPermission))
            << "SpecificPermission BYOD mismatch for code " << entries[i].code;
    }
}

HWTEST_F(PluginPolicyQueryTest, TestAllTagPermissionEntriesWithTag, TestSize.Level1)
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
        std::string permWithTag = query->GetPermission(
            IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "version_11");
        ASSERT_EQ(permWithTag, std::string(entries[i].config.permissionConfig.tagPermission))
            << "TagPermission with tag mismatch for code " << entries[i].code;
    }
}

HWTEST_F(PluginPolicyQueryTest, TestAllTagPermissionEntriesWithoutTag, TestSize.Level1)
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
        auto query = PolicyQueryFactory::CreateQuery(entries[i].code);
        ASSERT_NE(query, nullptr);
        std::string permNoTag = query->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "");
        ASSERT_EQ(permNoTag, std::string(entries[i].config.permissionConfig.specificPermission))
            << "TagPermission without tag mismatch for code " << entries[i].code;
    }
}

HWTEST_F(PluginPolicyQueryTest, TestAllTagPermissionByodEntries, TestSize.Level1)
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
        auto query = PolicyQueryFactory::CreateQuery(entries[i].code);
        ASSERT_NE(query, nullptr);
        std::string byodPerm = query->GetPermission(IPlugin::PermissionType::BYOD_DEVICE_ADMIN, "");
        if (entries[i].config.permissionConfig.byodPermission != nullptr) {
            ASSERT_EQ(byodPerm, std::string(entries[i].config.permissionConfig.byodPermission))
                << "TagPermission BYOD mismatch for code " << entries[i].code;
        } else {
            ASSERT_EQ(byodPerm, std::string(entries[i].config.permissionConfig.specificPermission))
                << "TagPermission BYOD with empty byodPerm mismatch for code " << entries[i].code;
        }
    }
}

HWTEST_F(PluginPolicyQueryTest, TestGetDeviceEncryptionStatusQuery, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> plugin = std::make_shared<GetDeviceEncryptionStatusQuery>();
    std::string policyValue{"GetDeviceEncryptionStatus"};
    MessageParcel data;
    MessageParcel reply;
    plugin->QueryPolicy(policyValue, data, reply, EdmConstants::DEFAULT_USER_ID);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    ASSERT_TRUE(reply.ReadBool() == true);
}

HWTEST_F(PluginPolicyQueryTest, TestGetDeviceEncryptionStatusQueryPermission, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<GetDeviceEncryptionStatusQuery>();
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "")
        == EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY);
    ASSERT_TRUE(queryObj->GetPolicyName() == PolicyName::POLICY_GET_DEVICE_ENCRYPTION_STATUS);
}

HWTEST_F(PluginPolicyQueryTest, TestGetSecurityPatchTagQuery, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> plugin = std::make_shared<GetSecurityPatchTagQuery>();
    std::string policyValue{"GetSecurityPatchTag"};
    MessageParcel data;
    MessageParcel reply;
    plugin->QueryPolicy(policyValue, data, reply, EdmConstants::DEFAULT_USER_ID);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    ASSERT_TRUE(reply.ReadString() != "");
}

HWTEST_F(PluginPolicyQueryTest, TestGetSecurityPatchTagQueryPermission, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<GetSecurityPatchTagQuery>();
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "")
        == EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY);
    ASSERT_TRUE(queryObj->GetPolicyName() == PolicyName::POLICY_GET_SECURITY_PATCH_TAG);
}

HWTEST_F(PluginPolicyQueryTest, TestGetDisplayVersionQueryPermission, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<GetDisplayVersionQuery>();
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "")
        == EdmPermission::PERMISSION_ENTERPRISE_GET_DEVICE_INFO);
    ASSERT_TRUE(queryObj->GetPolicyName() == PolicyName::POLICY_GET_DISPLAY_VERSION);
    ASSERT_TRUE(queryObj->IsPolicySaved() == true);
    ASSERT_TRUE(queryObj->GetApiType() == IPlugin::ApiType::SYSTEM);
}

HWTEST_F(PluginPolicyQueryTest, TestPermissionManagedStateQueryPermission, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<PermissionManagedStateQuery>();
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "")
        == EdmPermission::PERMISSION_ENTERPRISE_MANAGE_USER_GRANT_PERMISSION);
    ASSERT_TRUE(queryObj->GetPolicyName() == PolicyName::POLICY_PERMISSION_MANAGED_STATE_POLICY);
}

HWTEST_F(PluginPolicyQueryTest, TestInstalledBundleInfoListQueryPermission, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<InstalledBundleInfoListQuery>();
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "")
        == EdmPermission::PERMISSION_ENTERPRISE_GET_ALL_BUNDLE_INFO);
    ASSERT_TRUE(queryObj->GetPolicyName() == PolicyName::POLICY_INSTALLED_BUNDLE_INFO_LIST);
}

#ifdef USERIAM_EDM_ENABLE
HWTEST_F(PluginPolicyQueryTest, TestPasswordPolicyQuery, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> plugin = std::make_shared<PasswordPolicyQuery>();
    MessageParcel data;
    MessageParcel reply;
    std::string policyData;
    ErrCode ret = plugin->QueryPolicy(policyData, data, reply, 0);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(policyData.empty());
}

HWTEST_F(PluginPolicyQueryTest, TestPasswordPolicyQueryPermission, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<PasswordPolicyQuery>();
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "")
        == EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY);
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmConstants::PERMISSION_TAG_SYSTEM_API)
        == "");
    ASSERT_TRUE(queryObj->GetPolicyName() == PolicyName::POLICY_PASSWORD_POLICY);
}

HWTEST_F(PluginPolicyQueryTest, TestFingerprintAuthQuery, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> plugin = std::make_shared<FingerprintAuthQuery>();
    MessageParcel data;
    data.WriteString(EdmConstants::FINGERPRINT_AUTH_TYPE);
    MessageParcel reply;
    std::string policyData = "true";
    plugin->QueryPolicy(policyData, data, reply, 100);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    ASSERT_TRUE(reply.ReadBool());
}

HWTEST_F(PluginPolicyQueryTest, TestFingerprintAuthQueryPermission, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<FingerprintAuthQuery>();
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "")
        == EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::BYOD_DEVICE_ADMIN, "")
        == EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    ASSERT_TRUE(queryObj->GetPolicyName() == PolicyName::POLICY_FINGERPRINT_AUTH);
}
#endif

#ifdef PASTEBOARD_EDM_ENABLE
HWTEST_F(PluginPolicyQueryTest, TestClipboardPolicyQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<ClipboardPolicyQuery>();
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(5);
    const std::string POLICY_DATA =
        "[{\"tokenId\":1,\"userId\":100,\"bundleName\":\"com.ohos.test1\",\"clipboardPolicy\":1},"
        "{\"tokenId\":2,\"userId\":100,\"bundleName\":\"com.ohos.test2\",\"clipboardPolicy\":2}]";
    std::string policyData = POLICY_DATA;
    queryObj->QueryPolicy(policyData, data, reply, 0);
    int32_t ret = reply.ReadInt32();
    std::string policy = reply.ReadString();
    ASSERT_TRUE(ret == ERR_OK);
}

HWTEST_F(PluginPolicyQueryTest, TestClipboardPolicyQueryPermission, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<ClipboardPolicyQuery>();
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "")
        == EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::BYOD_DEVICE_ADMIN, "")
        == EdmPermission::PERMISSION_PERSONAL_MANAGE_RESTRICTIONS);
    ASSERT_TRUE(queryObj->GetPolicyName() == PolicyName::POLICY_CLIPBOARD_POLICY);
}
#endif

#ifdef LOCATION_EDM_ENABLE
HWTEST_F(PluginPolicyQueryTest, TestLocationPolicyQueryPermission, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<LocationPolicyQuery>();
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "")
        == EdmPermission::PERMISSION_ENTERPRISE_MANAGE_LOCATION);
    ASSERT_TRUE(queryObj->GetPolicyName() == PolicyName::POLICY_LOCATION_POLICY);
}
#endif

#ifdef COMMON_EVENT_SERVICE_EDM_ENABLE
HWTEST_F(PluginPolicyQueryTest, TestSetBrowserPoliciesQueryPermission, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<SetBrowserPoliciesQuery>();
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "")
        == "");
    ASSERT_TRUE(queryObj->GetPolicyName() == PolicyName::POLICY_SET_BROWSER_POLICIES);
}
#endif

#ifdef TELEPHONY_EDM_ENABLE
HWTEST_F(PluginPolicyQueryTest, TestTelephonyCallPolicyQueryPermission, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<TelephonyCallPolicyQuery>();
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "")
        == EdmPermission::PERMISSION_ENTERPRISE_MANAGE_TELEPHONY);
    ASSERT_TRUE(queryObj->GetPolicyName() == PolicyName::POLICY_TELEPHONY_CALL_POLICY);
}
#endif

#ifdef FEATURE_PC_ONLY
HWTEST_F(PluginPolicyQueryTest,
    TestInstallLocalEnterpriseAppEnabledQueryPermission, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj =
        std::make_shared<InstallLocalEnterpriseAppEnabledQuery>();
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "")
        == EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SYSTEM);
    ASSERT_TRUE(queryObj->GetPolicyName() ==
        PolicyName::POLICY_SET_INSTALL_LOCAL_ENTERPRISE_APP_ENABLED);
}

HWTEST_F(PluginPolicyQueryTest,
    TestInstallLocalEnterpriseAppEnabledForAccountQueryPermission, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj =
        std::make_shared<InstallLocalEnterpriseAppEnabledForAccountQuery>();
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "")
        == EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SYSTEM);
    ASSERT_TRUE(queryObj->GetPolicyName() ==
        PolicyName::POLICY_INSTALL_LOCAL_ENTERPRISE_APP_ENABLED_FOR_ACCOUNT);
}

HWTEST_F(PluginPolicyQueryTest,
    TestGetAutoUnlockAfterRebootQueryPermission, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj =
        std::make_shared<GetAutoUnlockAfterRebootQuery>();
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "")
        == EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SYSTEM);
    ASSERT_TRUE(queryObj->GetPolicyName() ==
        PolicyName::POLICY_SET_AUTO_UNLOCK_AFTER_REBOOT);
}
#endif

#ifndef FEATURE_PC_ONLY
HWTEST_F(PluginPolicyQueryTest, TestHideLauncherIconQueryPermission, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<HideLauncherIconQuery>();
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "")
        == EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION);
    ASSERT_TRUE(queryObj->GetPolicyName() == PolicyName::POLICY_HIDE_LAUNCHER_ICON);
}
#endif

HWTEST_F(PluginPolicyQueryTest, TestAllEnabledEntriesIsPolicySavedConsistent, TestSize.Level1)
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

HWTEST_F(PluginPolicyQueryTest, TestAllEnabledEntriesApiTypeConsistent, TestSize.Level1)
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

HWTEST_F(PluginPolicyQueryTest, TestDisallowedP2PRestrictionPermissionIntegration, TestSize.Level1)
{
    auto query = PolicyQueryFactory::CreateQuery(EdmInterfaceCode::DISALLOWED_P2P);
    ASSERT_NE(query, nullptr);
    ASSERT_EQ(query->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, ""),
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    ASSERT_EQ(query->GetPermission(IPlugin::PermissionType::BYOD_DEVICE_ADMIN, ""),
        EdmPermission::PERMISSION_PERSONAL_MANAGE_RESTRICTIONS);
    ASSERT_EQ(query->GetPolicyName(), PolicyName::POLICY_DISALLOWED_P2P);
    ASSERT_EQ(query->IsPolicySaved(), true);
    ASSERT_EQ(query->GetApiType(), IPlugin::ApiType::PUBLIC);
}

HWTEST_F(PluginPolicyQueryTest, TestDisabledAppCloneRestrictionNoByodIntegration, TestSize.Level1)
{
    auto query = PolicyQueryFactory::CreateQuery(EdmInterfaceCode::DISABLED_APP_CLONE);
    ASSERT_NE(query, nullptr);
    ASSERT_EQ(query->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, ""),
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    ASSERT_EQ(query->GetPermission(IPlugin::PermissionType::BYOD_DEVICE_ADMIN, ""),
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
}

HWTEST_F(PluginPolicyQueryTest, TestAllowedInstallBundlesSpecificPermissionIntegration, TestSize.Level1)
{
    auto query = PolicyQueryFactory::CreateQuery(EdmInterfaceCode::ALLOWED_INSTALL_BUNDLES);
    ASSERT_NE(query, nullptr);
    ASSERT_EQ(query->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, ""),
        EdmPermission::PERMISSION_ENTERPRISE_SET_BUNDLE_INSTALL_POLICY);
    ASSERT_EQ(query->GetPermission(IPlugin::PermissionType::BYOD_DEVICE_ADMIN, ""),
        EdmPermission::PERMISSION_ENTERPRISE_SET_BUNDLE_INSTALL_POLICY);
}

HWTEST_F(PluginPolicyQueryTest, TestDisallowModifyDatetimeTagPermissionIntegration, TestSize.Level1)
{
    auto query = PolicyQueryFactory::CreateQuery(EdmInterfaceCode::DISALLOW_MODIFY_DATETIME);
    ASSERT_NE(query, nullptr);
    ASSERT_EQ(query->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "version_11"),
        EdmPermission::PERMISSION_ENTERPRISE_SET_DATETIME);
    ASSERT_EQ(query->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, ""),
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
}

HWTEST_F(PluginPolicyQueryTest, TestIsAppKioskAllowedEmptyPermissionIntegration, TestSize.Level1)
{
    auto query = PolicyQueryFactory::CreateQuery(EdmInterfaceCode::IS_APP_KIOSK_ALLOWED);
    ASSERT_NE(query, nullptr);
    ASSERT_EQ(query->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, ""), "");
    ASSERT_EQ(query->GetPermission(IPlugin::PermissionType::BYOD_DEVICE_ADMIN, ""), "");
}

HWTEST_F(PluginPolicyQueryTest, TestGetDisplayVersionSystemApiIntegration, TestSize.Level1)
{
    auto query = PolicyQueryFactory::CreateQuery(EdmInterfaceCode::GET_DISPLAY_VERSION);
    ASSERT_NE(query, nullptr);
    ASSERT_EQ(query->GetApiType(), IPlugin::ApiType::SYSTEM);
    ASSERT_EQ(query->IsPolicySaved(), true);
    ASSERT_EQ(query->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, ""),
        EdmPermission::PERMISSION_ENTERPRISE_GET_DEVICE_INFO);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
