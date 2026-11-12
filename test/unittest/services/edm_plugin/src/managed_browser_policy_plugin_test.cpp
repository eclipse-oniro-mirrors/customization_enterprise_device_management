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

#include <cstdio>
#include <fstream>
#include "managed_browser_policy_plugin_test.h"

#include "device_policies_storage_rdb.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "edm_sys_manager.h"
#include "ipolicy_manager.h"
#include "managed_browser_policy_serializer.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string TEST_POLICY_DATA = "{\"test_bundle_name\":{\"version\":1,\"policyNames\":[\"test_policy_name\"]}}";
const std::string TEST_BUNDLE_NAME = "test_bundle_name";
const std::string TEST_POLICY_NAME = "test_policy_name";
const std::string TEST_POLICY_VALUE = "\"test_policy_value\"";
const std::string TEST_ADMIN_A = "com.admin.a";
const std::string TEST_ADMIN_B = "com.admin.b";
const std::string TEST_ADMIN_C = "com.admin.c";
const std::string TEST_OTHER_BUNDLE_NAME = "other_bundle_name";
const std::string TEST_OTHER_POLICY_NAME = "other_policy_name";
constexpr int32_t TEST_OTHER_BUNDLE_VERSION = 2;
constexpr int32_t TEST_FIRST_ADMIN_VERSION = 7;
constexpr int32_t TEST_SECOND_ADMIN_VERSION = 2;

namespace {
std::uint32_t BuildFuncCode(EdmInterfaceCode policyCode)
{
    return POLICY_FUNC_CODE(static_cast<std::uint32_t>(FuncOperateType::SET), policyCode);
}

std::uint32_t BuildNewFuncCode(EdmInterfaceCode policyCode)
{
    return POLICY_FUNC_CODE_NEW(static_cast<std::uint32_t>(FuncOperateType::SET), policyCode);
}

void BuildSetPolicyParcel(MessageParcel &data, bool isForceOverride)
{
    data.WriteString(TEST_BUNDLE_NAME);
    data.WriteString(TEST_POLICY_NAME);
    data.WriteString(TEST_POLICY_VALUE);
    data.WriteBool(isForceOverride);
}

// The legacy callers wrote no force override flag at all, their parcel ends after the policy value.
void BuildLegacySetPolicyParcel(MessageParcel &data)
{
    data.WriteString(TEST_BUNDLE_NAME);
    data.WriteString(TEST_POLICY_NAME);
    data.WriteString(TEST_POLICY_VALUE);
}

void DeserializeOrFail(const std::string &data, std::map<std::string, ManagedBrowserPolicyType> &policies)
{
    if (!ManagedBrowserPolicySerializer::GetInstance()->Deserialize(data, policies)) {
        ADD_FAILURE() << "the blob written by the code under test is not deserializable";
    }
}

int32_t CountName(const std::vector<std::string> &names, const std::string &name)
{
    return static_cast<int32_t>(std::count(names.begin(), names.end(), name));
}

std::string BuildAdminPolicyData(const std::string &bundleName, const std::string &policyName, uint16_t version)
{
    std::map<std::string, ManagedBrowserPolicyType> adminPolicies;
    adminPolicies[bundleName].version = version;
    adminPolicies[bundleName].policyNames.push_back(policyName);
    std::string data;
    ManagedBrowserPolicySerializer::GetInstance()->Serialize(adminPolicies, data);
    return data;
}
} // namespace
const char* const MANAGED_BROWSER_POLICY_DIR = "/data/service/el1/public/edm/browser/";
const char* const MANAGED_BROWSER_POLICY_SUFFIX = ".dat";
const std::string URL = MANAGED_BROWSER_POLICY_DIR + TEST_BUNDLE_NAME + MANAGED_BROWSER_POLICY_SUFFIX;
const std::string TMP_URL = MANAGED_BROWSER_POLICY_DIR + TEST_BUNDLE_NAME + "_tmp" + MANAGED_BROWSER_POLICY_SUFFIX;

void ManagedBrowserPolicyPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void ManagedBrowserPolicyPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

void ManagedBrowserPolicyPluginTest::SetUp(void)
{
    RemovePolicyFiles();
}

void ManagedBrowserPolicyPluginTest::TearDown(void)
{
    RemovePolicyFiles();
    ClearStoredBrowserPolicy();
    IPolicyManager::policyManagerInstance_ = nullptr;
}

void ManagedBrowserPolicyPluginTest::RemovePolicyFiles(void)
{
    if (remove(URL.c_str()) != 0) {
        EDMLOGW("ManagedBrowserPolicyPluginTest::RemovePolicyFiles remove %{public}s failed.", URL.c_str());
    }
    if (remove(TMP_URL.c_str()) != 0) {
        EDMLOGW("ManagedBrowserPolicyPluginTest::RemovePolicyFiles remove %{public}s failed.", TMP_URL.c_str());
    }
}

void ManagedBrowserPolicyPluginTest::ClearStoredBrowserPolicy(void)
{
    auto storage = DevicePoliciesStorageRdb::GetInstance();
    if (storage == nullptr) {
        return;
    }
    storage->DeleteAdminPolicy(DEFAULT_USER_ID, TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY);
    storage->DeleteAdminPolicy(DEFAULT_USER_ID, TEST_ADMIN_B, PolicyName::POLICY_MANAGED_BROWSER_POLICY);
    storage->DeleteAdminPolicy(DEFAULT_USER_ID, TEST_ADMIN_C, PolicyName::POLICY_MANAGED_BROWSER_POLICY);
    storage->DeleteCombinedPolicy(DEFAULT_USER_ID, PolicyName::POLICY_MANAGED_BROWSER_POLICY);
}

std::shared_ptr<PolicyManager> ManagedBrowserPolicyPluginTest::AcquirePolicyManager(void)
{
    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();
    return policyManager;
}

/**
 * @tc.name: TestOnHandlePolicyFailWithEmptyBundleName
 * @tc.desc: Test ManagedBrowserPolicyPluginTest::OnHandlePolicy when BundleName is empty.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyFailWithEmptyBundleName, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    std::uint32_t funcCode = 0;
    std::string emptyBundleName;
    MessageParcel data;
    data.WriteString(emptyBundleName);
    data.WriteString(TEST_POLICY_NAME);
    data.WriteString(TEST_POLICY_VALUE);
    data.WriteBool(false);
    MessageParcel reply;
    HandlePolicyData policyData;
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnHandlePolicyFailWithInvalidBundleName
 * @tc.desc: Test ManagedBrowserPolicyPluginTest::OnHandlePolicy when BundleName is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyFailWithInvalidBundleName, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    std::uint32_t funcCode = 0;
    std::string invalidBundleName = "../invalidBundleName";
    MessageParcel data;
    data.WriteString(invalidBundleName);
    data.WriteString(TEST_POLICY_NAME);
    data.WriteString(TEST_POLICY_VALUE);
    data.WriteBool(false);
    MessageParcel reply;
    HandlePolicyData policyData;
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnHandlePolicyFailWithEmptyPolicyName
 * @tc.desc: Test ManagedBrowserPolicyPluginTest::OnHandlePolicy when PolicyName is empty.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyFailWithEmptyPolicyName, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    std::uint32_t funcCode = 0;
    std::string emptyPolicyName;
    MessageParcel data;
    data.WriteString(TEST_BUNDLE_NAME);
    data.WriteString(emptyPolicyName);
    data.WriteString(TEST_POLICY_VALUE);
    data.WriteBool(false);
    MessageParcel reply;
    HandlePolicyData policyData;
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnHandlePolicySucAddPolicy
 * @tc.desc: Test ManagedBrowserPolicyPluginTest::OnHandlePolicy Success.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicySucAddPolicy, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    std::uint32_t funcCode = 0;
    MessageParcel data;
    data.WriteString(TEST_BUNDLE_NAME);
    data.WriteString(TEST_POLICY_NAME);
    data.WriteString(TEST_POLICY_VALUE);
    data.WriteBool(false);
    MessageParcel reply;
    HandlePolicyData policyData;
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnGetPolicyFailWithInvalidType
 * @tc.desc: Test ManagedBrowserPolicyPluginTest::OnGetPolicy when type is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnGetPolicyFailWithInvalidType, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    std::string policyData;
    std::string type = "invalidType";
    MessageParcel data;
    data.WriteString(type);
    MessageParcel reply;

    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestOnGetPolicyFailWithEmptyBundleName
 * @tc.desc: Test ManagedBrowserPolicyPluginTest::OnGetPolicy with empty bundle name.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnGetPolicyFailWithEmptyBundleName, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    std::string policyData;
    std::string type = EdmConstants::Browser::GET_MANAGED_BROWSER_FILE_DATA;
    std::string bundleName;
    MessageParcel data;
    data.WriteString(type);
    data.WriteString(bundleName);
    MessageParcel reply;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnGetPolicyFailWithInvalidBundleName
 * @tc.desc: Test ManagedBrowserPolicyPluginTest::OnGetPolicy with invalid bundle name.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnGetPolicyFailWithInvalidBundleName, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    std::string policyData;
    std::string type = EdmConstants::Browser::GET_MANAGED_BROWSER_FILE_DATA;
    std::string bundleName = "../invalidbundleName";
    MessageParcel data;
    data.WriteString(type);
    data.WriteString(bundleName);
    MessageParcel reply;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnGetPolicySucForGetPolicyData
 * @tc.desc: Test ManagedBrowserPolicyPluginTest::OnGetPolicy success for get policy data.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnGetPolicySucForGetPolicyData, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    MessageParcel data;
    data.WriteString(EdmConstants::Browser::GET_MANAGED_BROWSER_FILE_DATA);
    data.WriteString(TEST_BUNDLE_NAME);
    MessageParcel reply;
    std::string policyData = TEST_POLICY_DATA;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() > 0);
}

/**
 * @tc.name: TestGetManagedBrowserPolicyVersionSuc
 * @tc.desc: Test ManagedBrowserPolicyPluginTest::GetManagedBrowserPolicyVersion success.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestGetManagedBrowserPolicyVersionSuc, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    std::string policyData = TEST_POLICY_DATA;
    ErrCode ret = plugin.GetManagedBrowserPolicyVersion(policyData, TEST_BUNDLE_NAME, reply);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == 1);
}

/**
 * @tc.name: TestGetSelfManagedBrowserPolicyData
 * @tc.desc: Test ManagedBrowserPolicyPluginTest::GetManagedBrowserPolicyFileData success.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestGetSelfManagedBrowserPolicyData, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;

    ErrCode ret = plugin.GetManagedBrowserPolicyFileData(TEST_BUNDLE_NAME, reply);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() > 0);
}

/**
 * @tc.name: TestOnHandlePolicySucForModifyOrRemovePolicy
 * @tc.desc: Test ManagedBrowserPolicyPluginTest::OnHandlePolicy success.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicySucForModifyOrRemovePolicy, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    std::uint32_t funcCode = 0;
    std::string emptyPolicyValue;
    std::ofstream seed(URL);
    ASSERT_FALSE(seed.fail());
    seed << "\"" << TEST_POLICY_NAME << "\":" <<
    TEST_POLICY_VALUE << std::endl;
    seed.close();
    MessageParcel data;
    data.WriteString(TEST_BUNDLE_NAME);
    data.WriteString(TEST_POLICY_NAME);
    data.WriteString(emptyPolicyValue);
    data.WriteBool(false);
    MessageParcel reply;
    std::map<std::string, ManagedBrowserPolicyType> policies;
    policies[TEST_BUNDLE_NAME].version = 1;
    policies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    HandlePolicyData policyData;
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    serializer->Serialize(policies, policyData.policyData);
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestModifyOrRemoveManagedBrowserPolicyFailWithInvalidUrl
 * @tc.desc: Test ManagedBrowserPolicyPluginTest::ModifyOrRemoveManagedBrowserPolicy failed with invalid url.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestModifyOrRemoveManagedBrowserPolicyFailWithInvalidUrl, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    std::map<std::string, ManagedBrowserPolicyType> policies;
    const std::string bundleName = "com.not.existed";
    const std::string policyName;
    const std::string policyValue;
    ErrCode ret = plugin.ModifyOrRemoveManagedBrowserPolicy(policies, bundleName, policyName, policyValue);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestModifyOrRemoveManagedBrowserPolicyFailWithInvalidFile
 * @tc.desc: Test ManagedBrowserPolicyPluginTest::ModifyOrRemoveManagedBrowserPolicy failed with invalid bundle name.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestModifyOrRemoveManagedBrowserPolicyFailWithInvalidFile, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    std::map<std::string, ManagedBrowserPolicyType> policies;
    const std::string bundleName = TEST_BUNDLE_NAME;
    std::ofstream policyFile(URL, std::ios::app);
    if (policyFile.fail()) {
        ASSERT_TRUE(false);
    }
    policyFile << "test" << std::endl;
    policyFile.close();
    ErrCode ret = plugin.ModifyOrRemoveManagedBrowserPolicy(policies, bundleName, TEST_POLICY_NAME, TEST_POLICY_VALUE);
    std::string tempUrl = MANAGED_BROWSER_POLICY_DIR + bundleName + "_tmp" + MANAGED_BROWSER_POLICY_SUFFIX;
    ASSERT_TRUE(remove(URL.c_str()) == ERR_OK);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestOnHandlePolicyOwnershipTakenByAdminA
 * @tc.desc: Admin B cannot change a policy that admin A stored without force override.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyOwnershipTakenByAdminA, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        BuildAdminPolicyData(TEST_BUNDLE_NAME, TEST_POLICY_NAME, 1), "", DEFAULT_USER_ID), ERR_OK);

    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.currentAdminName = TEST_ADMIN_B;
    MessageParcel data;
    BuildSetPolicyParcel(data, false);
    ErrCode ret = plugin.OnHandlePolicy(BuildNewFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY),
        data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);
    ASSERT_FALSE(policyData.isChanged);
}

/**
 * @tc.name: TestOnHandlePolicyOwnerCanModifyOwnPolicy
 * @tc.desc: The owning admin can keep updating its own policy without force override.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyOwnerCanModifyOwnPolicy, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        BuildAdminPolicyData(TEST_BUNDLE_NAME, TEST_POLICY_NAME, 1), "", DEFAULT_USER_ID), ERR_OK);

    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.currentAdminName = TEST_ADMIN_A;
    MessageParcel data;
    BuildSetPolicyParcel(data, false);
    ErrCode ret = plugin.OnHandlePolicy(BuildNewFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY),
        data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(policyData.isChanged);
}

/**
 * @tc.name: TestOnHandlePolicyForceOverrideTakesOwnership
 * @tc.desc: Admin B can take over a policy that admin A stored by using force override.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyForceOverrideTakesOwnership, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        BuildAdminPolicyData(TEST_BUNDLE_NAME, TEST_POLICY_NAME, 1), "", DEFAULT_USER_ID), ERR_OK);

    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.currentAdminName = TEST_ADMIN_B;
    MessageParcel data;
    BuildSetPolicyParcel(data, true);
    ErrCode ret = plugin.OnHandlePolicy(BuildNewFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY), data,
        reply, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(policyData.isChanged);

    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    DeserializeOrFail(policyData.mergePolicyData, mergePolicies);
    EXPECT_EQ(CountName(mergePolicies[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 1);
}

/**
 * @tc.name: TestOnHandlePolicyForceOverrideDeletesPolicyOfPreviousOwner
 * @tc.desc: A force override deletes the policy of the admin that stored it before, so a policy
 *           has exactly one owner after the override.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyForceOverrideDeletesPolicyOfPreviousOwner, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        BuildAdminPolicyData(TEST_BUNDLE_NAME, TEST_POLICY_NAME, 1), "", DEFAULT_USER_ID), ERR_OK);

    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.currentAdminName = TEST_ADMIN_B;
    MessageParcel data;
    BuildSetPolicyParcel(data, true);
    ErrCode ret = plugin.OnHandlePolicy(BuildNewFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY), data,
        reply, policyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);

    std::string adminAPolicy;
    ASSERT_EQ(policyManager->GetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        adminAPolicy, DEFAULT_USER_ID), ERR_OK);
    std::map<std::string, ManagedBrowserPolicyType> adminAPolicies;
    DeserializeOrFail(adminAPolicy, adminAPolicies);
    EXPECT_EQ(CountName(adminAPolicies[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 0);
}

/**
 * @tc.name: TestOnHandlePolicyForceOverrideKeepsOtherPoliciesOfPreviousOwner
 * @tc.desc: A force override only removes the overridden policy from the previous owner, the
 *           other policies of that admin stay untouched.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyForceOverrideKeepsOtherPoliciesOfPreviousOwner,
    TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    std::map<std::string, ManagedBrowserPolicyType> adminPolicies;
    adminPolicies[TEST_BUNDLE_NAME].version = 1;
    adminPolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    adminPolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_OTHER_POLICY_NAME);
    std::string adminData;
    ASSERT_TRUE(ManagedBrowserPolicySerializer::GetInstance()->Serialize(adminPolicies, adminData));
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        adminData, "", DEFAULT_USER_ID), ERR_OK);

    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.currentAdminName = TEST_ADMIN_B;
    MessageParcel data;
    BuildSetPolicyParcel(data, true);
    ErrCode ret = plugin.OnHandlePolicy(BuildNewFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY), data,
        reply, policyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);

    std::string storedPolicy;
    ASSERT_EQ(policyManager->GetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        storedPolicy, DEFAULT_USER_ID), ERR_OK);
    std::map<std::string, ManagedBrowserPolicyType> storedPolicies;
    DeserializeOrFail(storedPolicy, storedPolicies);
    EXPECT_EQ(CountName(storedPolicies[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 0);
    EXPECT_EQ(CountName(storedPolicies[TEST_BUNDLE_NAME].policyNames, TEST_OTHER_POLICY_NAME), 1);
}

/**
 * @tc.name: TestOnHandlePolicyForceOverrideDeletesPolicyOfEveryOtherOwner
 * @tc.desc: A force override removes the policy from every other admin that stored it, so no
 *           stale copy of the policy is left behind.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyForceOverrideDeletesPolicyOfEveryOtherOwner, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        BuildAdminPolicyData(TEST_BUNDLE_NAME, TEST_POLICY_NAME, 1), "", DEFAULT_USER_ID), ERR_OK);
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_C, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        BuildAdminPolicyData(TEST_BUNDLE_NAME, TEST_POLICY_NAME, 1), "", DEFAULT_USER_ID), ERR_OK);

    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.currentAdminName = TEST_ADMIN_B;
    MessageParcel data;
    BuildSetPolicyParcel(data, true);
    ErrCode ret = plugin.OnHandlePolicy(BuildNewFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY), data,
        reply, policyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);

    for (const std::string &admin : {TEST_ADMIN_A, TEST_ADMIN_C}) {
        std::string storedPolicy;
        ASSERT_EQ(policyManager->GetPolicy(admin, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
            storedPolicy, DEFAULT_USER_ID), ERR_OK);
        std::map<std::string, ManagedBrowserPolicyType> storedPolicies;
        DeserializeOrFail(storedPolicy, storedPolicies);
        EXPECT_EQ(CountName(storedPolicies[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 0);
    }
}

/**
 * @tc.name: TestOnHandlePolicyForceOverrideDoesNotDeleteOwnPolicy
 * @tc.desc: A force override of an admin that already owns the policy keeps its own copy, only
 *           the policies of the other admins are deleted.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyForceOverrideDoesNotDeleteOwnPolicy, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_B, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        BuildAdminPolicyData(TEST_BUNDLE_NAME, TEST_POLICY_NAME, 1), "", DEFAULT_USER_ID), ERR_OK);

    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.currentAdminName = TEST_ADMIN_B;
    MessageParcel data;
    BuildSetPolicyParcel(data, true);
    ErrCode ret = plugin.OnHandlePolicy(BuildNewFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY), data,
        reply, policyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);

    std::string storedPolicy;
    ASSERT_EQ(policyManager->GetPolicy(TEST_ADMIN_B, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        storedPolicy, DEFAULT_USER_ID), ERR_OK);
    std::map<std::string, ManagedBrowserPolicyType> storedPolicies;
    DeserializeOrFail(storedPolicy, storedPolicies);
    EXPECT_EQ(CountName(storedPolicies[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 1);
}

/**
 * @tc.name: TestOnHandlePolicyForceOverrideKeepsCombinedPolicy
 * @tc.desc: Deleting the policy of the previous owner must not drop the combined policy of the
 *           other admins, so the shared policy stays available.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyForceOverrideKeepsCombinedPolicy, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    std::string adminData = BuildAdminPolicyData(TEST_BUNDLE_NAME, TEST_POLICY_NAME, 1);
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        adminData, "", DEFAULT_USER_ID), ERR_OK);
    ASSERT_EQ(policyManager->SetPolicy("", PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        "", adminData, DEFAULT_USER_ID), ERR_OK);

    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.currentAdminName = TEST_ADMIN_B;
    MessageParcel data;
    BuildSetPolicyParcel(data, true);
    ErrCode ret = plugin.OnHandlePolicy(BuildNewFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY), data,
        reply, policyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);

    std::string combinedPolicy;
    ASSERT_EQ(policyManager->GetPolicy("", PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        combinedPolicy, DEFAULT_USER_ID), ERR_OK);
    EXPECT_FALSE(combinedPolicy.empty());
}

/**
 * @tc.name: TestOnHandlePolicyForceOverrideBlocksOtherAdminAfterwards
 * @tc.desc: After admin B forced the override, admin A can no longer change it without force.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyForceOverrideBlocksOtherAdminAfterwards, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_B, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        BuildAdminPolicyData(TEST_BUNDLE_NAME, TEST_POLICY_NAME, 1), "", DEFAULT_USER_ID), ERR_OK);

    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.currentAdminName = TEST_ADMIN_A;
    MessageParcel data;
    BuildSetPolicyParcel(data, false);
    ErrCode ret = plugin.OnHandlePolicy(BuildNewFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY),
        data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);
    ASSERT_FALSE(policyData.isChanged);
}

/**
 * @tc.name: TestOnHandlePolicyWithoutOwnerIsAllowed
 * @tc.desc: A policy that no admin stored can still be set by any admin without force.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyWithoutOwnerIsAllowed, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.currentAdminName = TEST_ADMIN_B;
    MessageParcel data;
    BuildSetPolicyParcel(data, false);
    ErrCode ret = plugin.OnHandlePolicy(BuildNewFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY),
        data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(policyData.isChanged);
}

/**
 * @tc.name: TestOnHandlePolicyForceOverrideFailWithMissingFlag
 * @tc.desc: The browser policy entry point rejects a parcel that omits the force override flag.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyForceOverrideFailWithMissingFlag, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.currentAdminName = TEST_ADMIN_B;
    MessageParcel data;
    data.WriteString(TEST_BUNDLE_NAME);
    data.WriteString(TEST_POLICY_NAME);
    data.WriteString(TEST_POLICY_VALUE);
    ErrCode ret = plugin.OnHandlePolicy(BuildNewFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY), data,
        reply, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnHandlePolicyFailWithNonBoolForceFlag
 * @tc.desc: A non boolean force flag on the force override path is rejected.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyFailWithNonBoolForceFlag, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.currentAdminName = TEST_ADMIN_B;
    MessageParcel data;
    data.WriteString(TEST_BUNDLE_NAME);
    data.WriteString(TEST_POLICY_NAME);
    data.WriteString(TEST_POLICY_VALUE);
    data.WriteInt32(0);
    ErrCode ret = plugin.OnHandlePolicy(BuildFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY), data,
        reply, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnHandlePolicyRemovingPolicyDropsNameFromCurrentPolicy
 * @tc.desc: Clearing a policy value drops the policy name from the policy of the admin.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyRemovingPolicyDropsNameFromCurrentPolicy, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.currentAdminName = TEST_ADMIN_A;
    std::map<std::string, ManagedBrowserPolicyType> policies;
    policies[TEST_BUNDLE_NAME].version = 1;
    policies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    ASSERT_TRUE(ManagedBrowserPolicySerializer::GetInstance()->Serialize(policies, policyData.policyData));
    // The remove path rewrites the existing browser policy file, so the file must exist on disk.
    std::ofstream seed(URL);
    ASSERT_FALSE(seed.fail());
    seed << "\"" << TEST_POLICY_NAME << "\":" << TEST_POLICY_VALUE << std::endl;
    seed.close();
    MessageParcel data;
    data.WriteString(TEST_BUNDLE_NAME);
    data.WriteString(TEST_POLICY_NAME);
    data.WriteString("");
    data.WriteBool(false);
    ErrCode ret = plugin.OnHandlePolicy(BuildNewFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY),
        data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);

    std::map<std::string, ManagedBrowserPolicyType> currentPolicies;
    DeserializeOrFail(policyData.policyData, currentPolicies);
    EXPECT_EQ(CountName(currentPolicies[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 0);
}

/**
 * @tc.name: TestOnHandlePolicyForceOverrideKeepsMergeNameListWithoutDuplicates
 * @tc.desc: A force override skips the merged view conflict check and must not append the
 *           already listed policy name a second time to the merged view.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyForceOverrideKeepsMergeNameListWithoutDuplicates,
    TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        BuildAdminPolicyData(TEST_BUNDLE_NAME, TEST_POLICY_NAME, 1), "", DEFAULT_USER_ID), ERR_OK);

    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    mergePolicies[TEST_BUNDLE_NAME].version = 1;
    mergePolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    std::string mergeData;
    ASSERT_TRUE(ManagedBrowserPolicySerializer::GetInstance()->Serialize(mergePolicies, mergeData));
    policyData.mergePolicyData = mergeData;
    policyData.currentAdminName = TEST_ADMIN_B;
    MessageParcel data;
    BuildSetPolicyParcel(data, true);
    ErrCode ret = plugin.OnHandlePolicy(BuildNewFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY), data,
        reply, policyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);

    std::map<std::string, ManagedBrowserPolicyType> result;
    DeserializeOrFail(policyData.mergePolicyData, result);
    EXPECT_EQ(CountName(result[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 1);
}

/**
 * @tc.name: TestOnHandlePolicyForceOverrideAppendsUnlistedNameToMergeView
 * @tc.desc: A force override appends the policy name to the merged view when the other
 *           admin did not list it yet.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyForceOverrideAppendsUnlistedNameToMergeView,
    TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    mergePolicies[TEST_BUNDLE_NAME].version = 1;
    std::string mergeData;
    ASSERT_TRUE(ManagedBrowserPolicySerializer::GetInstance()->Serialize(mergePolicies, mergeData));
    policyData.mergePolicyData = mergeData;
    policyData.currentAdminName = TEST_ADMIN_B;
    MessageParcel data;
    BuildSetPolicyParcel(data, true);
    ErrCode ret = plugin.OnHandlePolicy(BuildNewFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY), data,
        reply, policyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);

    std::map<std::string, ManagedBrowserPolicyType> result;
    DeserializeOrFail(policyData.mergePolicyData, result);
    EXPECT_EQ(CountName(result[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 1);
}

/**
 * @tc.name: TestOnHandlePolicyEmptyAdminNameCannotChangeOwnedPolicy
 * @tc.desc: An empty admin name never matches the recorded owner, so a policy that has an
 *           owner must be rejected even though the caller identity is unknown.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyEmptyAdminNameCannotChangeOwnedPolicy, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        BuildAdminPolicyData(TEST_BUNDLE_NAME, TEST_POLICY_NAME, 1), "", DEFAULT_USER_ID), ERR_OK);

    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.currentAdminName = "";
    MessageParcel data;
    BuildSetPolicyParcel(data, false);
    ErrCode ret = plugin.OnHandlePolicy(BuildNewFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY),
        data, reply, policyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);
    EXPECT_FALSE(policyData.isChanged);
    EXPECT_TRUE(policyData.policyData.empty());
}

/**
 * @tc.name: TestOnHandlePolicyForceOverrideDoesNotDuplicateAcrossOtherBundles
 * @tc.desc: A force override on one bundle leaves an unrelated bundle in the merged view
 *           untouched.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyForceOverrideDoesNotDuplicateAcrossOtherBundles,
    TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    mergePolicies[TEST_BUNDLE_NAME].version = 1;
    mergePolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    mergePolicies[TEST_OTHER_BUNDLE_NAME].version = TEST_OTHER_BUNDLE_VERSION;
    mergePolicies[TEST_OTHER_BUNDLE_NAME].policyNames.push_back(TEST_OTHER_POLICY_NAME);
    std::string mergeData;
    ASSERT_TRUE(ManagedBrowserPolicySerializer::GetInstance()->Serialize(mergePolicies, mergeData));
    policyData.mergePolicyData = mergeData;
    policyData.currentAdminName = TEST_ADMIN_B;
    MessageParcel data;
    BuildSetPolicyParcel(data, true);
    ErrCode ret = plugin.OnHandlePolicy(BuildNewFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY), data,
        reply, policyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);

    std::map<std::string, ManagedBrowserPolicyType> result;
    DeserializeOrFail(policyData.mergePolicyData, result);
    EXPECT_EQ(CountName(result[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 1);
    EXPECT_EQ(CountName(result[TEST_OTHER_BUNDLE_NAME].policyNames, TEST_OTHER_POLICY_NAME), 1);
}

/**
 * @tc.name: TestOnHandlePolicyFailWithEmptyBundleNameOnForceOverride
 * @tc.desc: Parameter validation runs before the force flag is read, so an invalid bundle
 *           name is rejected even on the force override entry point.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyFailWithEmptyBundleNameOnForceOverride, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.currentAdminName = TEST_ADMIN_B;
    MessageParcel data;
    data.WriteString("");
    data.WriteString(TEST_POLICY_NAME);
    data.WriteString(TEST_POLICY_VALUE);
    data.WriteBool(true);
    ErrCode ret = plugin.OnHandlePolicy(BuildNewFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY), data,
        reply, policyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAM_ERROR);
    EXPECT_FALSE(policyData.isChanged);
}

/**
 * @tc.name: TestOnHandlePolicyFailWithInvalidBundleNameOnForceOverride
 * @tc.desc: A traversal bundle name is rejected on the force override entry point.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyFailWithInvalidBundleNameOnForceOverride, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.currentAdminName = TEST_ADMIN_B;
    MessageParcel data;
    data.WriteString("../invalid");
    data.WriteString(TEST_POLICY_NAME);
    data.WriteString(TEST_POLICY_VALUE);
    data.WriteBool(true);
    ErrCode ret = plugin.OnHandlePolicy(BuildNewFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY), data,
        reply, policyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAM_ERROR);
    EXPECT_FALSE(policyData.isChanged);
}

/**
 * @tc.name: TestOnHandlePolicyFailWithEmptyPolicyNameOnForceOverride
 * @tc.desc: An empty policy name is rejected on the force override entry point.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyFailWithEmptyPolicyNameOnForceOverride, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.currentAdminName = TEST_ADMIN_B;
    MessageParcel data;
    data.WriteString(TEST_BUNDLE_NAME);
    data.WriteString("");
    data.WriteString(TEST_POLICY_VALUE);
    data.WriteBool(true);
    ErrCode ret = plugin.OnHandlePolicy(BuildNewFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY), data,
        reply, policyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAM_ERROR);
    EXPECT_FALSE(policyData.isChanged);
}

/**
 * @tc.name: TestOnHandlePolicyForceOverrideFailWithFalseFlag
 * @tc.desc: A false force flag is a plain set, so the ownership check still rejects the
 *           request of an admin that does not own the item.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyForceOverrideFailWithFalseFlag, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        BuildAdminPolicyData(TEST_BUNDLE_NAME, TEST_POLICY_NAME, 1), "", DEFAULT_USER_ID), ERR_OK);

    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.currentAdminName = TEST_ADMIN_B;
    MessageParcel data;
    BuildSetPolicyParcel(data, false);
    ErrCode ret = plugin.OnHandlePolicy(BuildNewFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY),
        data, reply, policyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);
    EXPECT_FALSE(policyData.isChanged);
}

/**
 * @tc.name: TestOnHandlePolicyTrailingBoolEnablesForceOverride
 * @tc.desc: The force override flag is carried in the parcel of the shared browser policy
 *           interface, so a true flag takes over the item.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyTrailingBoolEnablesForceOverride, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.currentAdminName = TEST_ADMIN_B;
    MessageParcel data;
    data.WriteString(TEST_BUNDLE_NAME);
    data.WriteString(TEST_POLICY_NAME);
    data.WriteString(TEST_POLICY_VALUE);
    data.WriteBool(true);
    ErrCode ret = plugin.OnHandlePolicy(BuildNewFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY),
        data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    DeserializeOrFail(policyData.mergePolicyData, mergePolicies);
    EXPECT_EQ(CountName(mergePolicies[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 1);
}

/**
 * @tc.name: TestOnHandlePolicyFailWithMalformedPolicyData
 * @tc.desc: A malformed current policy blob is reported as a timeout error and the request
 *           is not applied, so a corrupted store cannot silently drop the policy.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyFailWithMalformedPolicyData, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.policyData = "not_a_json";
    policyData.currentAdminName = TEST_ADMIN_B;
    MessageParcel data;
    BuildSetPolicyParcel(data, false);
    ErrCode ret = plugin.OnHandlePolicy(BuildNewFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY),
        data, reply, policyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
    EXPECT_FALSE(policyData.isChanged);
    EXPECT_TRUE(policyData.policyData == "not_a_json");
}

/**
 * @tc.name: TestOnHandlePolicyFailWithMalformedMergePolicyData
 * @tc.desc: A malformed merged policy blob aborts the request before the ownership check,
 *           so no browser policy file write is attempted.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyFailWithMalformedMergePolicyData, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.mergePolicyData = "{\"broken\":";
    policyData.currentAdminName = TEST_ADMIN_B;
    MessageParcel data;
    BuildSetPolicyParcel(data, false);
    ErrCode ret = plugin.OnHandlePolicy(BuildNewFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY),
        data, reply, policyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
    EXPECT_FALSE(policyData.isChanged);
}

/**
 * @tc.name: TestOnHandlePolicyForceOverrideFailWithMalformedMergePolicyData
 * @tc.desc: The force override path also aborts on a malformed merged blob, so force
 *           override cannot be used to bypass the deserialization failure.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyForceOverrideFailWithMalformedMergePolicyData,
    TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.mergePolicyData = "invalid";
    policyData.currentAdminName = TEST_ADMIN_B;
    MessageParcel data;
    BuildSetPolicyParcel(data, true);
    ErrCode ret = plugin.OnHandlePolicy(BuildNewFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY),
        data, reply, policyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
    EXPECT_FALSE(policyData.isChanged);
}

/**
 * @tc.name: TestApplyPolicyToBrowserFileStripsNewLinesOnAdd
 * @tc.desc: Embedded newlines are stripped before the policy is appended to the browser
 *           policy file, so the file keeps one policy per line.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestApplyPolicyToBrowserFileStripsNewLinesOnAdd, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    std::map<std::string, ManagedBrowserPolicyType> policies;
    std::string policyValue = "\"line1\nline2\nline3\"";
    ErrCode ret = plugin.ApplyPolicyToBrowserFile(policies, TEST_BUNDLE_NAME, TEST_POLICY_NAME, policyValue, false);
    ASSERT_EQ(ret, ERR_OK);

    std::ifstream inFile(URL);
    ASSERT_FALSE(inFile.fail());
    std::string content;
    std::string line;
    int32_t lineCount = 0;
    while (std::getline(inFile, line)) {
        content += line;
        ++lineCount;
    }
    inFile.close();
    EXPECT_EQ(lineCount, 1);
    EXPECT_EQ(content, "\"test_policy_name\":\"line1line2line3\"");
}

/**
 * @tc.name: TestApplyPolicyToBrowserFileStripsNewLinesOnModify
 * @tc.desc: The modify path strips newlines as well, so an existing entry is rewritten as a
 *           single line instead of corrupting the browser policy file.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestApplyPolicyToBrowserFileStripsNewLinesOnModify, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    std::map<std::string, ManagedBrowserPolicyType> policies;
    std::ofstream seed(URL);
    ASSERT_FALSE(seed.fail());
    seed << "\"test_policy_name\":\"old\"" << std::endl;
    seed.close();

    ErrCode ret = plugin.ApplyPolicyToBrowserFile(policies, TEST_BUNDLE_NAME, TEST_POLICY_NAME,
        "\"new\nvalue\"", true);
    ASSERT_EQ(ret, ERR_OK);

    std::ifstream inFile(URL);
    ASSERT_FALSE(inFile.fail());
    std::string content;
    std::string line;
    int32_t lineCount = 0;
    while (std::getline(inFile, line)) {
        content += line;
        ++lineCount;
    }
    inFile.close();
    EXPECT_EQ(lineCount, 1);
    EXPECT_EQ(content, "\"test_policy_name\":\"newvalue\"");
}

/**
 * @tc.name: TestApplyPolicyToBrowserFileFailsWhenUrlInvalidOnModify
 * @tc.desc: The modify path validates the file path first and reports a system error
 *           instead of touching an unrelated location.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestApplyPolicyToBrowserFileFailsWhenUrlInvalidOnModify, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    std::map<std::string, ManagedBrowserPolicyType> policies;
    ErrCode ret = plugin.ApplyPolicyToBrowserFile(policies, "com.not.existed", TEST_POLICY_NAME,
        TEST_POLICY_VALUE, true);
    EXPECT_EQ(ret, EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestReadForceOverrideFlagAcceptsTrueFlag
 * @tc.desc: A true flag is accepted and reported to the caller.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestReadForceOverrideFlagAcceptsTrueFlag, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    MessageParcel data;
    data.WriteBool(true);
    bool isForceOverride = false;
    ErrCode ret = plugin.ReadForceOverrideFlag(data, isForceOverride);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(isForceOverride);
}

/**
 * @tc.name: TestReadForceOverrideFlagAcceptsFalseFlag
 * @tc.desc: An explicit false flag is a plain set, so the ownership check still applies.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestReadForceOverrideFlagAcceptsFalseFlag, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    MessageParcel data;
    data.WriteBool(false);
    bool isForceOverride = true;
    ErrCode ret = plugin.ReadForceOverrideFlag(data, isForceOverride);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(isForceOverride);
}

/**
 * @tc.name: TestReadForceOverrideFlagRejectsMissingFlag
 * @tc.desc: An exhausted parcel is a parameter error, so a truncated request never proceeds
 *           with a defaulted flag value.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestReadForceOverrideFlagRejectsMissingFlag, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    MessageParcel data;
    bool isForceOverride = true;
    ErrCode ret = plugin.ReadForceOverrideFlag(data, isForceOverride);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestReadForceOverrideFlagRejectsIntFlag
 * @tc.desc: A non bool flag is rejected, proving the parcel value type is validated.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestReadForceOverrideFlagRejectsIntFlag, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    MessageParcel data;
    data.WriteInt32(1);
    bool isForceOverride = false;
    ErrCode ret = plugin.ReadForceOverrideFlag(data, isForceOverride);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestReadForceOverrideFlagRejectsStringFlag
 * @tc.desc: A string flag is rejected, so a truthy looking string cannot enable force
 *           override by accident.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestReadForceOverrideFlagRejectsStringFlag, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    MessageParcel data;
    data.WriteString("true");
    bool isForceOverride = false;
    ErrCode ret = plugin.ReadForceOverrideFlag(data, isForceOverride);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestCheckPolicyOwnershipAllowedForForceOverride
 * @tc.desc: A force override is always allowed, even when another admin owns the item.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestCheckPolicyOwnershipAllowedForForceOverride, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        BuildAdminPolicyData(TEST_BUNDLE_NAME, TEST_POLICY_NAME, 1), "", DEFAULT_USER_ID), ERR_OK);

    ManagedBrowserPolicyPlugin plugin;
    EXPECT_EQ(plugin.CheckPolicyOwnership(TEST_BUNDLE_NAME, TEST_POLICY_NAME, TEST_ADMIN_B, true), ERR_OK);
}

/**
 * @tc.name: TestCheckPolicyOwnershipAllowedWhenNotStored
 * @tc.desc: A policy that no admin stored can be claimed by any admin.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestCheckPolicyOwnershipAllowedWhenNotStored, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    ManagedBrowserPolicyPlugin plugin;
    EXPECT_EQ(plugin.CheckPolicyOwnership(TEST_BUNDLE_NAME, TEST_POLICY_NAME, TEST_ADMIN_B, false), ERR_OK);
}

/**
 * @tc.name: TestCheckPolicyOwnershipRejectsOtherAdmin
 * @tc.desc: An admin that does not store the policy cannot change it without force override.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestCheckPolicyOwnershipRejectsOtherAdmin, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        BuildAdminPolicyData(TEST_BUNDLE_NAME, TEST_POLICY_NAME, 1), "", DEFAULT_USER_ID), ERR_OK);

    ManagedBrowserPolicyPlugin plugin;
    EXPECT_EQ(plugin.CheckPolicyOwnership(TEST_BUNDLE_NAME, TEST_POLICY_NAME, TEST_ADMIN_B, false),
        EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);
}

/**
 * @tc.name: TestCheckPolicyOwnershipRejectsEmptyAdminName
 * @tc.desc: An empty admin name never matches the owner of the policy, so the request is
 *           rejected instead of being applied to somebody else policy.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestCheckPolicyOwnershipRejectsEmptyAdminName, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        BuildAdminPolicyData(TEST_BUNDLE_NAME, TEST_POLICY_NAME, 1), "", DEFAULT_USER_ID), ERR_OK);

    ManagedBrowserPolicyPlugin plugin;
    EXPECT_EQ(plugin.CheckPolicyOwnership(TEST_BUNDLE_NAME, TEST_POLICY_NAME, "", false),
        EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);
}

/**
 * @tc.name: TestCheckPolicyOwnershipIgnoresOtherBundle
 * @tc.desc: A policy of another bundle does not block the requested item.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestCheckPolicyOwnershipIgnoresOtherBundle, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        BuildAdminPolicyData(TEST_OTHER_BUNDLE_NAME, TEST_OTHER_POLICY_NAME, 1), "", DEFAULT_USER_ID), ERR_OK);

    ManagedBrowserPolicyPlugin plugin;
    EXPECT_EQ(plugin.CheckPolicyOwnership(TEST_BUNDLE_NAME, TEST_POLICY_NAME, TEST_ADMIN_B, false), ERR_OK);
}

/**
 * @tc.name: TestFindPolicyOwnerFindsTheStoringAdmin
 * @tc.desc: The owner of a policy is the admin whose stored policy lists its name.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestFindPolicyOwnerFindsTheStoringAdmin, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        BuildAdminPolicyData(TEST_BUNDLE_NAME, TEST_POLICY_NAME, 1), "", DEFAULT_USER_ID), ERR_OK);

    ManagedBrowserPolicyPlugin plugin;
    std::string owner;
    EXPECT_TRUE(plugin.FindPolicyOwner(TEST_BUNDLE_NAME, TEST_POLICY_NAME, TEST_ADMIN_B, owner));
    EXPECT_EQ(owner, TEST_ADMIN_A);
}

/**
 * @tc.name: TestFindPolicyOwnerIgnoresTheOwnAdmin
 * @tc.desc: The admin that stores the policy is not reported as the owner of somebody else
 *           policy, so an admin never blocks itself.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestFindPolicyOwnerIgnoresTheOwnAdmin, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        BuildAdminPolicyData(TEST_BUNDLE_NAME, TEST_POLICY_NAME, 1), "", DEFAULT_USER_ID), ERR_OK);

    ManagedBrowserPolicyPlugin plugin;
    std::string owner;
    EXPECT_FALSE(plugin.FindPolicyOwner(TEST_BUNDLE_NAME, TEST_POLICY_NAME, TEST_ADMIN_A, owner));
    EXPECT_TRUE(owner.empty());
}

/**
 * @tc.name: TestFindPolicyOwnerSkipsBrokenAdmin
 * @tc.desc: An admin whose stored policy cannot be read is skipped, so one corrupted entry
 *           does not hide the owner of the policy.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestFindPolicyOwnerSkipsBrokenAdmin, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        BuildAdminPolicyData(TEST_BUNDLE_NAME, TEST_POLICY_NAME, 1), "", DEFAULT_USER_ID), ERR_OK);
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_C, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        "broken", "", DEFAULT_USER_ID), ERR_OK);

    ManagedBrowserPolicyPlugin plugin;
    std::string owner;
    EXPECT_TRUE(plugin.FindPolicyOwner(TEST_BUNDLE_NAME, TEST_POLICY_NAME, TEST_ADMIN_B, owner));
    EXPECT_EQ(owner, TEST_ADMIN_A);
}

/**
 * @tc.name: TestFindPolicyOwnerWithoutStoredAdmin
 * @tc.desc: When no admin stores the policy there is no owner of it.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestFindPolicyOwnerWithoutStoredAdmin, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    ManagedBrowserPolicyPlugin plugin;
    std::string owner;
    EXPECT_FALSE(plugin.FindPolicyOwner(TEST_BUNDLE_NAME, TEST_POLICY_NAME, TEST_ADMIN_B, owner));
    EXPECT_TRUE(owner.empty());
}

/**
 * @tc.name: TestRemovePolicyNameRemovesTheName
 * @tc.desc: The named policy is removed from the policy list of the bundle.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestRemovePolicyNameRemovesTheName, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    std::map<std::string, ManagedBrowserPolicyType> policies;
    policies[TEST_BUNDLE_NAME].version = 1;
    policies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    policies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_OTHER_POLICY_NAME);

    EXPECT_EQ(plugin.RemovePolicyName(policies, TEST_BUNDLE_NAME, TEST_POLICY_NAME), ERR_OK);
    EXPECT_EQ(CountName(policies[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 0);
    EXPECT_EQ(CountName(policies[TEST_BUNDLE_NAME].policyNames, TEST_OTHER_POLICY_NAME), 1);
}

/**
 * @tc.name: TestRemovePolicyNameOnUnknownBundleIsNoop
 * @tc.desc: A bundle that is not part of the policy is left untouched.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestRemovePolicyNameOnUnknownBundleIsNoop, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    std::map<std::string, ManagedBrowserPolicyType> policies;
    policies[TEST_BUNDLE_NAME].version = 1;
    policies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);

    EXPECT_EQ(plugin.RemovePolicyName(policies, TEST_OTHER_BUNDLE_NAME, TEST_POLICY_NAME), ERR_OK);
    EXPECT_EQ(CountName(policies[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 1);
}

/**
 * @tc.name: TestRemovePolicyNameOnUnknownNameIsNoop
 * @tc.desc: A policy name that the bundle does not list leaves the policy untouched.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestRemovePolicyNameOnUnknownNameIsNoop, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    std::map<std::string, ManagedBrowserPolicyType> policies;
    policies[TEST_BUNDLE_NAME].version = 1;
    policies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);

    EXPECT_EQ(plugin.RemovePolicyName(policies, TEST_BUNDLE_NAME, TEST_OTHER_POLICY_NAME), ERR_OK);
    EXPECT_EQ(CountName(policies[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 1);
}

/**
 * @tc.name: TestDeletePolicyOfOtherAdminsWithoutStoredAdmin
 * @tc.desc: When no admin stored the policy there is nothing to delete.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestDeletePolicyOfOtherAdminsWithoutStoredAdmin, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    ManagedBrowserPolicyPlugin plugin;
    EXPECT_EQ(plugin.DeletePolicyOfOtherAdmins(TEST_BUNDLE_NAME, TEST_POLICY_NAME, TEST_ADMIN_B), ERR_OK);
}

/**
 * @tc.name: TestDeletePolicyOfOtherAdminsSkipsBrokenAdmin
 * @tc.desc: An admin whose stored policy cannot be read is skipped, so one corrupted entry
 *           does not abort the override of the others.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestDeletePolicyOfOtherAdminsSkipsBrokenAdmin, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_C, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        "broken", "", DEFAULT_USER_ID), ERR_OK);
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        BuildAdminPolicyData(TEST_BUNDLE_NAME, TEST_POLICY_NAME, 1), "", DEFAULT_USER_ID), ERR_OK);

    ManagedBrowserPolicyPlugin plugin;
    EXPECT_EQ(plugin.DeletePolicyOfOtherAdmins(TEST_BUNDLE_NAME, TEST_POLICY_NAME, TEST_ADMIN_B), ERR_OK);

    std::string storedPolicy;
    ASSERT_EQ(policyManager->GetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        storedPolicy, DEFAULT_USER_ID), ERR_OK);
    std::map<std::string, ManagedBrowserPolicyType> storedPolicies;
    DeserializeOrFail(storedPolicy, storedPolicies);
    EXPECT_EQ(CountName(storedPolicies[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 0);
}

/**
 * @tc.name: TestDeserializePolicyFailWithBrokenCurrentPolicy
 * @tc.desc: A malformed current blob fails before the request is applied.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestDeserializePolicyFailWithBrokenCurrentPolicy, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    ManagedBrowserPolicyPlugin plugin;
    HandlePolicyData policyData;
    policyData.policyData = "broken";
    std::map<std::string, ManagedBrowserPolicyType> policies;
    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    EXPECT_EQ(plugin.DeserializePolicy(policyData, policies, mergePolicies),
        EdmReturnErrCode::EXECUTE_TIME_OUT);
    EXPECT_TRUE(mergePolicies.empty());
}

/**
 * @tc.name: TestDeserializePolicyEmptyInputStaysEmpty
 * @tc.desc: Empty current and merged blobs are valid and deserialize to empty maps, so a
 *           first policy write on a fresh device is not rejected.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestDeserializePolicyEmptyInputStaysEmpty, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    ManagedBrowserPolicyPlugin plugin;
    HandlePolicyData policyData;
    std::map<std::string, ManagedBrowserPolicyType> policies;
    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    ASSERT_EQ(plugin.DeserializePolicy(policyData, policies, mergePolicies), ERR_OK);
    EXPECT_TRUE(policies.empty());
    EXPECT_TRUE(mergePolicies.empty());
}

/**
 * @tc.name: TestDeserializePolicyKeepsPolicyNamesOfLegacyBlob
 * @tc.desc: A blob that still carries the ownership field of the previous version is read
 *           with its policy names unchanged.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestDeserializePolicyKeepsPolicyNamesOfLegacyBlob, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    ManagedBrowserPolicyPlugin plugin;
    HandlePolicyData policyData;
    policyData.mergePolicyData = "{\"test_bundle_name\":{\"version\":1,\"policyNames\":[\"test_policy_name\"],"
        "\"ownership\":{\"test_policy_name\":{\"adminBundleName\":\"com.admin.a\",\"isForceOverride\":true}}}}";
    std::map<std::string, ManagedBrowserPolicyType> policies;
    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    ASSERT_EQ(plugin.DeserializePolicy(policyData, policies, mergePolicies), ERR_OK);
    EXPECT_EQ(CountName(mergePolicies[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 1);
}

/**
 * @tc.name: TestGetOthersMergePolicyDataCombinesOtherAdmins
 * @tc.desc: The merged view rebuilt from other admins carries the policy names of all of
 *           them, the policy of the calling admin is left out.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestGetOthersMergePolicyDataCombinesOtherAdmins, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        BuildAdminPolicyData(TEST_BUNDLE_NAME, TEST_POLICY_NAME, 1), "", DEFAULT_USER_ID), ERR_OK);
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_C, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        BuildAdminPolicyData(TEST_OTHER_BUNDLE_NAME, TEST_OTHER_POLICY_NAME, 1), "", DEFAULT_USER_ID), ERR_OK);

    ManagedBrowserPolicyPlugin plugin;
    std::string othersMergePolicyData;
    ASSERT_EQ(plugin.GetOthersMergePolicyData(TEST_ADMIN_B, DEFAULT_USER_ID, othersMergePolicyData), ERR_OK);

    std::map<std::string, ManagedBrowserPolicyType> mergeData;
    DeserializeOrFail(othersMergePolicyData, mergeData);
    EXPECT_EQ(CountName(mergeData[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 1);
    EXPECT_EQ(CountName(mergeData[TEST_OTHER_BUNDLE_NAME].policyNames, TEST_OTHER_POLICY_NAME), 1);
}

/**
 * @tc.name: TestGetOthersMergePolicyDataExcludesTheCallingAdmin
 * @tc.desc: The merged view does not contain the policy of the calling admin, so the admin
 *           does not see its own policy twice.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestGetOthersMergePolicyDataExcludesTheCallingAdmin, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        BuildAdminPolicyData(TEST_BUNDLE_NAME, TEST_POLICY_NAME, 1), "", DEFAULT_USER_ID), ERR_OK);

    ManagedBrowserPolicyPlugin plugin;
    std::string othersMergePolicyData;
    ASSERT_EQ(plugin.GetOthersMergePolicyData(TEST_ADMIN_A, DEFAULT_USER_ID, othersMergePolicyData), ERR_OK);

    std::map<std::string, ManagedBrowserPolicyType> mergeData;
    DeserializeOrFail(othersMergePolicyData, mergeData);
    EXPECT_EQ(CountName(mergeData[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 0);
}

/**
 * @tc.name: TestGetOthersMergePolicyDataEmptyWhenNoAdminData
 * @tc.desc: Without any stored admin the merged view stays empty.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestGetOthersMergePolicyDataEmptyWhenNoAdminData, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    ManagedBrowserPolicyPlugin plugin;
    std::string othersMergePolicyData;
    ASSERT_EQ(plugin.GetOthersMergePolicyData(TEST_ADMIN_B, DEFAULT_USER_ID, othersMergePolicyData), ERR_OK);
    EXPECT_TRUE(othersMergePolicyData.empty());
}

/**
 * @tc.name: TestGetOthersMergePolicyDataEmptyWhenOnlySelfAdmin
 * @tc.desc: When the calling admin is the only one that stored something the merged view is
 *           empty, there is no other policy to report.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestGetOthersMergePolicyDataEmptyWhenOnlySelfAdmin, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_B, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        BuildAdminPolicyData(TEST_BUNDLE_NAME, TEST_POLICY_NAME, 1), "", DEFAULT_USER_ID), ERR_OK);

    ManagedBrowserPolicyPlugin plugin;
    std::string othersMergePolicyData;
    ASSERT_EQ(plugin.GetOthersMergePolicyData(TEST_ADMIN_B, DEFAULT_USER_ID, othersMergePolicyData), ERR_OK);
    EXPECT_TRUE(othersMergePolicyData.empty());
}

/**
 * @tc.name: TestMergeAdminPoliciesCombinesSeveralAdmins
 * @tc.desc: The policy names of several admins are combined into one merged view.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestMergeAdminPoliciesCombinesSeveralAdmins, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    AdminValueItemsMap adminValues;
    adminValues[TEST_ADMIN_A] = BuildAdminPolicyData(TEST_BUNDLE_NAME, TEST_POLICY_NAME, 1);
    adminValues[TEST_ADMIN_C] = BuildAdminPolicyData(TEST_BUNDLE_NAME, TEST_OTHER_POLICY_NAME, 1);

    std::map<std::string, ManagedBrowserPolicyType> mergeData;
    ASSERT_EQ(plugin.MergeAdminPolicies(adminValues, mergeData), ERR_OK);
    EXPECT_EQ(CountName(mergeData[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 1);
    EXPECT_EQ(CountName(mergeData[TEST_BUNDLE_NAME].policyNames, TEST_OTHER_POLICY_NAME), 1);
}

/**
 * @tc.name: TestMergeAdminPoliciesKeepsLowerVersionOfLaterAdmin
 * @tc.desc: The version of the merged view is the highest version that an admin stored.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestMergeAdminPoliciesKeepsLowerVersionOfLaterAdmin, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    AdminValueItemsMap adminValues;
    adminValues[TEST_ADMIN_A] = BuildAdminPolicyData(TEST_BUNDLE_NAME, TEST_POLICY_NAME, TEST_FIRST_ADMIN_VERSION);
    adminValues[TEST_ADMIN_C] = BuildAdminPolicyData(TEST_BUNDLE_NAME, TEST_POLICY_NAME, TEST_SECOND_ADMIN_VERSION);

    std::map<std::string, ManagedBrowserPolicyType> mergeData;
    ASSERT_EQ(plugin.MergeAdminPolicies(adminValues, mergeData), ERR_OK);
    EXPECT_EQ(mergeData[TEST_BUNDLE_NAME].version, TEST_FIRST_ADMIN_VERSION);
}

/**
 * @tc.name: TestMergeAdminPoliciesKeepsDuplicateNameOfTwoAdmins
 * @tc.desc: Two admins that stored the same policy name produce one merged entry that keeps
 *           the name once.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestMergeAdminPoliciesKeepsDuplicateNameOfTwoAdmins, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    AdminValueItemsMap adminValues;
    adminValues[TEST_ADMIN_A] = BuildAdminPolicyData(TEST_BUNDLE_NAME, TEST_POLICY_NAME, 1);
    adminValues[TEST_ADMIN_C] = BuildAdminPolicyData(TEST_BUNDLE_NAME, TEST_POLICY_NAME, 1);

    std::map<std::string, ManagedBrowserPolicyType> mergeData;
    ASSERT_EQ(plugin.MergeAdminPolicies(adminValues, mergeData), ERR_OK);
    EXPECT_EQ(CountName(mergeData[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 2);
}

/**
 * @tc.name: TestMergeAdminPoliciesFailsWithBrokenAdminData
 * @tc.desc: A malformed admin blob makes the merged view fail instead of reporting a
 *           partially merged state.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestMergeAdminPoliciesFailsWithBrokenAdminData, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    AdminValueItemsMap adminValues;
    adminValues[TEST_ADMIN_A] = "broken";

    std::map<std::string, ManagedBrowserPolicyType> mergeData;
    EXPECT_EQ(plugin.MergeAdminPolicies(adminValues, mergeData), EdmReturnErrCode::EXECUTE_TIME_OUT);
}

/**
 * @tc.name: TestMergeAdminPoliciesSkipsEmptyAdminData
 * @tc.desc: An admin that stored nothing is skipped, so the merged view is still reported.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestMergeAdminPoliciesSkipsEmptyAdminData, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    AdminValueItemsMap adminValues;
    adminValues[TEST_ADMIN_A] = "";

    std::map<std::string, ManagedBrowserPolicyType> mergeData;
    EXPECT_EQ(plugin.MergeAdminPolicies(adminValues, mergeData), ERR_OK);
    EXPECT_TRUE(mergeData.empty());
}

/**
 * @tc.name: TestMergeAdminPoliciesOnEmptyAdminMapIsNoop
 * @tc.desc: Without any admin the merged view stays empty.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestMergeAdminPoliciesOnEmptyAdminMapIsNoop, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    std::map<std::string, ManagedBrowserPolicyType> mergeData;
    EXPECT_EQ(plugin.MergeAdminPolicies({}, mergeData), ERR_OK);
    EXPECT_TRUE(mergeData.empty());
}

/**
 * @tc.name: TestMergeAdminPoliciesCombinesDifferentBundles
 * @tc.desc: The bundles of the admins are merged independently of each other.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestMergeAdminPoliciesCombinesDifferentBundles, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    AdminValueItemsMap adminValues;
    adminValues[TEST_ADMIN_A] = BuildAdminPolicyData(TEST_BUNDLE_NAME, TEST_POLICY_NAME, 1);
    adminValues[TEST_ADMIN_C] = BuildAdminPolicyData(TEST_OTHER_BUNDLE_NAME, TEST_OTHER_POLICY_NAME, 1);

    std::map<std::string, ManagedBrowserPolicyType> mergeData;
    ASSERT_EQ(plugin.MergeAdminPolicies(adminValues, mergeData), ERR_OK);
    EXPECT_EQ(mergeData.size(), 2);
    EXPECT_EQ(CountName(mergeData[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 1);
    EXPECT_EQ(CountName(mergeData[TEST_OTHER_BUNDLE_NAME].policyNames, TEST_OTHER_POLICY_NAME), 1);
}

/**
 * @tc.name: TestUpdateCurrentAndMergePolicyCopiesNewBundleIntoMergeView
 * @tc.desc: A bundle that the merged view does not know yet is added to it.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestUpdateCurrentAndMergePolicyCopiesNewBundleIntoMergeView, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    std::map<std::string, ManagedBrowserPolicyType> policies;
    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    ManagedBrowserPolicyPlugin::ManagedBrowserPolicyRequest request;
    request.bundleName = TEST_BUNDLE_NAME;
    request.policyName = TEST_POLICY_NAME;
    request.policyValue = TEST_POLICY_VALUE;

    ASSERT_EQ(plugin.UpdateCurrentAndMergePolicy(policies, mergePolicies, request), ERR_OK);
    EXPECT_EQ(CountName(mergePolicies[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 1);
}

/**
 * @tc.name: TestUpdateCurrentAndMergePolicyRemovesNameFromCurrentOnly
 * @tc.desc: Clearing a policy value drops the name from the policy of the admin, the merged
 *           view keeps the name that the other admins stored.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestUpdateCurrentAndMergePolicyRemovesNameFromCurrentOnly, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    std::map<std::string, ManagedBrowserPolicyType> policies;
    policies[TEST_BUNDLE_NAME].version = 1;
    policies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    ManagedBrowserPolicyPlugin::ManagedBrowserPolicyRequest request;
    request.bundleName = TEST_BUNDLE_NAME;
    request.policyName = TEST_POLICY_NAME;
    request.policyValue = "";

    ASSERT_EQ(plugin.UpdateCurrentAndMergePolicy(policies, mergePolicies, request), ERR_OK);
    EXPECT_EQ(CountName(policies[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 0);
}

/**
 * @tc.name: TestUpdateCurrentAndMergePolicyKeepsNameWhenValueNotEmpty
 * @tc.desc: A policy that is written again keeps its name in the policy of the admin.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestUpdateCurrentAndMergePolicyKeepsNameWhenValueNotEmpty, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    std::map<std::string, ManagedBrowserPolicyType> policies;
    policies[TEST_BUNDLE_NAME].version = 1;
    policies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    ManagedBrowserPolicyPlugin::ManagedBrowserPolicyRequest request;
    request.bundleName = TEST_BUNDLE_NAME;
    request.policyName = TEST_POLICY_NAME;
    request.policyValue = TEST_POLICY_VALUE;

    ASSERT_EQ(plugin.UpdateCurrentAndMergePolicy(policies, mergePolicies, request), ERR_OK);
    EXPECT_EQ(CountName(policies[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 1);
}

/**
 * @tc.name: TestUpdateCurrentAndMergePolicyKeepsOtherBundleUntouched
 * @tc.desc: A bundle that the request does not address keeps its policy names.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestUpdateCurrentAndMergePolicyKeepsOtherBundleUntouched, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    std::map<std::string, ManagedBrowserPolicyType> policies;
    policies[TEST_BUNDLE_NAME].version = 1;
    policies[TEST_OTHER_BUNDLE_NAME].version = TEST_OTHER_BUNDLE_VERSION;
    policies[TEST_OTHER_BUNDLE_NAME].policyNames.push_back(TEST_OTHER_POLICY_NAME);
    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    ManagedBrowserPolicyPlugin::ManagedBrowserPolicyRequest request;
    request.bundleName = TEST_BUNDLE_NAME;
    request.policyName = TEST_POLICY_NAME;
    request.policyValue = TEST_POLICY_VALUE;

    ASSERT_EQ(plugin.UpdateCurrentAndMergePolicy(policies, mergePolicies, request), ERR_OK);
    EXPECT_EQ(CountName(policies[TEST_OTHER_BUNDLE_NAME].policyNames, TEST_OTHER_POLICY_NAME), 1);
}

/**
 * @tc.name: TestOnHandlePolicyForceOverrideWithEmptyAdminName
 * @tc.desc: A force override of an unknown caller still takes the policy over, so a request
 *           without a known admin is not blocked by the ownership of somebody else.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyForceOverrideWithEmptyAdminName, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        BuildAdminPolicyData(TEST_BUNDLE_NAME, TEST_POLICY_NAME, 1), "", DEFAULT_USER_ID), ERR_OK);

    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.currentAdminName = "";
    MessageParcel data;
    BuildSetPolicyParcel(data, true);
    ErrCode ret = plugin.OnHandlePolicy(BuildNewFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY),
        data, reply, policyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(policyData.isChanged);
}

/**
 * @tc.name: TestOnHandlePolicyLegacyCodeWithoutFlagSucceeds
 * @tc.desc: A legacy caller sends the old parcel that ends after the policy value. The legacy
 *           interface code must not read a force override flag, so the request is applied and
 *           the policy name is recorded in the policy of the admin.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyLegacyCodeWithoutFlagSucceeds, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.currentAdminName = TEST_ADMIN_B;
    MessageParcel data;
    BuildLegacySetPolicyParcel(data);
    ErrCode ret = plugin.OnHandlePolicy(BuildFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY), data,
        reply, policyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_TRUE(policyData.isChanged);

    std::map<std::string, ManagedBrowserPolicyType> currentPolicies;
    DeserializeOrFail(policyData.policyData, currentPolicies);
    EXPECT_EQ(CountName(currentPolicies[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 1);
}

/**
 * @tc.name: TestOnHandlePolicyLegacyCodeRejectsPolicyOfAnotherAdmin
 * @tc.desc: The legacy interface keeps the original conflict semantics: a policy name that the
 *           merged view already lists is rejected with a parameter error, so an old caller
 *           cannot silently overwrite the policy of another admin.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyLegacyCodeRejectsPolicyOfAnotherAdmin, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        BuildAdminPolicyData(TEST_BUNDLE_NAME, TEST_POLICY_NAME, 1), "", DEFAULT_USER_ID), ERR_OK);

    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.currentAdminName = TEST_ADMIN_B;
    // The service hands the merged view of the other admins over to the plugin.
    policyData.mergePolicyData = BuildAdminPolicyData(TEST_BUNDLE_NAME, TEST_POLICY_NAME, 1);
    // A pre-existing blob of the calling admin must survive the rejected request untouched.
    policyData.policyData = BuildAdminPolicyData(TEST_OTHER_BUNDLE_NAME, TEST_OTHER_POLICY_NAME, 1);
    std::string policyDataBefore = policyData.policyData;
    MessageParcel data;
    BuildLegacySetPolicyParcel(data);
    ErrCode ret = plugin.OnHandlePolicy(BuildFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY), data,
        reply, policyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAM_ERROR);
    EXPECT_FALSE(policyData.isChanged);
    EXPECT_EQ(policyData.policyData, policyDataBefore);
}

/**
 * @tc.name: TestOnHandlePolicyLegacyCodeIgnoresTrailingBool
 * @tc.desc: The legacy interface code never reads the trailing force override flag, so a parcel
 *           that happens to carry one still hits the original conflict check and the policy of
 *           the other admin is not deleted.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyLegacyCodeIgnoresTrailingBool, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        BuildAdminPolicyData(TEST_BUNDLE_NAME, TEST_POLICY_NAME, 1), "", DEFAULT_USER_ID), ERR_OK);

    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.currentAdminName = TEST_ADMIN_B;
    policyData.mergePolicyData = BuildAdminPolicyData(TEST_BUNDLE_NAME, TEST_POLICY_NAME, 1);
    MessageParcel data;
    BuildSetPolicyParcel(data, true);
    ErrCode ret = plugin.OnHandlePolicy(BuildFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY), data,
        reply, policyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAM_ERROR);
    EXPECT_FALSE(policyData.isChanged);

    std::string adminAPolicy;
    ASSERT_EQ(policyManager->GetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        adminAPolicy, DEFAULT_USER_ID), ERR_OK);
    std::map<std::string, ManagedBrowserPolicyType> adminAPolicies;
    DeserializeOrFail(adminAPolicy, adminAPolicies);
    EXPECT_EQ(CountName(adminAPolicies[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 1);
}

/**
 * @tc.name: TestOnHandlePolicyNewCodeWithTrueFlagTakesOwnership
 * @tc.desc: The new interface code reads the force override flag, so a true flag takes the
 *           policy over from the admin that stored it before.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyNewCodeWithTrueFlagTakesOwnership, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        BuildAdminPolicyData(TEST_BUNDLE_NAME, TEST_POLICY_NAME, 1), "", DEFAULT_USER_ID), ERR_OK);

    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.currentAdminName = TEST_ADMIN_B;
    MessageParcel data;
    BuildSetPolicyParcel(data, true);
    ErrCode ret = plugin.OnHandlePolicy(BuildNewFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY), data,
        reply, policyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_TRUE(policyData.isChanged);

    std::string adminAPolicy;
    ASSERT_EQ(policyManager->GetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        adminAPolicy, DEFAULT_USER_ID), ERR_OK);
    std::map<std::string, ManagedBrowserPolicyType> adminAPolicies;
    DeserializeOrFail(adminAPolicy, adminAPolicies);
    EXPECT_EQ(CountName(adminAPolicies[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 0);
}

/**
 * @tc.name: TestOnHandlePolicyNewCodeWithFalseFlagRejectsOtherAdmin
 * @tc.desc: The new interface code with a false flag is a plain set, so the ownership check
 *           rejects an admin that does not own the policy.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyNewCodeWithFalseFlagRejectsOtherAdmin, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        BuildAdminPolicyData(TEST_BUNDLE_NAME, TEST_POLICY_NAME, 1), "", DEFAULT_USER_ID), ERR_OK);

    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.currentAdminName = TEST_ADMIN_B;
    MessageParcel data;
    BuildSetPolicyParcel(data, false);
    ErrCode ret = plugin.OnHandlePolicy(BuildNewFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY), data,
        reply, policyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);
    EXPECT_FALSE(policyData.isChanged);
}

/**
 * @tc.name: TestOnHandlePolicyNewCodeFailsWithoutFlag
 * @tc.desc: The new interface code always reads the force override flag, so a parcel that ends
 *           after the policy value is a parameter error instead of a defaulted plain set.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyNewCodeFailsWithoutFlag, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.currentAdminName = TEST_ADMIN_B;
    MessageParcel data;
    BuildLegacySetPolicyParcel(data);
    ErrCode ret = plugin.OnHandlePolicy(BuildNewFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY), data,
        reply, policyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAM_ERROR);
    EXPECT_FALSE(policyData.isChanged);
}

/**
 * @tc.name: TestOnHandlePolicyNewCodeOwnerCanModifyOwnPolicy
 * @tc.desc: The new interface code with a false flag still allows the admin that stores the
 *           policy to update its own copy.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyNewCodeOwnerCanModifyOwnPolicy, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_B, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        BuildAdminPolicyData(TEST_BUNDLE_NAME, TEST_POLICY_NAME, 1), "", DEFAULT_USER_ID), ERR_OK);

    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.currentAdminName = TEST_ADMIN_B;
    MessageParcel data;
    BuildSetPolicyParcel(data, false);
    ErrCode ret = plugin.OnHandlePolicy(BuildNewFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY), data,
        reply, policyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_TRUE(policyData.isChanged);

    std::map<std::string, ManagedBrowserPolicyType> currentPolicies;
    DeserializeOrFail(policyData.policyData, currentPolicies);
    EXPECT_EQ(CountName(currentPolicies[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 1);
}

/**
 * @tc.name: TestOnHandlePolicyNewCodeWithoutOwnerIsAllowed
 * @tc.desc: The new interface code with a false flag is allowed when no admin stored the policy
 *           yet, so the first writer can claim it.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyNewCodeWithoutOwnerIsAllowed, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.currentAdminName = TEST_ADMIN_B;
    MessageParcel data;
    BuildSetPolicyParcel(data, false);
    ErrCode ret = plugin.OnHandlePolicy(BuildNewFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY), data,
        reply, policyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_TRUE(policyData.isChanged);

    std::map<std::string, ManagedBrowserPolicyType> currentPolicies;
    DeserializeOrFail(policyData.policyData, currentPolicies);
    EXPECT_EQ(CountName(currentPolicies[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 1);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
