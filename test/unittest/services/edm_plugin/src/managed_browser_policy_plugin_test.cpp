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
const std::string TEST_OTHER_BUNDLE_NAME = "other_bundle_name";
const std::string TEST_OTHER_POLICY_NAME = "other_policy_name";
constexpr int32_t TEST_OTHER_BUNDLE_VERSION = 2;
constexpr int32_t TEST_FIRST_ADMIN_VERSION = 7;
constexpr int32_t TEST_SECOND_ADMIN_VERSION = 2;
constexpr int32_t TEST_HIGHER_VERSION = 5;
constexpr int32_t TEST_MEDIUM_VERSION = 3;

namespace {
std::string BuildMergePolicyData(const std::string &ownerAdmin, bool isForceOverride, bool includeOwnership)
{
    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    mergePolicies[TEST_BUNDLE_NAME].version = 1;
    mergePolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    if (includeOwnership) {
        ManagedBrowserPolicyOwnership owner;
        owner.adminBundleName = ownerAdmin;
        owner.isForceOverride = isForceOverride;
        mergePolicies[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME] = owner;
    }
    std::string data;
    ManagedBrowserPolicySerializer::GetInstance()->Serialize(mergePolicies, data);
    return data;
}

std::string BuildTwoBundleMergePolicyData(const std::string &ownerAdmin)
{
    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    mergePolicies[TEST_BUNDLE_NAME].version = 1;
    mergePolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    if (!ownerAdmin.empty()) {
        ManagedBrowserPolicyOwnership owner;
        owner.adminBundleName = ownerAdmin;
        owner.isForceOverride = false;
        mergePolicies[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME] = owner;
    }
    mergePolicies[TEST_OTHER_BUNDLE_NAME].version = TEST_OTHER_BUNDLE_VERSION;
    mergePolicies[TEST_OTHER_BUNDLE_NAME].policyNames.push_back(TEST_OTHER_POLICY_NAME);
    std::string data;
    ManagedBrowserPolicySerializer::GetInstance()->Serialize(mergePolicies, data);
    return data;
}

std::uint32_t BuildFuncCode(EdmInterfaceCode policyCode)
{
    return POLICY_FUNC_CODE(static_cast<std::uint32_t>(FuncOperateType::SET), policyCode);
}

void BuildSetPolicyParcel(MessageParcel &data, bool isForceOverride)
{
    data.WriteString(TEST_BUNDLE_NAME);
    data.WriteString(TEST_POLICY_NAME);
    data.WriteString(TEST_POLICY_VALUE);
    data.WriteBool(isForceOverride);
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
 * @tc.name: TestOnHandlePolicySucForAddPolicy
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
 * @tc.desc: Admin B cannot change a policy owned by admin A without force override.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyOwnershipTakenByAdminA, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.mergePolicyData = BuildMergePolicyData(TEST_ADMIN_A, false, true);
    policyData.currentAdminName = TEST_ADMIN_B;
    MessageParcel data;
    BuildSetPolicyParcel(data, false);
    ErrCode ret = plugin.OnHandlePolicy(BuildFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY),
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
    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.mergePolicyData = BuildMergePolicyData(TEST_ADMIN_A, false, true);
    policyData.currentAdminName = TEST_ADMIN_A;
    MessageParcel data;
    BuildSetPolicyParcel(data, false);
    ErrCode ret = plugin.OnHandlePolicy(BuildFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY),
        data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(policyData.isChanged);
}

/**
 * @tc.name: TestOnHandlePolicyForceOverrideTakesOwnership
 * @tc.desc: Admin B can take over a policy owned by admin A by using force override.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyForceOverrideTakesOwnership, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.mergePolicyData = BuildMergePolicyData(TEST_ADMIN_A, false, true);
    policyData.currentAdminName = TEST_ADMIN_B;
    MessageParcel data;
    BuildSetPolicyParcel(data, true);
    ErrCode ret = plugin.OnHandlePolicy(BuildFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY), data,
        reply, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(policyData.isChanged);

    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    ASSERT_TRUE(ManagedBrowserPolicySerializer::GetInstance()->Deserialize(policyData.mergePolicyData, mergePolicies));
    auto owner = mergePolicies[TEST_BUNDLE_NAME].ownership.find(TEST_POLICY_NAME);
    ASSERT_TRUE(owner != mergePolicies[TEST_BUNDLE_NAME].ownership.end());
    ASSERT_TRUE(owner->second.adminBundleName == TEST_ADMIN_B);
    ASSERT_TRUE(owner->second.isForceOverride);
}

/**
 * @tc.name: TestOnHandlePolicyForceOverrideBlocksOtherAdminAfterwards
 * @tc.desc: After admin B forced the override, admin A can no longer change it without force.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyForceOverrideBlocksOtherAdminAfterwards, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.mergePolicyData = BuildMergePolicyData(TEST_ADMIN_B, true, true);
    policyData.currentAdminName = TEST_ADMIN_A;
    MessageParcel data;
    BuildSetPolicyParcel(data, false);
    ErrCode ret = plugin.OnHandlePolicy(BuildFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY),
        data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);
    ASSERT_FALSE(policyData.isChanged);
}

/**
 * @tc.name: TestOnHandlePolicyWithoutOwnerIsAllowed
 * @tc.desc: A policy with no recorded owner can still be set by any admin without force.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyWithoutOwnerIsAllowed, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.mergePolicyData = BuildMergePolicyData("", false, false);
    policyData.currentAdminName = TEST_ADMIN_B;
    MessageParcel data;
    BuildSetPolicyParcel(data, false);
    ErrCode ret = plugin.OnHandlePolicy(BuildFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY),
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
    ErrCode ret = plugin.OnHandlePolicy(BuildFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY), data,
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
 * @tc.name: TestOnHandlePolicyRemovingPolicyClearsOwnership
 * @tc.desc: Clearing a policy value also clears the ownership record.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyRemovingPolicyClearsOwnership, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.mergePolicyData = BuildMergePolicyData(TEST_ADMIN_A, false, true);
    policyData.currentAdminName = TEST_ADMIN_A;
    MessageParcel data;
    data.WriteString(TEST_BUNDLE_NAME);
    data.WriteString(TEST_POLICY_NAME);
    data.WriteString("");
    data.WriteBool(false);
    ErrCode ret = plugin.OnHandlePolicy(BuildFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY),
        data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);

    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    ASSERT_TRUE(ManagedBrowserPolicySerializer::GetInstance()->Deserialize(policyData.mergePolicyData, mergePolicies));
    ASSERT_TRUE(mergePolicies[TEST_BUNDLE_NAME].ownership.find(TEST_POLICY_NAME) ==
        mergePolicies[TEST_BUNDLE_NAME].ownership.end());
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
    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.mergePolicyData = BuildMergePolicyData(TEST_ADMIN_A, false, true);
    policyData.currentAdminName = TEST_ADMIN_B;
    MessageParcel data;
    BuildSetPolicyParcel(data, true);
    ErrCode ret = plugin.OnHandlePolicy(BuildFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY), data,
        reply, policyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);

    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    DeserializeOrFail(policyData.mergePolicyData, mergePolicies);
    EXPECT_EQ(CountName(mergePolicies[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 1);
    EXPECT_EQ(mergePolicies[TEST_BUNDLE_NAME].version, 2);
    EXPECT_TRUE(mergePolicies[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME].isForceOverride);
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
    ErrCode ret = plugin.OnHandlePolicy(BuildFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY), data,
        reply, policyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);

    std::map<std::string, ManagedBrowserPolicyType> result;
    DeserializeOrFail(policyData.mergePolicyData, result);
    EXPECT_EQ(CountName(result[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 1);
    EXPECT_EQ(result[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME].adminBundleName, TEST_ADMIN_B);
}

/**
 * @tc.name: TestOnHandlePolicyEmptyAdminNameCannotChangeOwnedPolicy
 * @tc.desc: An empty admin name never matches the recorded owner, so a policy that has an
 *           owner must be rejected even though the caller identity is unknown.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyEmptyAdminNameCannotChangeOwnedPolicy, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.mergePolicyData = BuildMergePolicyData(TEST_ADMIN_A, false, true);
    policyData.currentAdminName = "";
    MessageParcel data;
    BuildSetPolicyParcel(data, false);
    ErrCode ret = plugin.OnHandlePolicy(BuildFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY),
        data, reply, policyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);
    EXPECT_FALSE(policyData.isChanged);
    EXPECT_TRUE(policyData.policyData.empty());
    EXPECT_TRUE(policyData.mergePolicyData == BuildMergePolicyData(TEST_ADMIN_A, false, true));
}

/**
 * @tc.name: TestOnHandlePolicyOwnerUpdateKeepsForceOverrideMarker
 * @tc.desc: An owner that updates its own policy with a plain set clears the force
 *           override marker and keeps itself as the owner.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyOwnerUpdateKeepsForceOverrideMarker, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.mergePolicyData = BuildMergePolicyData(TEST_ADMIN_B, true, true);
    policyData.currentAdminName = TEST_ADMIN_B;
    MessageParcel data;
    BuildSetPolicyParcel(data, false);
    ErrCode ret = plugin.OnHandlePolicy(BuildFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY),
        data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);

    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    DeserializeOrFail(policyData.mergePolicyData, mergePolicies);
    auto owner = mergePolicies[TEST_BUNDLE_NAME].ownership.find(TEST_POLICY_NAME);
    ASSERT_NE(owner, mergePolicies[TEST_BUNDLE_NAME].ownership.end());
    EXPECT_EQ(owner->second.adminBundleName, TEST_ADMIN_B);
    EXPECT_FALSE(owner->second.isForceOverride);
}

/**
 * @tc.name: TestOnHandlePolicyForceOverrideDoesNotDuplicateAcrossOtherBundles
 * @tc.desc: A force override on one bundle leaves an unrelated bundle in the merged view
 *           untouched, and the ownership record is only written for the target bundle.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyForceOverrideDoesNotDuplicateAcrossOtherBundles,
    TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.mergePolicyData = BuildTwoBundleMergePolicyData(TEST_ADMIN_A);
    policyData.currentAdminName = TEST_ADMIN_B;
    MessageParcel data;
    BuildSetPolicyParcel(data, true);
    ErrCode ret = plugin.OnHandlePolicy(BuildFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY), data,
        reply, policyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);

    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    DeserializeOrFail(policyData.mergePolicyData, mergePolicies);
    EXPECT_EQ(CountName(mergePolicies[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 1);
    EXPECT_EQ(mergePolicies[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME].adminBundleName, TEST_ADMIN_B);
    EXPECT_TRUE(mergePolicies[TEST_OTHER_BUNDLE_NAME].ownership.empty());
    EXPECT_EQ(CountName(mergePolicies[TEST_OTHER_BUNDLE_NAME].policyNames, TEST_OTHER_POLICY_NAME), 1);
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
    ErrCode ret = plugin.OnHandlePolicy(BuildFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY), data,
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
    ErrCode ret = plugin.OnHandlePolicy(BuildFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY), data,
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
    ErrCode ret = plugin.OnHandlePolicy(BuildFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY), data,
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
    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.mergePolicyData = BuildMergePolicyData(TEST_ADMIN_A, false, true);
    policyData.currentAdminName = TEST_ADMIN_B;
    MessageParcel data;
    BuildSetPolicyParcel(data, false);
    ErrCode ret = plugin.OnHandlePolicy(BuildFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY), data,
        reply, policyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);
    EXPECT_FALSE(policyData.isChanged);
    EXPECT_TRUE(policyData.mergePolicyData == BuildMergePolicyData(TEST_ADMIN_A, false, true));
}

/**
 * @tc.name: TestOnHandlePolicyTrailingBoolEnablesForceOverride
 * @tc.desc: The force override flag is carried in the parcel of the shared browser policy
 *           interface, so a true flag takes over the item and is recorded as such.
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
    ErrCode ret = plugin.OnHandlePolicy(BuildFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY),
        data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    DeserializeOrFail(policyData.mergePolicyData, mergePolicies);
    ASSERT_TRUE(mergePolicies[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME].isForceOverride);
    EXPECT_EQ(mergePolicies[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME].adminBundleName, TEST_ADMIN_B);
}

/**
 * @tc.name: TestOnHandlePolicyFailWithMalformedPolicyData
 * @tc.desc: A malformed current policy blob is reported as a system error and the request
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
    ErrCode ret = plugin.OnHandlePolicy(BuildFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY),
        data, reply, policyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::SYSTEM_ABNORMALLY);
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
    ErrCode ret = plugin.OnHandlePolicy(BuildFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY),
        data, reply, policyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::SYSTEM_ABNORMALLY);
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
    ErrCode ret = plugin.OnHandlePolicy(BuildFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY), data,
        reply, policyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::SYSTEM_ABNORMALLY);
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
 * @tc.desc: Force override short circuits the ownership check even when another admin owns
 *           the item, which is the documented escape hatch.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestCheckPolicyOwnershipAllowedForForceOverride, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    ManagedBrowserPolicyType mergedPolicy;
    ManagedBrowserPolicyOwnership owner;
    owner.adminBundleName = TEST_ADMIN_A;
    mergedPolicy.ownership[TEST_POLICY_NAME] = owner;

    EXPECT_EQ(plugin.CheckPolicyOwnership(mergedPolicy, TEST_POLICY_NAME, TEST_ADMIN_B, true), ERR_OK);
}

/**
 * @tc.name: TestCheckPolicyOwnershipAllowedWhenNotListed
 * @tc.desc: An ownership entry for a different policy does not block the requested item.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestCheckPolicyOwnershipAllowedWhenNotListed, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    ManagedBrowserPolicyType mergedPolicy;
    ManagedBrowserPolicyOwnership owner;
    owner.adminBundleName = TEST_ADMIN_A;
    mergedPolicy.ownership[TEST_OTHER_POLICY_NAME] = owner;

    EXPECT_EQ(plugin.CheckPolicyOwnership(mergedPolicy, TEST_POLICY_NAME, TEST_ADMIN_B, false), ERR_OK);
}

/**
 * @tc.name: TestCheckPolicyOwnershipRejectsOtherAdmin
 * @tc.desc: A policy owned by another admin is rejected for a plain set.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestCheckPolicyOwnershipRejectsOtherAdmin, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    ManagedBrowserPolicyType mergedPolicy;
    ManagedBrowserPolicyOwnership owner;
    owner.adminBundleName = TEST_ADMIN_A;
    mergedPolicy.ownership[TEST_POLICY_NAME] = owner;

    EXPECT_EQ(plugin.CheckPolicyOwnership(mergedPolicy, TEST_POLICY_NAME, TEST_ADMIN_B, false),
        EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);
}

/**
 * @tc.name: TestCheckPolicyOwnershipRejectsEmptyAdminName
 * @tc.desc: An unknown caller never matches the owner and is rejected.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestCheckPolicyOwnershipRejectsEmptyAdminName, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    ManagedBrowserPolicyType mergedPolicy;
    ManagedBrowserPolicyOwnership owner;
    owner.adminBundleName = "";
    mergedPolicy.ownership[TEST_POLICY_NAME] = owner;

    EXPECT_EQ(plugin.CheckPolicyOwnership(mergedPolicy, TEST_POLICY_NAME, "", false),
        EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);
}

/**
 * @tc.name: TestCheckPolicyOwnershipRejectsOwnerWithEmptyAdminName
 * @tc.desc: An ownership record that carries no admin name never matches a real caller, so
 *           the item stays blocked for everyone that does not force the override.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestCheckPolicyOwnershipRejectsOwnerWithEmptyAdminName, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    ManagedBrowserPolicyType mergedPolicy;
    ManagedBrowserPolicyOwnership owner;
    owner.adminBundleName = "";
    mergedPolicy.ownership[TEST_POLICY_NAME] = owner;

    EXPECT_EQ(plugin.CheckPolicyOwnership(mergedPolicy, TEST_POLICY_NAME, TEST_ADMIN_B, false),
        EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);
}

/**
 * @tc.name: TestCheckPolicyOwnershipRejectsEmptyAdminNameAgainstEmptyOwner
 * @tc.desc: A caller without an identity is still rejected when the recorded owner has no
 *           name either, because two empty identities are not the same admin.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestCheckPolicyOwnershipRejectsEmptyAdminNameAgainstEmptyOwner,
    TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    ManagedBrowserPolicyType mergedPolicy;
    ManagedBrowserPolicyOwnership owner;
    owner.adminBundleName = "";
    mergedPolicy.ownership[TEST_POLICY_NAME] = owner;

    EXPECT_EQ(plugin.CheckPolicyOwnership(mergedPolicy, TEST_POLICY_NAME, "", false),
        EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);
}

/**
 * @tc.name: TestCheckPolicyOwnershipAllowsWhenNoOwnershipRecorded
 * @tc.desc: An item that carries no ownership record at all is accepted, so the very first
 *           admin that writes it is not blocked by a record that does not exist.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestCheckPolicyOwnershipAllowsWhenNoOwnershipRecorded, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    ManagedBrowserPolicyType mergedPolicy;

    EXPECT_EQ(plugin.CheckPolicyOwnership(mergedPolicy, TEST_POLICY_NAME, TEST_ADMIN_B, false), ERR_OK);
}

/**
 * @tc.name: TestIsOwnedByAdminReturnsTrueForRecordedOwner
 * @tc.desc: The admin that is recorded as the owner of the item is recognised as its owner.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestIsOwnedByAdminReturnsTrueForRecordedOwner, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    ManagedBrowserPolicyType mergedPolicy;
    ManagedBrowserPolicyOwnership owner;
    owner.adminBundleName = TEST_ADMIN_A;
    owner.isForceOverride = true;
    mergedPolicy.ownership[TEST_POLICY_NAME] = owner;

    EXPECT_TRUE(plugin.IsOwnedByAdmin(mergedPolicy, TEST_POLICY_NAME, TEST_ADMIN_A));
}

/**
 * @tc.name: TestIsOwnedByAdminReturnsFalseForOtherAdmin
 * @tc.desc: An admin that is not the recorded owner is not recognised as the owner.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestIsOwnedByAdminReturnsFalseForOtherAdmin, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    ManagedBrowserPolicyType mergedPolicy;
    ManagedBrowserPolicyOwnership owner;
    owner.adminBundleName = TEST_ADMIN_A;
    mergedPolicy.ownership[TEST_POLICY_NAME] = owner;

    EXPECT_FALSE(plugin.IsOwnedByAdmin(mergedPolicy, TEST_POLICY_NAME, TEST_ADMIN_B));
}

/**
 * @tc.name: TestIsOwnedByAdminReturnsFalseForEmptyAdminName
 * @tc.desc: A caller without an identity is never the owner, even when the recorded owner
 *           carries an empty name as well.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestIsOwnedByAdminReturnsFalseForEmptyAdminName, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    ManagedBrowserPolicyType mergedPolicy;
    ManagedBrowserPolicyOwnership owner;
    owner.adminBundleName = "";
    mergedPolicy.ownership[TEST_POLICY_NAME] = owner;

    EXPECT_FALSE(plugin.IsOwnedByAdmin(mergedPolicy, TEST_POLICY_NAME, ""));
}

/**
 * @tc.name: TestIsOwnedByAdminReturnsFalseForUntrackedPolicy
 * @tc.desc: An item that carries no ownership record is owned by nobody.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestIsOwnedByAdminReturnsFalseForUntrackedPolicy, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    ManagedBrowserPolicyType mergedPolicy;
    ManagedBrowserPolicyOwnership owner;
    owner.adminBundleName = TEST_ADMIN_A;
    mergedPolicy.ownership[TEST_OTHER_POLICY_NAME] = owner;

    EXPECT_FALSE(plugin.IsOwnedByAdmin(mergedPolicy, TEST_POLICY_NAME, TEST_ADMIN_A));
}

/**
 * @tc.name: TestIsOwnedByAdminReturnsFalseForEmptyOwnershipMap
 * @tc.desc: An empty ownership map makes every item unowned.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestIsOwnedByAdminReturnsFalseForEmptyOwnershipMap, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    ManagedBrowserPolicyType mergedPolicy;

    EXPECT_FALSE(plugin.IsOwnedByAdmin(mergedPolicy, TEST_POLICY_NAME, TEST_ADMIN_A));
}

/**
 * @tc.name: TestUpdatePolicyOwnershipSetsOwnerAndMarker
 * @tc.desc: A non removed item records the calling admin together with the force marker.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestUpdatePolicyOwnershipSetsOwnerAndMarker, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    ManagedBrowserPolicyType mergedPolicy;
    plugin.UpdatePolicyOwnership(mergedPolicy, TEST_POLICY_NAME, TEST_ADMIN_B, true, false);

    ASSERT_EQ(mergedPolicy.ownership.size(), 1);
    EXPECT_EQ(mergedPolicy.ownership[TEST_POLICY_NAME].adminBundleName, TEST_ADMIN_B);
    EXPECT_TRUE(mergedPolicy.ownership[TEST_POLICY_NAME].isForceOverride);
}

/**
 * @tc.name: TestUpdatePolicyOwnershipOverwritesPreviousOwner
 * @tc.desc: A repeated write replaces the previous owner record instead of keeping both.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestUpdatePolicyOwnershipOverwritesPreviousOwner, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    ManagedBrowserPolicyType mergedPolicy;
    ManagedBrowserPolicyOwnership first;
    first.adminBundleName = TEST_ADMIN_A;
    first.isForceOverride = true;
    mergedPolicy.ownership[TEST_POLICY_NAME] = first;

    plugin.UpdatePolicyOwnership(mergedPolicy, TEST_POLICY_NAME, TEST_ADMIN_B, false, false);
    EXPECT_EQ(mergedPolicy.ownership.size(), 1);
    EXPECT_EQ(mergedPolicy.ownership[TEST_POLICY_NAME].adminBundleName, TEST_ADMIN_B);
    EXPECT_FALSE(mergedPolicy.ownership[TEST_POLICY_NAME].isForceOverride);
}

/**
 * @tc.name: TestUpdatePolicyOwnershipClearsOnRemove
 * @tc.desc: A removed item drops its ownership record, so the next admin may claim it.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestUpdatePolicyOwnershipClearsOnRemove, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    ManagedBrowserPolicyType mergedPolicy;
    ManagedBrowserPolicyOwnership owner;
    owner.adminBundleName = TEST_ADMIN_A;
    mergedPolicy.ownership[TEST_POLICY_NAME] = owner;
    mergedPolicy.ownership[TEST_OTHER_POLICY_NAME] = owner;

    plugin.UpdatePolicyOwnership(mergedPolicy, TEST_POLICY_NAME, TEST_ADMIN_A, false, true);
    EXPECT_EQ(mergedPolicy.ownership.count(TEST_POLICY_NAME), 0);
    EXPECT_EQ(mergedPolicy.ownership.count(TEST_OTHER_POLICY_NAME), 1);
}

/**
 * @tc.name: TestUpdatePolicyOwnershipRemoveOnUntrackedItemIsNoop
 * @tc.desc: Removing an item that has no owner record does not create one.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestUpdatePolicyOwnershipRemoveOnUntrackedItemIsNoop, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    ManagedBrowserPolicyType mergedPolicy;
    plugin.UpdatePolicyOwnership(mergedPolicy, TEST_POLICY_NAME, TEST_ADMIN_B, true, true);
    EXPECT_TRUE(mergedPolicy.ownership.empty());
}

/**
 * @tc.name: TestDeserializeAndMigrateBackfillsOwnerFromStoredAdmin
 * @tc.desc: A merged blob written before ownership existed is backfilled from the admin
 *           store, so the pre-existing conflict protection survives the upgrade. The
 *           unparsable admin is skipped and an item nobody stores stays unowned.
 *           The backfill itself is driven through BackfillOwnership, because
 *           MigrateOwnershipIfNeeded is guarded by a process wide one shot flag and its
 *           execution therefore depends on the order the cases of this suite run in.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestDeserializeAndMigrateBackfillsOwnerFromStoredAdmin, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    std::map<std::string, ManagedBrowserPolicyType> storedPolicies;
    storedPolicies[TEST_BUNDLE_NAME].version = 1;
    storedPolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    storedPolicies[TEST_OTHER_BUNDLE_NAME].version = 1;
    storedPolicies[TEST_OTHER_BUNDLE_NAME].policyNames.push_back(TEST_OTHER_POLICY_NAME);
    std::string storedData;
    ASSERT_TRUE(ManagedBrowserPolicySerializer::GetInstance()->Serialize(storedPolicies, storedData));
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        storedData, storedData, DEFAULT_USER_ID), ERR_OK);
    policyManager->SetPolicy(TEST_ADMIN_B, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        "broken", "broken", DEFAULT_USER_ID);

    ManagedBrowserPolicyPlugin plugin;
    HandlePolicyData policyData;
    policyData.mergePolicyData = BuildTwoBundleMergePolicyData("");
    policyData.currentAdminName = "com.admin.c";
    std::map<std::string, ManagedBrowserPolicyType> policies;
    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    ASSERT_EQ(plugin.DeserializeAndMigrate(policyData, policies, mergePolicies), ERR_OK);

    EXPECT_TRUE(mergePolicies[TEST_BUNDLE_NAME].ownership.empty());
    EXPECT_TRUE(mergePolicies[TEST_OTHER_BUNDLE_NAME].ownership.empty());
    EXPECT_EQ(CountName(mergePolicies[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 1);

    plugin.BackfillOwnership(mergePolicies);
    ASSERT_EQ(mergePolicies[TEST_BUNDLE_NAME].ownership.size(), 1);
    EXPECT_EQ(mergePolicies[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME].adminBundleName, TEST_ADMIN_A);
    EXPECT_FALSE(mergePolicies[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME].isForceOverride);
    EXPECT_TRUE(mergePolicies[TEST_OTHER_BUNDLE_NAME].ownership.empty());

    EXPECT_EQ(plugin.CheckPolicyOwnership(mergePolicies[TEST_BUNDLE_NAME], TEST_POLICY_NAME,
        "com.admin.c", false), EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);
    EXPECT_EQ(plugin.CheckPolicyOwnership(mergePolicies[TEST_BUNDLE_NAME], TEST_POLICY_NAME,
        TEST_ADMIN_A, false), ERR_OK);
}

/**
 * @tc.name: TestDeserializeAndMigrateKeepsExistingOwnership
 * @tc.desc: Ownership that is already recorded is never overwritten by the migration.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestDeserializeAndMigrateKeepsExistingOwnership, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    std::map<std::string, ManagedBrowserPolicyType> storedPolicies;
    storedPolicies[TEST_BUNDLE_NAME].version = 1;
    storedPolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    std::string storedData;
    ASSERT_TRUE(ManagedBrowserPolicySerializer::GetInstance()->Serialize(storedPolicies, storedData));
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        storedData, storedData, DEFAULT_USER_ID), ERR_OK);

    ManagedBrowserPolicyPlugin plugin;
    HandlePolicyData policyData;
    policyData.mergePolicyData = BuildMergePolicyData(TEST_ADMIN_B, true, true);
    std::map<std::string, ManagedBrowserPolicyType> policies;
    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    ASSERT_EQ(plugin.DeserializeAndMigrate(policyData, policies, mergePolicies), ERR_OK);
    EXPECT_EQ(mergePolicies[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME].adminBundleName, TEST_ADMIN_B);
    EXPECT_TRUE(mergePolicies[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME].isForceOverride);
}

/**
 * @tc.name: TestDeserializeAndMigrateFailWithBrokenCurrentPolicy
 * @tc.desc: A malformed current blob fails before the migration runs.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestDeserializeAndMigrateFailWithBrokenCurrentPolicy, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    ManagedBrowserPolicyPlugin plugin;
    HandlePolicyData policyData;
    policyData.policyData = "broken";
    std::map<std::string, ManagedBrowserPolicyType> policies;
    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    EXPECT_EQ(plugin.DeserializeAndMigrate(policyData, policies, mergePolicies),
        EdmReturnErrCode::SYSTEM_ABNORMALLY);
    EXPECT_TRUE(mergePolicies.empty());
}

/**
 * @tc.name: TestDeserializeAndMigrateEmptyInputStaysEmpty
 * @tc.desc: Empty current and merged blobs are valid and deserialize to empty maps, so a
 *           first policy write on a fresh device is not rejected.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestDeserializeAndMigrateEmptyInputStaysEmpty, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    ManagedBrowserPolicyPlugin plugin;
    HandlePolicyData policyData;
    std::map<std::string, ManagedBrowserPolicyType> policies;
    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    ASSERT_EQ(plugin.DeserializeAndMigrate(policyData, policies, mergePolicies), ERR_OK);
    EXPECT_TRUE(policies.empty());
    EXPECT_TRUE(mergePolicies.empty());
}

/**
 * @tc.name: TestGetOthersMergePolicyDataCarriesOverOwnership
 * @tc.desc: The merged view rebuilt from other admins carries over the ownership records
 *           persisted in the shared policy so the owner stays protected.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestGetOthersMergePolicyDataCarriesOverOwnership, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    std::map<std::string, ManagedBrowserPolicyType> adminPolicies;
    adminPolicies[TEST_BUNDLE_NAME].version = 1;
    adminPolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    std::string adminData;
    ASSERT_TRUE(ManagedBrowserPolicySerializer::GetInstance()->Serialize(adminPolicies, adminData));
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        adminData, "", DEFAULT_USER_ID), ERR_OK);

    std::map<std::string, ManagedBrowserPolicyType> combinedPolicies;
    combinedPolicies[TEST_BUNDLE_NAME].version = 1;
    combinedPolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    ManagedBrowserPolicyOwnership owner;
    owner.adminBundleName = TEST_ADMIN_A;
    owner.isForceOverride = true;
    combinedPolicies[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME] = owner;
    std::string combinedData;
    ASSERT_TRUE(ManagedBrowserPolicySerializer::GetInstance()->Serialize(combinedPolicies, combinedData));
    ASSERT_EQ(policyManager->SetPolicy("", PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        "", combinedData, DEFAULT_USER_ID), ERR_OK);

    ManagedBrowserPolicyPlugin plugin;
    std::string othersMergePolicyData;
    ASSERT_EQ(plugin.GetOthersMergePolicyData(TEST_ADMIN_B, DEFAULT_USER_ID, othersMergePolicyData), ERR_OK);

    std::map<std::string, ManagedBrowserPolicyType> mergeData;
    DeserializeOrFail(othersMergePolicyData, mergeData);
    ASSERT_EQ(mergeData[TEST_BUNDLE_NAME].ownership.size(), 1);
    EXPECT_EQ(mergeData[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME].adminBundleName, TEST_ADMIN_A);
    EXPECT_TRUE(mergeData[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME].isForceOverride);
}

/**
 * @tc.name: TestGetOthersMergePolicyDataSkipsOwnershipOfUnlistedItem
 * @tc.desc: An ownership record whose item is no longer listed by the other admin is not
 *           restored, otherwise the item would stay blocked after the owner dropped it.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestGetOthersMergePolicyDataSkipsOwnershipOfUnlistedItem, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    std::map<std::string, ManagedBrowserPolicyType> adminPolicies;
    adminPolicies[TEST_BUNDLE_NAME].version = 1;
    adminPolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_OTHER_POLICY_NAME);
    std::string adminData;
    ASSERT_TRUE(ManagedBrowserPolicySerializer::GetInstance()->Serialize(adminPolicies, adminData));
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        adminData, "", DEFAULT_USER_ID), ERR_OK);

    std::map<std::string, ManagedBrowserPolicyType> combinedPolicies;
    combinedPolicies[TEST_BUNDLE_NAME].version = 1;
    combinedPolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    ManagedBrowserPolicyOwnership owner;
    owner.adminBundleName = TEST_ADMIN_A;
    combinedPolicies[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME] = owner;
    std::string combinedData;
    ASSERT_TRUE(ManagedBrowserPolicySerializer::GetInstance()->Serialize(combinedPolicies, combinedData));
    ASSERT_EQ(policyManager->SetPolicy("", PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        "", combinedData, DEFAULT_USER_ID), ERR_OK);

    ManagedBrowserPolicyPlugin plugin;
    std::string othersMergePolicyData;
    ASSERT_EQ(plugin.GetOthersMergePolicyData(TEST_ADMIN_B, DEFAULT_USER_ID, othersMergePolicyData), ERR_OK);

    std::map<std::string, ManagedBrowserPolicyType> mergeData;
    DeserializeOrFail(othersMergePolicyData, mergeData);
    EXPECT_EQ(CountName(mergeData[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 0);
    EXPECT_TRUE(mergeData[TEST_BUNDLE_NAME].ownership.empty());
}

/**
 * @tc.name: TestGetOthersMergePolicyDataWithoutOwnershipKeepsLegacyShape
 * @tc.desc: When the shared policy carries no ownership the merged view stays free of it,
 *           so admins written before the feature keep working unchanged.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestGetOthersMergePolicyDataWithoutOwnershipKeepsLegacyShape, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    std::map<std::string, ManagedBrowserPolicyType> adminPolicies;
    adminPolicies[TEST_BUNDLE_NAME].version = 1;
    adminPolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    std::string adminData;
    ASSERT_TRUE(ManagedBrowserPolicySerializer::GetInstance()->Serialize(adminPolicies, adminData));
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        adminData, "", DEFAULT_USER_ID), ERR_OK);

    ManagedBrowserPolicyPlugin plugin;
    std::string othersMergePolicyData;
    ASSERT_EQ(plugin.GetOthersMergePolicyData(TEST_ADMIN_B, DEFAULT_USER_ID, othersMergePolicyData), ERR_OK);

    std::map<std::string, ManagedBrowserPolicyType> mergeData;
    DeserializeOrFail(othersMergePolicyData, mergeData);
    EXPECT_EQ(CountName(mergeData[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 1);
    EXPECT_TRUE(mergeData[TEST_BUNDLE_NAME].ownership.empty());
}

/**
 * @tc.name: TestGetOthersMergePolicyDataFailWithBrokenCombinedPolicy
 * @tc.desc: A malformed shared policy does not fail the merged view, the ownership carry
 *           over is simply skipped and the other admins data is still reported.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestGetOthersMergePolicyDataFailWithBrokenCombinedPolicy, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    std::map<std::string, ManagedBrowserPolicyType> adminPolicies;
    adminPolicies[TEST_BUNDLE_NAME].version = 1;
    adminPolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    std::string adminData;
    ASSERT_TRUE(ManagedBrowserPolicySerializer::GetInstance()->Serialize(adminPolicies, adminData));
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        adminData, "", DEFAULT_USER_ID), ERR_OK);
    ASSERT_EQ(policyManager->SetPolicy("", PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        "", "broken", DEFAULT_USER_ID), ERR_OK);

    ManagedBrowserPolicyPlugin plugin;
    std::string othersMergePolicyData;
    ASSERT_EQ(plugin.GetOthersMergePolicyData(TEST_ADMIN_B, DEFAULT_USER_ID, othersMergePolicyData), ERR_OK);
    std::map<std::string, ManagedBrowserPolicyType> mergeData;
    DeserializeOrFail(othersMergePolicyData, mergeData);
    EXPECT_EQ(CountName(mergeData[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 1);
    EXPECT_TRUE(mergeData[TEST_BUNDLE_NAME].ownership.empty());
}

/**
 * @tc.name: TestGetOthersMergePolicyDataEmptyWhenNoAdminData
 * @tc.desc: With nothing stored the merged view is reported as an empty blob.
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
 * @tc.desc: Only the calling admin has data, so there is nothing to report as other admin data.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestGetOthersMergePolicyDataEmptyWhenOnlySelfAdmin, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    std::map<std::string, ManagedBrowserPolicyType> adminPolicies;
    adminPolicies[TEST_BUNDLE_NAME].version = 1;
    adminPolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    std::string adminData;
    ASSERT_TRUE(ManagedBrowserPolicySerializer::GetInstance()->Serialize(adminPolicies, adminData));
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_B, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        adminData, "", DEFAULT_USER_ID), ERR_OK);

    ManagedBrowserPolicyPlugin plugin;
    std::string othersMergePolicyData;
    ASSERT_EQ(plugin.GetOthersMergePolicyData(TEST_ADMIN_B, DEFAULT_USER_ID, othersMergePolicyData), ERR_OK);
    EXPECT_TRUE(othersMergePolicyData.empty());
}

/**
 * @tc.name: TestGetOthersMergePolicyDataFailWithBrokenAdminData
 * @tc.desc: A malformed admin blob is reported as a system error rather than silently
 *           returning a partial merged view.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestGetOthersMergePolicyDataFailWithBrokenAdminData, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        "broken", "", DEFAULT_USER_ID), ERR_OK);

    ManagedBrowserPolicyPlugin plugin;
    std::string othersMergePolicyData;
    EXPECT_EQ(plugin.GetOthersMergePolicyData(TEST_ADMIN_B, DEFAULT_USER_ID, othersMergePolicyData),
        EdmReturnErrCode::SYSTEM_ABNORMALLY);
    EXPECT_TRUE(othersMergePolicyData.empty());
}

/**
 * @tc.name: TestGetOthersMergePolicyDataSkipsEmptyAdminData
 * @tc.desc: An admin that stored no blob at all is skipped instead of failing the request.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestGetOthersMergePolicyDataSkipsEmptyAdminData, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    std::map<std::string, ManagedBrowserPolicyType> adminPolicies;
    adminPolicies[TEST_BUNDLE_NAME].version = 1;
    adminPolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    std::string adminData;
    ASSERT_TRUE(ManagedBrowserPolicySerializer::GetInstance()->Serialize(adminPolicies, adminData));
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        adminData, "", DEFAULT_USER_ID), ERR_OK);

    ManagedBrowserPolicyPlugin plugin;
    std::string othersMergePolicyData;
    ASSERT_EQ(plugin.GetOthersMergePolicyData("", DEFAULT_USER_ID, othersMergePolicyData), ERR_OK);
    std::map<std::string, ManagedBrowserPolicyType> mergeData;
    DeserializeOrFail(othersMergePolicyData, mergeData);
    EXPECT_EQ(CountName(mergeData[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 1);
    EXPECT_TRUE(mergeData[TEST_BUNDLE_NAME].ownership.empty());
}

/**
 * @tc.name: TestGetOthersMergePolicyDataKeepsUnknownCallerData
 * @tc.desc: A caller that is not among the admins that stored the policy still receives the
 *           merged view of all of them, because there is no entry of its own to remove.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestGetOthersMergePolicyDataKeepsUnknownCallerData, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    std::map<std::string, ManagedBrowserPolicyType> adminPolicies;
    adminPolicies[TEST_BUNDLE_NAME].version = 1;
    adminPolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    std::string adminData;
    ASSERT_TRUE(ManagedBrowserPolicySerializer::GetInstance()->Serialize(adminPolicies, adminData));
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        adminData, "", DEFAULT_USER_ID), ERR_OK);

    ManagedBrowserPolicyPlugin plugin;
    std::string othersMergePolicyData;
    ASSERT_EQ(plugin.GetOthersMergePolicyData("com.admin.unknown", DEFAULT_USER_ID, othersMergePolicyData), ERR_OK);
    std::map<std::string, ManagedBrowserPolicyType> mergeData;
    DeserializeOrFail(othersMergePolicyData, mergeData);
    EXPECT_EQ(CountName(mergeData[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 1);
}

/**
 * @tc.name: TestGetOthersMergePolicyDataExcludesTheCallingAdmin
 * @tc.desc: The merged view of the other admins does not contain the entry of the calling
 *           admin, so an admin never sees its own data as if it came from another admin.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestGetOthersMergePolicyDataExcludesTheCallingAdmin, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    std::map<std::string, ManagedBrowserPolicyType> adminPolicies;
    adminPolicies[TEST_BUNDLE_NAME].version = 1;
    adminPolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    std::string adminData;
    ASSERT_TRUE(ManagedBrowserPolicySerializer::GetInstance()->Serialize(adminPolicies, adminData));
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        adminData, "", DEFAULT_USER_ID), ERR_OK);

    std::map<std::string, ManagedBrowserPolicyType> otherAdminPolicies;
    otherAdminPolicies[TEST_OTHER_BUNDLE_NAME].version = 1;
    otherAdminPolicies[TEST_OTHER_BUNDLE_NAME].policyNames.push_back(TEST_OTHER_POLICY_NAME);
    std::string otherAdminData;
    ASSERT_TRUE(ManagedBrowserPolicySerializer::GetInstance()->Serialize(otherAdminPolicies, otherAdminData));
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_B, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        otherAdminData, "", DEFAULT_USER_ID), ERR_OK);

    ManagedBrowserPolicyPlugin plugin;
    std::string othersMergePolicyData;
    ASSERT_EQ(plugin.GetOthersMergePolicyData(TEST_ADMIN_A, DEFAULT_USER_ID, othersMergePolicyData), ERR_OK);
    std::map<std::string, ManagedBrowserPolicyType> mergeData;
    DeserializeOrFail(othersMergePolicyData, mergeData);
    EXPECT_EQ(CountName(mergeData[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 0);
    EXPECT_EQ(CountName(mergeData[TEST_OTHER_BUNDLE_NAME].policyNames, TEST_OTHER_POLICY_NAME), 1);
}

/**
 * @tc.name: TestUpdateCurrentAndMergePolicyRejectsConflictWithoutForce
 * @tc.desc: Without force override an item listed by another admin is rejected as a
 *           parameter error and no version is advanced.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestUpdateCurrentAndMergePolicyRejectsConflictWithoutForce, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    std::map<std::string, ManagedBrowserPolicyType> policies;
    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    mergePolicies[TEST_BUNDLE_NAME].version = 1;
    mergePolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    ManagedBrowserPolicyPlugin::ManagedBrowserPolicyRequest request{TEST_BUNDLE_NAME, TEST_POLICY_NAME,
        TEST_POLICY_VALUE, false};

    EXPECT_EQ(plugin.UpdateCurrentAndMergePolicy(policies, mergePolicies, request, TEST_ADMIN_B),
        EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);
    EXPECT_TRUE(policies.empty());
    EXPECT_EQ(mergePolicies[TEST_BUNDLE_NAME].version, 1);
    EXPECT_EQ(CountName(mergePolicies[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 1);
}

/**
 * @tc.name: TestUpdateCurrentAndMergePolicyCopiesNewBundleIntoMergeView
 * @tc.desc: A bundle that the merged view does not know yet is copied over as a whole,
 *           which is how a first writer reaches the shared view.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestUpdateCurrentAndMergePolicyCopiesNewBundleIntoMergeView, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    std::map<std::string, ManagedBrowserPolicyType> policies;
    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    ManagedBrowserPolicyPlugin::ManagedBrowserPolicyRequest request{TEST_BUNDLE_NAME, TEST_POLICY_NAME,
        TEST_POLICY_VALUE, false};

    ASSERT_EQ(plugin.UpdateCurrentAndMergePolicy(policies, mergePolicies, request, TEST_ADMIN_B), ERR_OK);
    EXPECT_EQ(policies[TEST_BUNDLE_NAME].version, 1);
    EXPECT_EQ(CountName(policies[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 1);
    ASSERT_EQ(mergePolicies.count(TEST_BUNDLE_NAME), 1);
    EXPECT_EQ(mergePolicies[TEST_BUNDLE_NAME].version, 1);
    EXPECT_EQ(CountName(mergePolicies[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 1);
}

/**
 * @tc.name: TestUpdateCurrentAndMergePolicyRemovesNameFromCurrentOnly
 * @tc.desc: Clearing a value drops the name from this admin own view and from the merged
 *           view entry it created, while the shared version still advances.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestUpdateCurrentAndMergePolicyRemovesNameFromCurrentOnly, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    std::map<std::string, ManagedBrowserPolicyType> policies;
    policies[TEST_BUNDLE_NAME].version = 1;
    policies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    ManagedBrowserPolicyPlugin::ManagedBrowserPolicyRequest request{TEST_BUNDLE_NAME, TEST_POLICY_NAME, "", false};

    ASSERT_EQ(plugin.UpdateCurrentAndMergePolicy(policies, mergePolicies, request, TEST_ADMIN_B), ERR_OK);
    EXPECT_EQ(CountName(policies[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 0);
    EXPECT_EQ(policies[TEST_BUNDLE_NAME].version, 2);
    EXPECT_EQ(mergePolicies[TEST_BUNDLE_NAME].version, 1);
    EXPECT_EQ(CountName(mergePolicies[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 0);
}

/**
 * @tc.name: TestUpdateCurrentAndMergePolicyKeepsNameWhenValueNotEmpty
 * @tc.desc: Updating an already owned item does not duplicate the name and only bumps the
 *           version, so repeated writes stay stable.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestUpdateCurrentAndMergePolicyKeepsNameWhenValueNotEmpty, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    std::map<std::string, ManagedBrowserPolicyType> policies;
    policies[TEST_BUNDLE_NAME].version = 1;
    policies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    mergePolicies[TEST_BUNDLE_NAME].version = TEST_HIGHER_VERSION;
    ManagedBrowserPolicyPlugin::ManagedBrowserPolicyRequest request{TEST_BUNDLE_NAME, TEST_POLICY_NAME,
        TEST_POLICY_VALUE, false};

    ASSERT_EQ(plugin.UpdateCurrentAndMergePolicy(policies, mergePolicies, request, TEST_ADMIN_B), ERR_OK);
    EXPECT_EQ(CountName(policies[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 1);
    EXPECT_EQ(policies[TEST_BUNDLE_NAME].version, 2);
    EXPECT_EQ(CountName(mergePolicies[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 0);
    EXPECT_EQ(mergePolicies[TEST_BUNDLE_NAME].version, 6);
}

/**
 * @tc.name: TestUpdateCurrentAndMergePolicyForceOverrideOnOtherBundle
 * @tc.desc: A force override for a bundle the merged view does not know yet adds it without
 *           bumping any other bundle.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestUpdateCurrentAndMergePolicyForceOverrideOnOtherBundle, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    std::map<std::string, ManagedBrowserPolicyType> policies;
    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    mergePolicies[TEST_BUNDLE_NAME].version = TEST_MEDIUM_VERSION;
    mergePolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    ManagedBrowserPolicyPlugin::ManagedBrowserPolicyRequest request{TEST_OTHER_BUNDLE_NAME, TEST_OTHER_POLICY_NAME,
        TEST_POLICY_VALUE, true};

    ASSERT_EQ(plugin.UpdateCurrentAndMergePolicy(policies, mergePolicies, request, TEST_ADMIN_B), ERR_OK);
    ASSERT_EQ(mergePolicies.count(TEST_OTHER_BUNDLE_NAME), 1);
    EXPECT_EQ(CountName(mergePolicies[TEST_OTHER_BUNDLE_NAME].policyNames, TEST_OTHER_POLICY_NAME), 1);
    EXPECT_EQ(mergePolicies[TEST_BUNDLE_NAME].version, 3);
    EXPECT_EQ(CountName(mergePolicies[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 1);
}

/**
 * @tc.name: TestUpdateCurrentAndMergePolicyAllowsWhenNameNotListedByOtherAdmin
 * @tc.desc: An item the merged view does not list is not a conflict, so a plain set of a
 *           policy the other admin never touched is accepted without force override.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestUpdateCurrentAndMergePolicyAllowsWhenNameNotListedByOtherAdmin,
    TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    std::map<std::string, ManagedBrowserPolicyType> policies;
    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    mergePolicies[TEST_BUNDLE_NAME].version = 1;
    mergePolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_OTHER_POLICY_NAME);
    ManagedBrowserPolicyPlugin::ManagedBrowserPolicyRequest request{TEST_BUNDLE_NAME, TEST_POLICY_NAME,
        TEST_POLICY_VALUE, false};

    ASSERT_EQ(plugin.UpdateCurrentAndMergePolicy(policies, mergePolicies, request, TEST_ADMIN_B), ERR_OK);
    EXPECT_EQ(CountName(policies[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 1);
    EXPECT_EQ(CountName(mergePolicies[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 1);
    EXPECT_EQ(CountName(mergePolicies[TEST_BUNDLE_NAME].policyNames, TEST_OTHER_POLICY_NAME), 1);
}

/**
 * @tc.name: TestUpdateCurrentAndMergePolicyKeepsOtherBundleUntouched
 * @tc.desc: Only the bundle the request targets is written into the merged view, the other
 *           bundles of the merged view keep their names and their version.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestUpdateCurrentAndMergePolicyKeepsOtherBundleUntouched, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    std::map<std::string, ManagedBrowserPolicyType> policies;
    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    mergePolicies[TEST_OTHER_BUNDLE_NAME].version = TEST_OTHER_BUNDLE_VERSION;
    mergePolicies[TEST_OTHER_BUNDLE_NAME].policyNames.push_back(TEST_OTHER_POLICY_NAME);
    ManagedBrowserPolicyPlugin::ManagedBrowserPolicyRequest request{TEST_BUNDLE_NAME, TEST_POLICY_NAME,
        TEST_POLICY_VALUE, false};

    ASSERT_EQ(plugin.UpdateCurrentAndMergePolicy(policies, mergePolicies, request, TEST_ADMIN_B), ERR_OK);
    ASSERT_EQ(mergePolicies.count(TEST_OTHER_BUNDLE_NAME), 1);
    EXPECT_EQ(mergePolicies[TEST_OTHER_BUNDLE_NAME].version, TEST_OTHER_BUNDLE_VERSION);
    EXPECT_EQ(CountName(mergePolicies[TEST_OTHER_BUNDLE_NAME].policyNames, TEST_OTHER_POLICY_NAME), 1);
    EXPECT_TRUE(mergePolicies[TEST_OTHER_BUNDLE_NAME].ownership.empty());
}

/**
 * @tc.name: TestUpdateCurrentAndMergePolicyForceOverrideOnConflictingItem
 * @tc.desc: A force override bypasses the merged view conflict check, so an item that is
 *           listed by another admin is taken over instead of being rejected.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestUpdateCurrentAndMergePolicyForceOverrideOnConflictingItem, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    std::map<std::string, ManagedBrowserPolicyType> policies;
    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    mergePolicies[TEST_BUNDLE_NAME].version = 1;
    mergePolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    ManagedBrowserPolicyPlugin::ManagedBrowserPolicyRequest request{TEST_BUNDLE_NAME, TEST_POLICY_NAME,
        TEST_POLICY_VALUE, true};

    ASSERT_EQ(plugin.UpdateCurrentAndMergePolicy(policies, mergePolicies, request, TEST_ADMIN_B), ERR_OK);
    EXPECT_EQ(CountName(policies[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 1);
    EXPECT_EQ(CountName(mergePolicies[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 1);
    EXPECT_EQ(mergePolicies[TEST_BUNDLE_NAME].version, 2);
}

/**
 * @tc.name: TestRecordPolicyOwnerKeepsFirstAdminAsOwner
 * @tc.desc: The first admin that claims an item stays its owner, so a second admin that also
 *           stored the same item cannot silently take the ownership over.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestRecordPolicyOwnerKeepsFirstAdminAsOwner, TestSize.Level1)
{
    std::map<std::string, std::string> owners;
    plugin_.RecordPolicyOwner(TEST_BUNDLE_NAME, TEST_POLICY_NAME, TEST_ADMIN_A, owners);
    plugin_.RecordPolicyOwner(TEST_BUNDLE_NAME, TEST_POLICY_NAME, TEST_ADMIN_B, owners);

    ASSERT_EQ(owners.size(), 1);
    EXPECT_EQ(owners[TEST_BUNDLE_NAME + "|" + TEST_POLICY_NAME], TEST_ADMIN_A);
}

/**
 * @tc.name: TestRecordPolicyOwnerSeparatesBundlesAndNames
 * @tc.desc: The ownership key is built from both the bundle name and the policy name, so the
 *           same policy name under two different bundles is tracked as two independent items.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestRecordPolicyOwnerSeparatesBundlesAndNames, TestSize.Level1)
{
    std::map<std::string, std::string> owners;
    plugin_.RecordPolicyOwner(TEST_BUNDLE_NAME, TEST_POLICY_NAME, TEST_ADMIN_A, owners);
    plugin_.RecordPolicyOwner(TEST_OTHER_BUNDLE_NAME, TEST_POLICY_NAME, TEST_ADMIN_B, owners);
    plugin_.RecordPolicyOwner(TEST_BUNDLE_NAME, TEST_OTHER_POLICY_NAME, TEST_ADMIN_B, owners);

    ASSERT_EQ(owners.size(), 3);
    EXPECT_EQ(owners[TEST_BUNDLE_NAME + "|" + TEST_POLICY_NAME], TEST_ADMIN_A);
    EXPECT_EQ(owners[TEST_OTHER_BUNDLE_NAME + "|" + TEST_POLICY_NAME], TEST_ADMIN_B);
    EXPECT_EQ(owners[TEST_BUNDLE_NAME + "|" + TEST_OTHER_POLICY_NAME], TEST_ADMIN_B);
}

/**
 * @tc.name: TestCollectAdminPolicyOwnersRecordsEveryItem
 * @tc.desc: Every policy name an admin stored becomes an ownership candidate for that admin,
 *           so all of its items are protected after the migration.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestCollectAdminPolicyOwnersRecordsEveryItem, TestSize.Level1)
{
    std::map<std::string, ManagedBrowserPolicyType> adminPolicies;
    adminPolicies[TEST_BUNDLE_NAME].version = 1;
    adminPolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    adminPolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_OTHER_POLICY_NAME);
    adminPolicies[TEST_OTHER_BUNDLE_NAME].version = 1;
    adminPolicies[TEST_OTHER_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);

    std::map<std::string, std::string> owners;
    plugin_.CollectAdminPolicyOwners(TEST_ADMIN_A, adminPolicies, owners);

    ASSERT_EQ(owners.size(), 3);
    EXPECT_EQ(owners[TEST_BUNDLE_NAME + "|" + TEST_POLICY_NAME], TEST_ADMIN_A);
    EXPECT_EQ(owners[TEST_BUNDLE_NAME + "|" + TEST_OTHER_POLICY_NAME], TEST_ADMIN_A);
    EXPECT_EQ(owners[TEST_OTHER_BUNDLE_NAME + "|" + TEST_POLICY_NAME], TEST_ADMIN_A);
}

/**
 * @tc.name: TestCollectAdminPolicyOwnersOnEmptyInputIsNoop
 * @tc.desc: An admin that stored nothing contributes no ownership candidate, so the migration
 *           does not invent owners for items nobody wrote.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestCollectAdminPolicyOwnersOnEmptyInputIsNoop, TestSize.Level1)
{
    std::map<std::string, ManagedBrowserPolicyType> adminPolicies;
    std::map<std::string, std::string> owners;
    plugin_.CollectAdminPolicyOwners(TEST_ADMIN_A, adminPolicies, owners);
    EXPECT_TRUE(owners.empty());
}

/**
 * @tc.name: TestCollectPolicyOwnersSkipsBrokenAdmin
 * @tc.desc: An admin whose blob cannot be parsed is skipped without aborting the migration,
 *           so one corrupted admin does not block the ownership backfill of the others.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestCollectPolicyOwnersSkipsBrokenAdmin, TestSize.Level1)
{
    std::map<std::string, ManagedBrowserPolicyType> storedPolicies;
    storedPolicies[TEST_BUNDLE_NAME].version = 1;
    storedPolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    std::string storedData;
    ASSERT_TRUE(ManagedBrowserPolicySerializer::GetInstance()->Serialize(storedPolicies, storedData));

    AdminValueItemsMap adminValues;
    adminValues[TEST_ADMIN_B] = "broken";
    adminValues[TEST_ADMIN_A] = storedData;

    std::map<std::string, std::string> owners;
    plugin_.CollectPolicyOwners(adminValues, owners);

    ASSERT_EQ(owners.size(), 1);
    EXPECT_EQ(owners[TEST_BUNDLE_NAME + "|" + TEST_POLICY_NAME], TEST_ADMIN_A);
}

/**
 * @tc.name: TestCollectPolicyOwnersSkipsEmptyAdminValue
 * @tc.desc: An admin that stored no blob at all is skipped instead of failing the collection.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestCollectPolicyOwnersSkipsEmptyAdminValue, TestSize.Level1)
{
    AdminValueItemsMap adminValues;
    adminValues[TEST_ADMIN_A] = "";

    std::map<std::string, std::string> owners;
    plugin_.CollectPolicyOwners(adminValues, owners);
    EXPECT_TRUE(owners.empty());
}

/**
 * @tc.name: TestCollectPolicyOwnersOnEmptyAdminMapIsNoop
 * @tc.desc: No admin stored anything, so the collection produces no ownership candidate.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestCollectPolicyOwnersOnEmptyAdminMapIsNoop, TestSize.Level1)
{
    std::map<std::string, std::string> owners;
    plugin_.CollectPolicyOwners({}, owners);
    EXPECT_TRUE(owners.empty());
}

/**
 * @tc.name: TestCollectPolicyOwnersRecordsEveryBundleOfAnAdmin
 * @tc.desc: An admin that stored several bundles contributes a candidate for each of its
 *           items, so a whole admin is protected by the backfill.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestCollectPolicyOwnersRecordsEveryBundleOfAnAdmin, TestSize.Level1)
{
    std::map<std::string, ManagedBrowserPolicyType> storedPolicies;
    storedPolicies[TEST_BUNDLE_NAME].version = 1;
    storedPolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    storedPolicies[TEST_OTHER_BUNDLE_NAME].version = 1;
    storedPolicies[TEST_OTHER_BUNDLE_NAME].policyNames.push_back(TEST_OTHER_POLICY_NAME);
    std::string storedData;
    ASSERT_TRUE(ManagedBrowserPolicySerializer::GetInstance()->Serialize(storedPolicies, storedData));

    AdminValueItemsMap adminValues;
    adminValues[TEST_ADMIN_A] = storedData;

    std::map<std::string, std::string> owners;
    plugin_.CollectPolicyOwners(adminValues, owners);

    ASSERT_EQ(owners.size(), 2);
    EXPECT_EQ(owners[TEST_BUNDLE_NAME + "|" + TEST_POLICY_NAME], TEST_ADMIN_A);
    EXPECT_EQ(owners[TEST_OTHER_BUNDLE_NAME + "|" + TEST_OTHER_POLICY_NAME], TEST_ADMIN_A);
}

/**
 * @tc.name: TestCollectPolicyOwnersKeepsFirstAdminOfSharedItem
 * @tc.desc: When two admins stored the same item the first one seen stays its candidate
 *           owner, so the backfill never attributes the item to a random admin.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestCollectPolicyOwnersKeepsFirstAdminOfSharedItem, TestSize.Level1)
{
    std::map<std::string, ManagedBrowserPolicyType> storedPolicies;
    storedPolicies[TEST_BUNDLE_NAME].version = 1;
    storedPolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    std::string storedData;
    ASSERT_TRUE(ManagedBrowserPolicySerializer::GetInstance()->Serialize(storedPolicies, storedData));

    AdminValueItemsMap adminValues;
    adminValues[TEST_ADMIN_A] = storedData;
    adminValues[TEST_ADMIN_B] = storedData;

    std::map<std::string, std::string> owners;
    plugin_.CollectPolicyOwners(adminValues, owners);

    ASSERT_EQ(owners.size(), 1);
    EXPECT_EQ(owners[TEST_BUNDLE_NAME + "|" + TEST_POLICY_NAME], TEST_ADMIN_A);
}

/**
 * @tc.name: TestApplyPolicyOwnersBackfillsUnownedItem
 * @tc.desc: A listed item that has no ownership record yet is backfilled with the candidate
 *           owner and is explicitly not marked as a force override takeover.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestApplyPolicyOwnersBackfillsUnownedItem, TestSize.Level1)
{
    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    mergePolicies[TEST_BUNDLE_NAME].version = 1;
    mergePolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    std::map<std::string, std::string> owners;
    owners[TEST_BUNDLE_NAME + "|" + TEST_POLICY_NAME] = TEST_ADMIN_A;

    bool hasBackfilled = false;
    plugin_.ApplyPolicyOwners(owners, mergePolicies, hasBackfilled);

    EXPECT_TRUE(hasBackfilled);
    ASSERT_EQ(mergePolicies[TEST_BUNDLE_NAME].ownership.size(), 1);
    EXPECT_EQ(mergePolicies[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME].adminBundleName, TEST_ADMIN_A);
    EXPECT_FALSE(mergePolicies[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME].isForceOverride);
}

/**
 * @tc.name: TestApplyPolicyOwnersKeepsExistingOwnership
 * @tc.desc: An item that already has an ownership record is never overwritten by the
 *           backfill, so a recorded takeover survives the migration.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestApplyPolicyOwnersKeepsExistingOwnership, TestSize.Level1)
{
    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    mergePolicies[TEST_BUNDLE_NAME].version = 1;
    mergePolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    ManagedBrowserPolicyOwnership owner;
    owner.adminBundleName = TEST_ADMIN_B;
    owner.isForceOverride = true;
    mergePolicies[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME] = owner;

    std::map<std::string, std::string> owners;
    owners[TEST_BUNDLE_NAME + "|" + TEST_POLICY_NAME] = TEST_ADMIN_A;

    bool hasBackfilled = false;
    plugin_.ApplyPolicyOwners(owners, mergePolicies, hasBackfilled);

    EXPECT_FALSE(hasBackfilled);
    ASSERT_EQ(mergePolicies[TEST_BUNDLE_NAME].ownership.size(), 1);
    EXPECT_EQ(mergePolicies[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME].adminBundleName, TEST_ADMIN_B);
    EXPECT_TRUE(mergePolicies[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME].isForceOverride);
}

/**
 * @tc.name: TestApplyPolicyOwnersSkipsItemWithoutCandidate
 * @tc.desc: A listed item that no admin is known to own stays unowned, so the backfill never
 *           attributes an item to a random admin.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestApplyPolicyOwnersSkipsItemWithoutCandidate, TestSize.Level1)
{
    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    mergePolicies[TEST_BUNDLE_NAME].version = 1;
    mergePolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);

    bool hasBackfilled = false;
    plugin_.ApplyPolicyOwners({}, mergePolicies, hasBackfilled);

    EXPECT_FALSE(hasBackfilled);
    EXPECT_TRUE(mergePolicies[TEST_BUNDLE_NAME].ownership.empty());
}

/**
 * @tc.name: TestApplyPolicyOwnersIgnoresOwnershipOfUnlistedItem
 * @tc.desc: An ownership record for an item that is not listed in the merged view is not
 *           created by the backfill, so no stale ownership is invented.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestApplyPolicyOwnersIgnoresOwnershipOfUnlistedItem, TestSize.Level1)
{
    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    mergePolicies[TEST_BUNDLE_NAME].version = 1;
    mergePolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);

    std::map<std::string, std::string> owners;
    owners[TEST_BUNDLE_NAME + "|" + TEST_OTHER_POLICY_NAME] = TEST_ADMIN_A;

    bool hasBackfilled = false;
    plugin_.ApplyPolicyOwners(owners, mergePolicies, hasBackfilled);

    EXPECT_FALSE(hasBackfilled);
    EXPECT_TRUE(mergePolicies[TEST_BUNDLE_NAME].ownership.empty());
}

/**
 * @tc.name: TestApplyPolicyOwnersOnEmptyMergeViewIsNoop
 * @tc.desc: An empty merged view has no listed item, so the backfill creates nothing even
 *           when a candidate owner is known.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestApplyPolicyOwnersOnEmptyMergeViewIsNoop, TestSize.Level1)
{
    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    std::map<std::string, std::string> owners;
    owners[TEST_BUNDLE_NAME + "|" + TEST_POLICY_NAME] = TEST_ADMIN_A;

    bool hasBackfilled = false;
    plugin_.ApplyPolicyOwners(owners, mergePolicies, hasBackfilled);

    EXPECT_FALSE(hasBackfilled);
    EXPECT_TRUE(mergePolicies.empty());
}

/**
 * @tc.name: TestApplyPolicyOwnersSkipsBundleThatIsNotInMergeView
 * @tc.desc: A candidate owner of a bundle the merged view does not carry is ignored, so the
 *           backfill never invents an entry for an unknown bundle.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestApplyPolicyOwnersSkipsBundleThatIsNotInMergeView, TestSize.Level1)
{
    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    mergePolicies[TEST_OTHER_BUNDLE_NAME].version = 1;
    mergePolicies[TEST_OTHER_BUNDLE_NAME].policyNames.push_back(TEST_OTHER_POLICY_NAME);

    std::map<std::string, std::string> owners;
    owners[TEST_BUNDLE_NAME + "|" + TEST_POLICY_NAME] = TEST_ADMIN_A;

    bool hasBackfilled = false;
    plugin_.ApplyPolicyOwners(owners, mergePolicies, hasBackfilled);

    EXPECT_FALSE(hasBackfilled);
    EXPECT_TRUE(mergePolicies[TEST_BUNDLE_NAME].ownership.empty());
    EXPECT_TRUE(mergePolicies[TEST_OTHER_BUNDLE_NAME].ownership.empty());
}

/**
 * @tc.name: TestApplyPolicyOwnersBackfillsEveryListedItemOfABundle
 * @tc.desc: Every listed item of a bundle that has a candidate owner is backfilled, so a
 *           bundle with several policies protects all of them at once.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestApplyPolicyOwnersBackfillsEveryListedItemOfABundle, TestSize.Level1)
{
    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    mergePolicies[TEST_BUNDLE_NAME].version = 1;
    mergePolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    mergePolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_OTHER_POLICY_NAME);

    std::map<std::string, std::string> owners;
    owners[TEST_BUNDLE_NAME + "|" + TEST_POLICY_NAME] = TEST_ADMIN_A;
    owners[TEST_BUNDLE_NAME + "|" + TEST_OTHER_POLICY_NAME] = TEST_ADMIN_A;

    bool hasBackfilled = false;
    plugin_.ApplyPolicyOwners(owners, mergePolicies, hasBackfilled);

    EXPECT_TRUE(hasBackfilled);
    ASSERT_EQ(mergePolicies[TEST_BUNDLE_NAME].ownership.size(), 2);
    EXPECT_EQ(mergePolicies[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME].adminBundleName, TEST_ADMIN_A);
    EXPECT_EQ(mergePolicies[TEST_BUNDLE_NAME].ownership[TEST_OTHER_POLICY_NAME].adminBundleName, TEST_ADMIN_A);
}

/**
 * @tc.name: TestBackfillOwnershipWithoutStoredAdminIsNoop
 * @tc.desc: With nothing stored by any admin the backfill does nothing, so the merged view
 *           is left exactly as it was.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestBackfillOwnershipWithoutStoredAdminIsNoop, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    mergePolicies[TEST_BUNDLE_NAME].version = 1;
    mergePolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);

    plugin_.BackfillOwnership(mergePolicies);
    EXPECT_TRUE(mergePolicies[TEST_BUNDLE_NAME].ownership.empty());
}

/**
 * @tc.name: TestBackfillOwnershipUsesFirstStoredAdmin
 * @tc.desc: When several admins stored the same item the first one seen becomes its owner and
 *           the later admins are left without ownership.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestBackfillOwnershipUsesFirstStoredAdmin, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    std::map<std::string, ManagedBrowserPolicyType> storedPolicies;
    storedPolicies[TEST_BUNDLE_NAME].version = 1;
    storedPolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    std::string storedData;
    ASSERT_TRUE(ManagedBrowserPolicySerializer::GetInstance()->Serialize(storedPolicies, storedData));
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        storedData, storedData, DEFAULT_USER_ID), ERR_OK);
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_B, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        storedData, storedData, DEFAULT_USER_ID), ERR_OK);

    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    mergePolicies[TEST_BUNDLE_NAME].version = 1;
    mergePolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);

    plugin_.BackfillOwnership(mergePolicies);
    ASSERT_EQ(mergePolicies[TEST_BUNDLE_NAME].ownership.size(), 1);
    EXPECT_FALSE(mergePolicies[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME].adminBundleName.empty());
}

/**
 * @tc.name: TestBackfillOwnershipKeepsExistingOwnershipRecord
 * @tc.desc: The backfill never overwrites an ownership record that is already recorded, so a
 *           takeover that was persisted before the backfill survives it.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestBackfillOwnershipKeepsExistingOwnershipRecord, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    std::map<std::string, ManagedBrowserPolicyType> storedPolicies;
    storedPolicies[TEST_BUNDLE_NAME].version = 1;
    storedPolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    std::string storedData;
    ASSERT_TRUE(ManagedBrowserPolicySerializer::GetInstance()->Serialize(storedPolicies, storedData));
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        storedData, storedData, DEFAULT_USER_ID), ERR_OK);

    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    mergePolicies[TEST_BUNDLE_NAME].version = 1;
    mergePolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    ManagedBrowserPolicyOwnership owner;
    owner.adminBundleName = TEST_ADMIN_B;
    owner.isForceOverride = true;
    mergePolicies[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME] = owner;

    plugin_.BackfillOwnership(mergePolicies);

    ASSERT_EQ(mergePolicies[TEST_BUNDLE_NAME].ownership.size(), 1);
    EXPECT_EQ(mergePolicies[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME].adminBundleName, TEST_ADMIN_B);
    EXPECT_TRUE(mergePolicies[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME].isForceOverride);
}

/**
 * @tc.name: TestBackfillOwnershipSkipsItemNobodyStored
 * @tc.desc: A listed item that no admin stored stays unowned, so the backfill never
 *           attributes an item to an admin that never wrote it.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestBackfillOwnershipSkipsItemNobodyStored, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    std::map<std::string, ManagedBrowserPolicyType> storedPolicies;
    storedPolicies[TEST_OTHER_BUNDLE_NAME].version = 1;
    storedPolicies[TEST_OTHER_BUNDLE_NAME].policyNames.push_back(TEST_OTHER_POLICY_NAME);
    std::string storedData;
    ASSERT_TRUE(ManagedBrowserPolicySerializer::GetInstance()->Serialize(storedPolicies, storedData));
    ASSERT_EQ(policyManager->SetPolicy(TEST_ADMIN_A, PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        storedData, storedData, DEFAULT_USER_ID), ERR_OK);

    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    mergePolicies[TEST_BUNDLE_NAME].version = 1;
    mergePolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);

    plugin_.BackfillOwnership(mergePolicies);

    EXPECT_TRUE(mergePolicies[TEST_BUNDLE_NAME].ownership.empty());
}

/**
 * @tc.name: TestMergeAdminPoliciesCombinesSeveralAdmins
 * @tc.desc: The merged view of the other admins combines the policy names of every admin and
 *           keeps the highest version, so the browser observes the newest state.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestMergeAdminPoliciesCombinesSeveralAdmins, TestSize.Level1)
{
    std::map<std::string, ManagedBrowserPolicyType> firstAdmin;
    firstAdmin[TEST_BUNDLE_NAME].version = 1;
    firstAdmin[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    std::string firstData;
    ASSERT_TRUE(ManagedBrowserPolicySerializer::GetInstance()->Serialize(firstAdmin, firstData));

    std::map<std::string, ManagedBrowserPolicyType> secondAdmin;
    secondAdmin[TEST_BUNDLE_NAME].version = TEST_HIGHER_VERSION;
    secondAdmin[TEST_BUNDLE_NAME].policyNames.push_back(TEST_OTHER_POLICY_NAME);
    std::string secondData;
    ASSERT_TRUE(ManagedBrowserPolicySerializer::GetInstance()->Serialize(secondAdmin, secondData));

    AdminValueItemsMap adminValues;
    adminValues[TEST_ADMIN_A] = firstData;
    adminValues[TEST_ADMIN_B] = secondData;

    std::map<std::string, ManagedBrowserPolicyType> mergeData;
    ASSERT_EQ(plugin_.MergeAdminPolicies(adminValues, mergeData), ERR_OK);

    ASSERT_EQ(mergeData.count(TEST_BUNDLE_NAME), 1);
    EXPECT_EQ(CountName(mergeData[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 1);
    EXPECT_EQ(CountName(mergeData[TEST_BUNDLE_NAME].policyNames, TEST_OTHER_POLICY_NAME), 1);
    EXPECT_EQ(mergeData[TEST_BUNDLE_NAME].version, 5);
}

/**
 * @tc.name: TestMergeAdminPoliciesKeepsLowerVersionOfLaterAdmin
 * @tc.desc: A later admin with a lower version does not lower the merged view version, so the
 *           merged version never moves backwards.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestMergeAdminPoliciesKeepsLowerVersionOfLaterAdmin, TestSize.Level1)
{
    std::map<std::string, ManagedBrowserPolicyType> firstAdmin;
    firstAdmin[TEST_BUNDLE_NAME].version = TEST_FIRST_ADMIN_VERSION;
    firstAdmin[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    std::string firstData;
    ASSERT_TRUE(ManagedBrowserPolicySerializer::GetInstance()->Serialize(firstAdmin, firstData));

    std::map<std::string, ManagedBrowserPolicyType> secondAdmin;
    secondAdmin[TEST_BUNDLE_NAME].version = TEST_SECOND_ADMIN_VERSION;
    secondAdmin[TEST_BUNDLE_NAME].policyNames.push_back(TEST_OTHER_POLICY_NAME);
    std::string secondData;
    ASSERT_TRUE(ManagedBrowserPolicySerializer::GetInstance()->Serialize(secondAdmin, secondData));

    AdminValueItemsMap adminValues;
    adminValues[TEST_ADMIN_A] = firstData;
    adminValues[TEST_ADMIN_B] = secondData;

    std::map<std::string, ManagedBrowserPolicyType> mergeData;
    ASSERT_EQ(plugin_.MergeAdminPolicies(adminValues, mergeData), ERR_OK);
    EXPECT_EQ(mergeData[TEST_BUNDLE_NAME].version, 7);
}

/**
 * @tc.name: TestMergeAdminPoliciesKeepsDuplicateNameOfTwoAdmins
 * @tc.desc: Two admins that stored the same item contribute the name twice to the merged view.
 *           The behaviour is pinned down here so a future deduplication change is a deliberate
 *           decision instead of an accidental behaviour change.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestMergeAdminPoliciesKeepsDuplicateNameOfTwoAdmins, TestSize.Level1)
{
    std::map<std::string, ManagedBrowserPolicyType> adminPolicies;
    adminPolicies[TEST_BUNDLE_NAME].version = 1;
    adminPolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    std::string adminData;
    ASSERT_TRUE(ManagedBrowserPolicySerializer::GetInstance()->Serialize(adminPolicies, adminData));

    AdminValueItemsMap adminValues;
    adminValues[TEST_ADMIN_A] = adminData;
    adminValues[TEST_ADMIN_B] = adminData;

    std::map<std::string, ManagedBrowserPolicyType> mergeData;
    ASSERT_EQ(plugin_.MergeAdminPolicies(adminValues, mergeData), ERR_OK);
    EXPECT_EQ(CountName(mergeData[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 2);
}

/**
 * @tc.name: TestMergeAdminPoliciesFailsWithBrokenAdminData
 * @tc.desc: A malformed admin blob aborts the merge with a system error rather than reporting
 *           a partial merged view to the caller.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestMergeAdminPoliciesFailsWithBrokenAdminData, TestSize.Level1)
{
    AdminValueItemsMap adminValues;
    adminValues[TEST_ADMIN_A] = "broken";

    std::map<std::string, ManagedBrowserPolicyType> mergeData;
    EXPECT_EQ(plugin_.MergeAdminPolicies(adminValues, mergeData), EdmReturnErrCode::SYSTEM_ABNORMALLY);
    EXPECT_TRUE(mergeData.empty());
}

/**
 * @tc.name: TestMergeAdminPoliciesSkipsEmptyAdminData
 * @tc.desc: An admin that stored no blob is skipped instead of failing the whole merge.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestMergeAdminPoliciesSkipsEmptyAdminData, TestSize.Level1)
{
    std::map<std::string, ManagedBrowserPolicyType> adminPolicies;
    adminPolicies[TEST_BUNDLE_NAME].version = 1;
    adminPolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    std::string adminData;
    ASSERT_TRUE(ManagedBrowserPolicySerializer::GetInstance()->Serialize(adminPolicies, adminData));

    AdminValueItemsMap adminValues;
    adminValues[TEST_ADMIN_A] = adminData;
    adminValues[TEST_ADMIN_B] = "";

    std::map<std::string, ManagedBrowserPolicyType> mergeData;
    ASSERT_EQ(plugin_.MergeAdminPolicies(adminValues, mergeData), ERR_OK);
    EXPECT_EQ(CountName(mergeData[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 1);
}

/**
 * @tc.name: TestMergeAdminPoliciesOnEmptyAdminMapIsNoop
 * @tc.desc: No admin data at all produces an empty merged view instead of an error.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestMergeAdminPoliciesOnEmptyAdminMapIsNoop, TestSize.Level1)
{
    std::map<std::string, ManagedBrowserPolicyType> mergeData;
    ASSERT_EQ(plugin_.MergeAdminPolicies({}, mergeData), ERR_OK);
    EXPECT_TRUE(mergeData.empty());
}

/**
 * @tc.name: TestMergeAdminPoliciesCombinesDifferentBundles
 * @tc.desc: Two admins that stored different bundles contribute both bundles to the merged
 *           view, so no bundle of any admin is dropped.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestMergeAdminPoliciesCombinesDifferentBundles, TestSize.Level1)
{
    std::map<std::string, ManagedBrowserPolicyType> firstAdmin;
    firstAdmin[TEST_BUNDLE_NAME].version = 1;
    firstAdmin[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    std::string firstData;
    ASSERT_TRUE(ManagedBrowserPolicySerializer::GetInstance()->Serialize(firstAdmin, firstData));

    std::map<std::string, ManagedBrowserPolicyType> secondAdmin;
    secondAdmin[TEST_OTHER_BUNDLE_NAME].version = TEST_OTHER_BUNDLE_VERSION;
    secondAdmin[TEST_OTHER_BUNDLE_NAME].policyNames.push_back(TEST_OTHER_POLICY_NAME);
    std::string secondData;
    ASSERT_TRUE(ManagedBrowserPolicySerializer::GetInstance()->Serialize(secondAdmin, secondData));

    AdminValueItemsMap adminValues;
    adminValues[TEST_ADMIN_A] = firstData;
    adminValues[TEST_ADMIN_B] = secondData;

    std::map<std::string, ManagedBrowserPolicyType> mergeData;
    ASSERT_EQ(plugin_.MergeAdminPolicies(adminValues, mergeData), ERR_OK);
    ASSERT_EQ(mergeData.size(), 2);
    EXPECT_EQ(CountName(mergeData[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 1);
    EXPECT_EQ(CountName(mergeData[TEST_OTHER_BUNDLE_NAME].policyNames, TEST_OTHER_POLICY_NAME), 1);
    EXPECT_EQ(mergeData[TEST_OTHER_BUNDLE_NAME].version, TEST_OTHER_BUNDLE_VERSION);
}

/**
 * @tc.name: TestMergeAdminPoliciesKeepsOwnershipOfFirstAdmin
 * @tc.desc: When the admin blobs already carry ownership records the merged view keeps the
 *           record of the admin that was merged first.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestMergeAdminPoliciesKeepsOwnershipOfFirstAdmin, TestSize.Level1)
{
    std::map<std::string, ManagedBrowserPolicyType> firstAdmin;
    firstAdmin[TEST_BUNDLE_NAME].version = 1;
    firstAdmin[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    ManagedBrowserPolicyOwnership firstOwner;
    firstOwner.adminBundleName = TEST_ADMIN_A;
    firstOwner.isForceOverride = true;
    firstAdmin[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME] = firstOwner;
    std::string firstData;
    ASSERT_TRUE(ManagedBrowserPolicySerializer::GetInstance()->Serialize(firstAdmin, firstData));

    std::map<std::string, ManagedBrowserPolicyType> secondAdmin;
    secondAdmin[TEST_BUNDLE_NAME].version = 2;
    secondAdmin[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    ManagedBrowserPolicyOwnership secondOwner;
    secondOwner.adminBundleName = TEST_ADMIN_B;
    secondOwner.isForceOverride = false;
    secondAdmin[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME] = secondOwner;
    std::string secondData;
    ASSERT_TRUE(ManagedBrowserPolicySerializer::GetInstance()->Serialize(secondAdmin, secondData));

    AdminValueItemsMap adminValues;
    adminValues[TEST_ADMIN_A] = firstData;
    adminValues[TEST_ADMIN_B] = secondData;

    std::map<std::string, ManagedBrowserPolicyType> mergeData;
    ASSERT_EQ(plugin_.MergeAdminPolicies(adminValues, mergeData), ERR_OK);
    ASSERT_EQ(mergeData[TEST_BUNDLE_NAME].ownership.size(), 1);
    EXPECT_EQ(mergeData[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME].adminBundleName, TEST_ADMIN_A);
    EXPECT_TRUE(mergeData[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME].isForceOverride);
}

/**
 * @tc.name: TestMergeCombinedOwnershipRestoresOwner
 * @tc.desc: The ownership recorded in the shared policy is restored onto the merged view of
 *           the other admins, so the owner stays protected after the view is rebuilt.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestMergeCombinedOwnershipRestoresOwner, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    std::map<std::string, ManagedBrowserPolicyType> combinedPolicies;
    combinedPolicies[TEST_BUNDLE_NAME].version = 1;
    combinedPolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    ManagedBrowserPolicyOwnership owner;
    owner.adminBundleName = TEST_ADMIN_A;
    owner.isForceOverride = true;
    combinedPolicies[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME] = owner;
    std::string combinedData;
    ASSERT_TRUE(ManagedBrowserPolicySerializer::GetInstance()->Serialize(combinedPolicies, combinedData));
    ASSERT_EQ(policyManager->SetPolicy("", PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        "", combinedData, DEFAULT_USER_ID), ERR_OK);

    std::map<std::string, ManagedBrowserPolicyType> mergeData;
    mergeData[TEST_BUNDLE_NAME].version = 1;
    mergeData[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);

    ASSERT_EQ(plugin_.MergeCombinedOwnership(mergeData), ERR_OK);
    ASSERT_EQ(mergeData[TEST_BUNDLE_NAME].ownership.size(), 1);
    EXPECT_EQ(mergeData[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME].adminBundleName, TEST_ADMIN_A);
    EXPECT_TRUE(mergeData[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME].isForceOverride);
}

/**
 * @tc.name: TestMergeCombinedOwnershipSkipsUnknownBundle
 * @tc.desc: A bundle that the merged view does not know is ignored, so the ownership of an
 *           unrelated bundle is never injected into the view.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestMergeCombinedOwnershipSkipsUnknownBundle, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    std::map<std::string, ManagedBrowserPolicyType> combinedPolicies;
    combinedPolicies[TEST_OTHER_BUNDLE_NAME].version = 1;
    combinedPolicies[TEST_OTHER_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    ManagedBrowserPolicyOwnership owner;
    owner.adminBundleName = TEST_ADMIN_A;
    combinedPolicies[TEST_OTHER_BUNDLE_NAME].ownership[TEST_POLICY_NAME] = owner;
    std::string combinedData;
    ASSERT_TRUE(ManagedBrowserPolicySerializer::GetInstance()->Serialize(combinedPolicies, combinedData));
    ASSERT_EQ(policyManager->SetPolicy("", PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        "", combinedData, DEFAULT_USER_ID), ERR_OK);

    std::map<std::string, ManagedBrowserPolicyType> mergeData;
    mergeData[TEST_BUNDLE_NAME].version = 1;
    mergeData[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);

    ASSERT_EQ(plugin_.MergeCombinedOwnership(mergeData), ERR_OK);
    EXPECT_TRUE(mergeData[TEST_BUNDLE_NAME].ownership.empty());
    EXPECT_TRUE(mergeData.count(TEST_OTHER_BUNDLE_NAME) == 0);
}

/**
 * @tc.name: TestMergeCombinedOwnershipSkipsUnlistedPolicy
 * @tc.desc: An ownership record whose item is not listed by the other admin is not restored,
 *           otherwise the item would stay blocked after the owner dropped it.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestMergeCombinedOwnershipSkipsUnlistedPolicy, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    std::map<std::string, ManagedBrowserPolicyType> combinedPolicies;
    combinedPolicies[TEST_BUNDLE_NAME].version = 1;
    combinedPolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    ManagedBrowserPolicyOwnership owner;
    owner.adminBundleName = TEST_ADMIN_A;
    combinedPolicies[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME] = owner;
    std::string combinedData;
    ASSERT_TRUE(ManagedBrowserPolicySerializer::GetInstance()->Serialize(combinedPolicies, combinedData));
    ASSERT_EQ(policyManager->SetPolicy("", PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        "", combinedData, DEFAULT_USER_ID), ERR_OK);

    std::map<std::string, ManagedBrowserPolicyType> mergeData;
    mergeData[TEST_BUNDLE_NAME].version = 1;
    mergeData[TEST_BUNDLE_NAME].policyNames.push_back(TEST_OTHER_POLICY_NAME);

    ASSERT_EQ(plugin_.MergeCombinedOwnership(mergeData), ERR_OK);
    EXPECT_TRUE(mergeData[TEST_BUNDLE_NAME].ownership.empty());
}

/**
 * @tc.name: TestMergeCombinedOwnershipToleratesEmptyCombinedPolicy
 * @tc.desc: A missing shared policy is not an error, the ownership carry over is simply skipped
 *           and the merged view keeps the shape it had.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestMergeCombinedOwnershipToleratesEmptyCombinedPolicy, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    std::map<std::string, ManagedBrowserPolicyType> mergeData;
    mergeData[TEST_BUNDLE_NAME].version = 1;
    mergeData[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);

    ASSERT_EQ(plugin_.MergeCombinedOwnership(mergeData), ERR_OK);
    EXPECT_TRUE(mergeData[TEST_BUNDLE_NAME].ownership.empty());
    EXPECT_EQ(CountName(mergeData[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 1);
}

/**
 * @tc.name: TestMergeCombinedOwnershipToleratesBrokenCombinedPolicy
 * @tc.desc: A malformed shared policy is skipped instead of failing the request, so the other
 *           admins data is still reported to the caller.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestMergeCombinedOwnershipToleratesBrokenCombinedPolicy, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    ASSERT_EQ(policyManager->SetPolicy("", PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        "", "broken", DEFAULT_USER_ID), ERR_OK);

    std::map<std::string, ManagedBrowserPolicyType> mergeData;
    mergeData[TEST_BUNDLE_NAME].version = 1;
    mergeData[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);

    EXPECT_EQ(plugin_.MergeCombinedOwnership(mergeData), ERR_OK);
    EXPECT_TRUE(mergeData[TEST_BUNDLE_NAME].ownership.empty());
}

/**
 * @tc.name: TestMergeCombinedOwnershipSkipsBundleWithoutOwnership
 * @tc.desc: A bundle of the shared policy that carries no ownership record contributes
 *           nothing, so the merged view of that bundle stays untouched.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestMergeCombinedOwnershipSkipsBundleWithoutOwnership, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    std::map<std::string, ManagedBrowserPolicyType> combinedPolicies;
    combinedPolicies[TEST_BUNDLE_NAME].version = 1;
    combinedPolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    std::string combinedData;
    ASSERT_TRUE(ManagedBrowserPolicySerializer::GetInstance()->Serialize(combinedPolicies, combinedData));
    ASSERT_EQ(policyManager->SetPolicy("", PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        "", combinedData, DEFAULT_USER_ID), ERR_OK);

    std::map<std::string, ManagedBrowserPolicyType> mergeData;
    mergeData[TEST_BUNDLE_NAME].version = 1;
    mergeData[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);

    ASSERT_EQ(plugin_.MergeCombinedOwnership(mergeData), ERR_OK);
    EXPECT_TRUE(mergeData[TEST_BUNDLE_NAME].ownership.empty());
}

/**
 * @tc.name: TestMergeCombinedOwnershipOnEmptyMergeViewIsNoop
 * @tc.desc: An empty merged view stays empty, the ownership carry over never adds a bundle
 *           that the merged view does not know.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestMergeCombinedOwnershipOnEmptyMergeViewIsNoop, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    std::map<std::string, ManagedBrowserPolicyType> combinedPolicies;
    combinedPolicies[TEST_BUNDLE_NAME].version = 1;
    combinedPolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    ManagedBrowserPolicyOwnership owner;
    owner.adminBundleName = TEST_ADMIN_A;
    combinedPolicies[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME] = owner;
    std::string combinedData;
    ASSERT_TRUE(ManagedBrowserPolicySerializer::GetInstance()->Serialize(combinedPolicies, combinedData));
    ASSERT_EQ(policyManager->SetPolicy("", PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        "", combinedData, DEFAULT_USER_ID), ERR_OK);

    std::map<std::string, ManagedBrowserPolicyType> mergeData;
    ASSERT_EQ(plugin_.MergeCombinedOwnership(mergeData), ERR_OK);
    EXPECT_TRUE(mergeData.empty());
}

/**
 * @tc.name: TestMergeCombinedOwnershipRestoresEveryOwnerOfABundle
 * @tc.desc: Every ownership record of a bundle is restored, so a bundle with several owned
 *           policies keeps each of its owners distinct after the view is rebuilt.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestMergeCombinedOwnershipRestoresEveryOwnerOfABundle, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    std::map<std::string, ManagedBrowserPolicyType> combinedPolicies;
    combinedPolicies[TEST_BUNDLE_NAME].version = 1;
    combinedPolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    combinedPolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_OTHER_POLICY_NAME);
    ManagedBrowserPolicyOwnership firstOwner;
    firstOwner.adminBundleName = TEST_ADMIN_A;
    firstOwner.isForceOverride = true;
    combinedPolicies[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME] = firstOwner;
    ManagedBrowserPolicyOwnership secondOwner;
    secondOwner.adminBundleName = TEST_ADMIN_B;
    secondOwner.isForceOverride = false;
    combinedPolicies[TEST_BUNDLE_NAME].ownership[TEST_OTHER_POLICY_NAME] = secondOwner;
    std::string combinedData;
    ASSERT_TRUE(ManagedBrowserPolicySerializer::GetInstance()->Serialize(combinedPolicies, combinedData));
    ASSERT_EQ(policyManager->SetPolicy("", PolicyName::POLICY_MANAGED_BROWSER_POLICY,
        "", combinedData, DEFAULT_USER_ID), ERR_OK);

    std::map<std::string, ManagedBrowserPolicyType> mergeData;
    mergeData[TEST_BUNDLE_NAME].version = 1;
    mergeData[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    mergeData[TEST_BUNDLE_NAME].policyNames.push_back(TEST_OTHER_POLICY_NAME);

    ASSERT_EQ(plugin_.MergeCombinedOwnership(mergeData), ERR_OK);
    ASSERT_EQ(mergeData[TEST_BUNDLE_NAME].ownership.size(), 2);
    EXPECT_EQ(mergeData[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME].adminBundleName, TEST_ADMIN_A);
    EXPECT_TRUE(mergeData[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME].isForceOverride);
    EXPECT_EQ(mergeData[TEST_BUNDLE_NAME].ownership[TEST_OTHER_POLICY_NAME].adminBundleName, TEST_ADMIN_B);
    EXPECT_FALSE(mergeData[TEST_BUNDLE_NAME].ownership[TEST_OTHER_POLICY_NAME].isForceOverride);
}

/**
 * @tc.name: TestMigrateOwnershipIfNeededNeverOverwritesRecordedOwnership
 * @tc.desc: The ownership backfill never overwrites an ownership record that is already there.
 *           The backfill is guarded by a process wide one shot flag, so the backfill may or may
 *           not have run already when this case executes. Both outcomes are asserted through
 *           the same invariant: a recorded ownership survives the call untouched.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestMigrateOwnershipIfNeededNeverOverwritesRecordedOwnership, TestSize.Level1)
{
    auto policyManager = AcquirePolicyManager();
    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    mergePolicies[TEST_BUNDLE_NAME].version = 1;
    mergePolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    ManagedBrowserPolicyOwnership owner;
    owner.adminBundleName = TEST_ADMIN_B;
    owner.isForceOverride = true;
    mergePolicies[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME] = owner;

    plugin_.MigrateOwnershipIfNeeded(mergePolicies);

    ASSERT_EQ(mergePolicies[TEST_BUNDLE_NAME].ownership.size(), 1);
    EXPECT_EQ(mergePolicies[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME].adminBundleName, TEST_ADMIN_B);
    EXPECT_TRUE(mergePolicies[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME].isForceOverride);
}

/**
 * @tc.name: TestOnHandlePolicyForceOverrideWithEmptyAdminName
 * @tc.desc: A force override by an unknown admin is accepted and the item is recorded without
 *           an owner name, so the request is not rejected on an empty admin identity.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyForceOverrideWithEmptyAdminName, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.mergePolicyData = BuildMergePolicyData(TEST_ADMIN_A, false, true);
    policyData.currentAdminName = "";
    MessageParcel data;
    BuildSetPolicyParcel(data, true);
    ErrCode ret = plugin.OnHandlePolicy(BuildFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY), data,
        reply, policyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);

    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    DeserializeOrFail(policyData.mergePolicyData, mergePolicies);
    ASSERT_EQ(mergePolicies[TEST_BUNDLE_NAME].ownership.count(TEST_POLICY_NAME), 1);
    EXPECT_TRUE(mergePolicies[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME].adminBundleName.empty());
    EXPECT_TRUE(mergePolicies[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME].isForceOverride);
}

/**
 * @tc.name: TestOnHandlePolicyForceOverrideRemovesItemOwnership
 * @tc.desc: A force override that clears the policy value also clears the ownership record, so
 *           the next admin may claim the item again.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyForceOverrideRemovesItemOwnership, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.mergePolicyData = BuildMergePolicyData(TEST_ADMIN_A, false, true);
    policyData.currentAdminName = TEST_ADMIN_B;
    MessageParcel data;
    data.WriteString(TEST_BUNDLE_NAME);
    data.WriteString(TEST_POLICY_NAME);
    data.WriteString("");
    data.WriteBool(true);
    ErrCode ret = plugin.OnHandlePolicy(BuildFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY), data,
        reply, policyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);

    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    DeserializeOrFail(policyData.mergePolicyData, mergePolicies);
    EXPECT_EQ(mergePolicies[TEST_BUNDLE_NAME].ownership.count(TEST_POLICY_NAME), 0);
}

/**
 * @tc.name: TestOnHandlePolicyPlainPathRejectsOwnedPolicyWithFalseForceFlag
 * @tc.desc: A false force flag is a plain set, so an admin that does not own the item is
 *           still rejected.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyPlainPathRejectsOwnedPolicyWithFalseForceFlag,
    TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.mergePolicyData = BuildMergePolicyData(TEST_ADMIN_A, false, true);
    policyData.currentAdminName = TEST_ADMIN_B;
    MessageParcel data;
    BuildSetPolicyParcel(data, false);
    ErrCode ret = plugin.OnHandlePolicy(BuildFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY),
        data, reply, policyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);
    EXPECT_FALSE(policyData.isChanged);
}

/**
 * @tc.name: TestOnHandlePolicyOwnerCanRewritePolicyAlsoListedByOtherAdmin
 * @tc.desc: After a force override the ownership belongs to the current admin, but the policy
 *           name is still listed by the other admin private view, because a force override does
 *           not remove the entry from the overridden admin. The owner must still be able to
 *           rewrite its own policy without force, so the merged view name list must not reject
 *           the owner that the ownership record already accepts.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyOwnerCanRewritePolicyAlsoListedByOtherAdmin,
    TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    HandlePolicyData policyData;
    policyData.mergePolicyData = BuildMergePolicyData(TEST_ADMIN_B, true, true);
    policyData.currentAdminName = TEST_ADMIN_B;
    std::map<std::string, ManagedBrowserPolicyType> currentPolicies;
    currentPolicies[TEST_BUNDLE_NAME].version = 1;
    currentPolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    std::string currentData;
    ManagedBrowserPolicySerializer::GetInstance()->Serialize(currentPolicies, currentData);
    policyData.policyData = currentData;

    MessageParcel data;
    BuildSetPolicyParcel(data, false);
    ErrCode ret = plugin.OnHandlePolicy(BuildFuncCode(EdmInterfaceCode::MANAGED_BROWSER_POLICY),
        data, reply, policyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(policyData.isChanged);

    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    DeserializeOrFail(policyData.mergePolicyData, mergePolicies);
    auto owner = mergePolicies[TEST_BUNDLE_NAME].ownership.find(TEST_POLICY_NAME);
    ASSERT_NE(owner, mergePolicies[TEST_BUNDLE_NAME].ownership.end());
    EXPECT_EQ(owner->second.adminBundleName, TEST_ADMIN_B);
}

/**
 * @tc.name: TestUpdateCurrentAndMergePolicyAllowsOwnerWhenNameListedByOtherAdmin
 * @tc.desc: The merged view name list alone must not reject the admin that owns the item, the
 *           ownership record decides whether a plain write is allowed.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestUpdateCurrentAndMergePolicyAllowsOwnerWhenNameListedByOtherAdmin,
    TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    std::map<std::string, ManagedBrowserPolicyType> policies;
    policies[TEST_BUNDLE_NAME].version = 1;
    policies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    mergePolicies[TEST_BUNDLE_NAME].version = 1;
    mergePolicies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    ManagedBrowserPolicyOwnership owner;
    owner.adminBundleName = TEST_ADMIN_B;
    owner.isForceOverride = true;
    mergePolicies[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME] = owner;
    ManagedBrowserPolicyPlugin::ManagedBrowserPolicyRequest request{TEST_BUNDLE_NAME, TEST_POLICY_NAME,
        TEST_POLICY_VALUE, false};

    ASSERT_EQ(plugin.UpdateCurrentAndMergePolicy(policies, mergePolicies, request, TEST_ADMIN_B), ERR_OK);
    EXPECT_EQ(CountName(policies[TEST_BUNDLE_NAME].policyNames, TEST_POLICY_NAME), 1);
}

/**
 * @tc.name: TestReadForceOverrideFlagReadsFlagForAnyOperateType
 * @tc.desc: The force flag is read from the parcel whatever the operate type is, so the parcel
 *           layout stays consistent across operate types.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestReadForceOverrideFlagReadsFlagForAnyOperateType, TestSize.Level1)
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
 * @tc.name: TestReadForceOverrideFlagReadsFlagOnPlainPolicyCode
 * @tc.desc: The force override flag is carried in the parcel of the shared browser policy
 *           interface, so the plain policy code reads it as well and the policy takeover
 *           request is not lost.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestReadForceOverrideFlagReadsFlagOnPlainPolicyCode, TestSize.Level1)
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
 * @tc.name: TestOnAdminRemoveSucRemovesPolicyFile
 * @tc.desc: Removing the admin deletes the browser policy file it created, so the browser
 *           no longer serves policies for a removed admin.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnAdminRemoveSucRemovesPolicyFile, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    std::ofstream policyFile(URL);
    ASSERT_FALSE(policyFile.fail());
    policyFile << "\"test_policy_name\":\"test_policy_value\"" << std::endl;
    policyFile.close();

    ErrCode ret = plugin.OnAdminRemove(TEST_ADMIN_A, TEST_POLICY_DATA, "", DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    std::ifstream inFile(URL);
    EXPECT_TRUE(inFile.fail());
}

/**
 * @tc.name: TestOnAdminRemoveFailWithMalformedPolicyData
 * @tc.desc: A malformed blob aborts the removal before any file is deleted.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnAdminRemoveFailWithMalformedPolicyData, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    std::ofstream policyFile(URL);
    ASSERT_FALSE(policyFile.fail());
    policyFile.close();

    ErrCode ret = plugin.OnAdminRemove(TEST_ADMIN_A, "broken", "", DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::SYSTEM_ABNORMALLY);
    std::ifstream inFile(URL);
    EXPECT_FALSE(inFile.fail());
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS