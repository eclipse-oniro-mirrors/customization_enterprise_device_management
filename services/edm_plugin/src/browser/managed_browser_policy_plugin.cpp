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

#include "managed_browser_policy_plugin.h"

#include <fcntl.h>
#include <fstream>
#include <ipc_skeleton.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <mutex>
#include "bundle_manager_utils.h"
#include "cjson_check.h"
#include "cjson_serializer.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "edm_bundle_manager_impl.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_utils.h"
#include "managed_browser_policy_serializer.h"
#include "iplugin_manager.h"
#include "security_label.h"
#include "want.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<ManagedBrowserPolicyPlugin>());
const char* const MANAGED_BROWSER_POLICY_DIR = "/data/service/el1/public/edm/browser/";
const char* const MANAGED_BROWSER_POLICY_SUFFIX = ".dat";
const char* const BROWSER_POLICY_CHANGED_EVENT = "usual.event.MANAGED_BROWSER_POLICY_CHANGED";
const char* const EMPTY_POLICY = "{}";
constexpr int32_t EMPTY_POLICY_SIZE = 3;
constexpr int32_t MAX_POLICY_FILE_SIZE = 134217728; // 128 * 1024 * 1024

ManagedBrowserPolicyPlugin::ManagedBrowserPolicyPlugin()
{
    policyCode_ = EdmInterfaceCode::MANAGED_BROWSER_POLICY;
    policyName_ = PolicyName::POLICY_MANAGED_BROWSER_POLICY;
    permissionMap_.insert(std::make_pair(
        FuncOperateType::SET, IPlugin::PolicyPermissionConfig(EdmPermission::PERMISSION_ENTERPRISE_SET_BROWSER_POLICY,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC)));
    permissionMap_.insert(std::make_pair(
        FuncOperateType::GET, IPlugin::PolicyPermissionConfig("", IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        IPlugin::ApiType::PUBLIC)));
    needSave_ = true;
}

ErrCode ManagedBrowserPolicyPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    EDMLOGI("ManagedBrowserPolicyPlugin OnHandlePolicy.");
    ManagedBrowserPolicyRequest request;
    std::map<std::string, ManagedBrowserPolicyType> policies;
    std::map<std::string, ManagedBrowserPolicyType> mergePolicies;
    bool isModifyOrRemove = false;
    ErrCode ret = PreparePolicyContext(data, policyData, request, policies, mergePolicies, isModifyOrRemove);
    if (FAILED(ret)) {
        return ret;
    }

    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    const std::string &bundleName = request.bundleName;
    const std::string &policyName = request.policyName;
    const std::string &policyValue = request.policyValue;
    const std::string &adminName = policyData.currentAdminName;

    ret = UpdateCurrentAndMergePolicy(policies, mergePolicies, request, adminName);
    if (FAILED(ret)) {
        return ret;
    }

    UpdatePolicyOwnership(mergePolicies[bundleName], policyName, adminName, request.isForceOverride,
        policyValue.empty());

    std::string afterHandle;
    std::string afterMerge;
    if (!serializer->Serialize(policies, afterHandle) || !serializer->Serialize(mergePolicies, afterMerge)) {
        EDMLOGE("ManagedBrowserPolicyPlugin::OnHandlePolicy Serialize current policy and merge policy failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }

    ret = ApplyPolicyToBrowserFile(policies, bundleName, policyName, policyValue, isModifyOrRemove);
    if (ret != ERR_OK) {
        return ret;
    }

    policyData.isChanged = true;
    policyData.policyData = afterHandle;
    policyData.mergePolicyData = afterMerge;
    return ret;
}

ErrCode ManagedBrowserPolicyPlugin::PreparePolicyContext(MessageParcel &data, const HandlePolicyData &policyData,
    ManagedBrowserPolicyRequest &request, std::map<std::string, ManagedBrowserPolicyType> &policies,
    std::map<std::string, ManagedBrowserPolicyType> &mergePolicies, bool &isModifyOrRemove)
{
    request.bundleName = data.ReadString();
    request.policyName = data.ReadString();
    request.policyValue = data.ReadString();
    if (request.bundleName.empty() || request.policyName.empty() ||
        request.bundleName.find("..") != std::string::npos) {
        return EdmReturnErrCode::PARAM_ERROR;
    }

    ErrCode forceFlagRet = ReadForceOverrideFlag(data, request.isForceOverride);
    if (FAILED(forceFlagRet)) {
        return forceFlagRet;
    }

    ErrCode deserializeRet = DeserializeAndMigrate(policyData, policies, mergePolicies);
    if (FAILED(deserializeRet)) {
        return deserializeRet;
    }

    const std::vector<std::string> &policyNames = policies[request.bundleName].policyNames;
    isModifyOrRemove = (std::find(policyNames.begin(), policyNames.end(), request.policyName) != policyNames.end());

    return CheckPolicyOwnership(mergePolicies[request.bundleName], request.policyName,
        policyData.currentAdminName, request.isForceOverride);
}

ErrCode ManagedBrowserPolicyPlugin::ApplyPolicyToBrowserFile(std::map<std::string, ManagedBrowserPolicyType> &policies,
    const std::string &bundleName, const std::string &policyName, std::string policyValue, bool isModifyOrRemove)
{
    size_t pos = 0;
    while ((pos = policyValue.find("\n", pos)) != std::string::npos) {
        policyValue.replace(pos, 1, "");
    }
    if (isModifyOrRemove) {
        return ModifyOrRemoveManagedBrowserPolicy(policies, bundleName, policyName, policyValue);
    }
    return AddManagedBrowserPolicy(policies, bundleName, policyName, policyValue);
}

ErrCode ManagedBrowserPolicyPlugin::ReadForceOverrideFlag(MessageParcel &data, bool &isForceOverride)
{
    if (!data.ReadBool(isForceOverride)) {
        EDMLOGE("ManagedBrowserPolicyPlugin::OnHandlePolicy force override flag invalid.");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    return ERR_OK;
}

ErrCode ManagedBrowserPolicyPlugin::DeserializeAndMigrate(const HandlePolicyData &policyData,
    std::map<std::string, ManagedBrowserPolicyType> &policies,
    std::map<std::string, ManagedBrowserPolicyType> &mergePolicies)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    if (!serializer->Deserialize(policyData.policyData, policies) ||
        !serializer->Deserialize(policyData.mergePolicyData, mergePolicies)) {
        EDMLOGE("ManagedBrowserPolicyPlugin::OnHandlePolicy Deserialize current policy and merge policy failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }

    MigrateOwnershipIfNeeded(mergePolicies);
    return ERR_OK;
}

bool ManagedBrowserPolicyPlugin::IsOwnedByAdmin(const ManagedBrowserPolicyType &mergedPolicy,
    const std::string &policyName, const std::string &adminName)
{
    if (adminName.empty()) {
        return false;
    }
    auto it = mergedPolicy.ownership.find(policyName);
    if (it == mergedPolicy.ownership.end()) {
        return false;
    }
    return it->second.adminBundleName == adminName;
}

ErrCode ManagedBrowserPolicyPlugin::CheckPolicyOwnership(const ManagedBrowserPolicyType &mergedPolicy,
    const std::string &policyName, const std::string &adminName, bool isForceOverride)
{
    if (isForceOverride) {
        return ERR_OK;
    }
    auto it = mergedPolicy.ownership.find(policyName);
    if (it == mergedPolicy.ownership.end()) {
        return ERR_OK;
    }
    if (!adminName.empty() && it->second.adminBundleName == adminName) {
        return ERR_OK;
    }
    EDMLOGE("ManagedBrowserPolicyPlugin policy %{public}s is owned by admin %{public}s and cannot be changed here.",
        policyName.c_str(), it->second.adminBundleName.c_str());
    return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
}

void ManagedBrowserPolicyPlugin::UpdatePolicyOwnership(ManagedBrowserPolicyType &mergedPolicy,
    const std::string &policyName, const std::string &adminName, bool isForceOverride, bool isRemoved)
{
    if (isRemoved) {
        mergedPolicy.ownership.erase(policyName);
        return;
    }
    ManagedBrowserPolicyOwnership owner;
    owner.adminBundleName = adminName;
    owner.isForceOverride = isForceOverride;
    mergedPolicy.ownership[policyName] = owner;
}

void ManagedBrowserPolicyPlugin::MigrateOwnershipIfNeeded(
    std::map<std::string, ManagedBrowserPolicyType> &mergePolicies)
{
    static std::once_flag onceFlag;
    std::call_once(onceFlag, [this, &mergePolicies]() {
        BackfillOwnership(mergePolicies);
    });
}

void ManagedBrowserPolicyPlugin::CollectPolicyOwners(const AdminValueItemsMap &adminValues,
    std::map<std::string, std::string> &owners)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    for (const auto &entry : adminValues) {
        std::map<std::string, ManagedBrowserPolicyType> adminPolicies;
        if (entry.second.empty() || !serializer->Deserialize(entry.second, adminPolicies)) {
            EDMLOGW("ManagedBrowserPolicyPlugin::MigrateOwnershipIfNeeded skip admin %{public}s",
                entry.first.c_str());
            continue;
        }
        CollectAdminPolicyOwners(entry.first, adminPolicies, owners);
    }
}

void ManagedBrowserPolicyPlugin::CollectAdminPolicyOwners(const std::string &adminName,
    const std::map<std::string, ManagedBrowserPolicyType> &adminPolicies,
    std::map<std::string, std::string> &owners)
{
    for (const auto &policyIt : adminPolicies) {
        for (const auto &policyName : policyIt.second.policyNames) {
            RecordPolicyOwner(policyIt.first, policyName, adminName, owners);
        }
    }
}

void ManagedBrowserPolicyPlugin::RecordPolicyOwner(const std::string &bundleName, const std::string &policyName,
    const std::string &adminName, std::map<std::string, std::string> &owners)
{
    std::string key = bundleName + "|" + policyName;
    if (owners.find(key) != owners.end()) {
        return;
    }
    owners[key] = adminName;
}

void ManagedBrowserPolicyPlugin::ApplyPolicyOwners(const std::map<std::string, std::string> &owners,
    std::map<std::string, ManagedBrowserPolicyType> &mergePolicies, bool &hasBackfilled)
{
    for (auto &mergeIt : mergePolicies) {
        for (const auto &policyName : mergeIt.second.policyNames) {
            if (mergeIt.second.ownership.find(policyName) != mergeIt.second.ownership.end()) {
                continue;
            }
            auto ownerIt = owners.find(mergeIt.first + "|" + policyName);
            if (ownerIt == owners.end()) {
                continue;
            }
            ManagedBrowserPolicyOwnership owner;
            owner.adminBundleName = ownerIt->second;
            owner.isForceOverride = false;
            mergeIt.second.ownership[policyName] = owner;
            hasBackfilled = true;
        }
    }
}

void ManagedBrowserPolicyPlugin::BackfillOwnership(std::map<std::string, ManagedBrowserPolicyType> &mergePolicies)
{
    AdminValueItemsMap adminValues;
    IPolicyManager::GetInstance()->GetAdminByPolicyName(GetPolicyName(), adminValues);
    if (adminValues.empty()) {
        return;
    }
    std::map<std::string, std::string> owners;
    CollectPolicyOwners(adminValues, owners);
    bool hasBackfilled = false;
    ApplyPolicyOwners(owners, mergePolicies, hasBackfilled);
    if (hasBackfilled) {
        EDMLOGI("ManagedBrowserPolicyPlugin::MigrateOwnershipIfNeeded backfilled ownership records.");
    }
}

ErrCode ManagedBrowserPolicyPlugin::UpdateCurrentAndMergePolicy(
    std::map<std::string, ManagedBrowserPolicyType> &policies,
    std::map<std::string, ManagedBrowserPolicyType> &mergePolicies, const ManagedBrowserPolicyRequest &request,
    const std::string &adminName)
{
    const std::string &bundleName = request.bundleName;
    const std::string &policyName = request.policyName;
    const std::string &policyValue = request.policyValue;

    auto mergedIt = mergePolicies.find(bundleName);
    if (!request.isForceOverride && mergedIt != mergePolicies.end() &&
        !IsOwnedByAdmin(mergedIt->second, policyName, adminName) &&
        std::find(mergedIt->second.policyNames.begin(),
            mergedIt->second.policyNames.end(), policyName) != mergedIt->second.policyNames.end()) {
        EDMLOGE("ManagedBrowserPolicyPlugin another admin has already set this item policy for this application.");
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }

    std::vector<std::string> &policyNames = policies[bundleName].policyNames;
    auto it = std::find(policyNames.begin(), policyNames.end(), policyName);
    if (it != policyNames.end()) {
        if (policyValue.empty()) {
            policyNames.erase(it);
        }
    } else {
        policies[bundleName].policyNames.push_back(policyName);
    }
    policies[bundleName].version++;

    for (auto &policy : policies) {
        auto mergeIt = mergePolicies.find(policy.first);
        if (mergeIt == mergePolicies.end()) {
            mergePolicies[policy.first] = policy.second;
            continue;
        }
        mergeIt->second.version++;
        std::vector<std::string> &mergedNames = mergeIt->second.policyNames;
        for (const auto &name : policy.second.policyNames) {
            if (std::find(mergedNames.begin(), mergedNames.end(), name) != mergedNames.end()) {
                continue;
            }
            mergedNames.push_back(name);
        }
    }
    return ERR_OK;
}

ErrCode ManagedBrowserPolicyPlugin::GetOthersMergePolicyData(const std::string &adminName, int32_t userId,
    std::string &othersMergePolicyData)
{
    AdminValueItemsMap adminValues;
    IPolicyManager::GetInstance()->GetAdminByPolicyName(GetPolicyName(), adminValues);
    EDMLOGD("IPluginTemplate::GetOthersMergePolicyData %{public}s value size %{public}d.", GetPolicyName().c_str(),
        (uint32_t)adminValues.size());
    if (adminValues.empty()) {
        return ERR_OK;
    }
    auto entry = adminValues.find(adminName);
    if (entry != adminValues.end()) {
        adminValues.erase(entry);
    }
    if (adminValues.empty()) {
        return ERR_OK;
    }

    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    std::map<std::string, ManagedBrowserPolicyType> mergeData;
    ErrCode ret = MergeAdminPolicies(adminValues, mergeData);
    if (FAILED(ret)) {
        return ret;
    }

    ret = MergeCombinedOwnership(mergeData);
    if (FAILED(ret)) {
        return ret;
    }

    if (!serializer->Serialize(mergeData, othersMergePolicyData)) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode ManagedBrowserPolicyPlugin::MergeAdminPolicies(const AdminValueItemsMap &adminValues,
    std::map<std::string, ManagedBrowserPolicyType> &mergeData)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    for (const auto &adminEntry : adminValues) {
        std::map<std::string, ManagedBrowserPolicyType> adminPolicies;
        if (adminEntry.second.empty()) {
            continue;
        }
        if (!serializer->Deserialize(adminEntry.second, adminPolicies)) {
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        for (const auto &policyEntry : adminPolicies) {
            auto mergeIt = mergeData.find(policyEntry.first);
            if (mergeIt == mergeData.end()) {
                mergeData[policyEntry.first] = policyEntry.second;
                continue;
            }
            mergeIt->second.policyNames.insert(mergeIt->second.policyNames.end(),
                policyEntry.second.policyNames.begin(), policyEntry.second.policyNames.end());
            if (policyEntry.second.version > mergeIt->second.version) {
                mergeIt->second.version = policyEntry.second.version;
            }
        }
    }
    return ERR_OK;
}

ErrCode ManagedBrowserPolicyPlugin::MergeCombinedOwnership(std::map<std::string, ManagedBrowserPolicyType> &mergeData)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    std::string combinedPolicy;
    IPolicyManager::GetInstance()->GetPolicy("", GetPolicyName(), combinedPolicy);
    std::map<std::string, ManagedBrowserPolicyType> combinedData;
    if (combinedPolicy.empty() || !serializer->Deserialize(combinedPolicy, combinedData)) {
        return ERR_OK;
    }
    for (auto &combinedIt : combinedData) {
        auto mergeIt = mergeData.find(combinedIt.first);
        if (mergeIt == mergeData.end() || combinedIt.second.ownership.empty()) {
            continue;
        }
        for (const auto &ownerIt : combinedIt.second.ownership) {
            if (std::find(mergeIt->second.policyNames.begin(), mergeIt->second.policyNames.end(),
                ownerIt.first) == mergeIt->second.policyNames.end()) {
                continue;
            }
            mergeIt->second.ownership[ownerIt.first] = ownerIt.second;
        }
    }
    return ERR_OK;
}

// LCOV_EXCL_START
ErrCode ManagedBrowserPolicyPlugin::ModifyOrRemoveManagedBrowserPolicy(
    std::map<std::string, ManagedBrowserPolicyType> &policies, const std::string &bundleName,
    const std::string &policyName, const std::string &policyValue)
{
    EDMLOGI("ManagedBrowserPolicyPlugin::ModifyOrRemoveManagedBrowserPolicy start");
    std::string url = MANAGED_BROWSER_POLICY_DIR + bundleName + MANAGED_BROWSER_POLICY_SUFFIX;
    if (!EdmUtils::CheckRealPath(url, MANAGED_BROWSER_POLICY_DIR)) {
        EDMLOGE("ManagedBrowserPolicyPlugin::CheckRealPath fail");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::ifstream inFile(url);
    if (inFile.fail()) {
        EDMLOGE("ManagedBrowserPolicyPlugin::ModifyOrRemoveManagedBrowserPolicy open file fail");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }

    std::string tempUrl = MANAGED_BROWSER_POLICY_DIR + bundleName + "_tmp" + MANAGED_BROWSER_POLICY_SUFFIX;
    std::ofstream tempOutFile(tempUrl);
    if (tempOutFile.fail()) {
        EDMLOGE("ManagedBrowserPolicyPlugin::ModifyOrRemoveManagedBrowserPolicy open file fail");
        inFile.close();
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::string policyNameWithQuotation = "\"" + policyName + "\"";
    std::string line;
    while (std::getline(inFile, line)) {
        std::string policyNameInLine;
        if (!FindPolicyNameInLine(line, policyNameInLine)) {
            EDMLOGE("can not find policyNameInLine");
            remove(tempUrl.c_str());
            inFile.close();
            tempOutFile.close();
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }

        if (policyNameInLine == policyNameWithQuotation) {
            if (policyValue.empty()) {
                continue;
            } else {
                tempOutFile << policyNameWithQuotation << ":" << policyValue << std::endl;
            }
        } else {
            tempOutFile << line << std::endl;
        }
    }

    inFile.close();
    tempOutFile.close();

    return UpdatePolicyFile(policies, bundleName, url, tempUrl) ? ERR_OK : EdmReturnErrCode::SYSTEM_ABNORMALLY;
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
ErrCode ManagedBrowserPolicyPlugin::AddManagedBrowserPolicy(std::map<std::string, ManagedBrowserPolicyType> &policies,
    const std::string &bundleName, const std::string &policyName, const std::string &policyValue)
{
    std::string url = MANAGED_BROWSER_POLICY_DIR + bundleName + MANAGED_BROWSER_POLICY_SUFFIX;
    std::ofstream outfile(url, std::ios::app);
    if (outfile.fail()) {
        EDMLOGE("ManagedBrowserPolicyPlugin::AddManagedBrowserPolicy open file fail");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::string newPolicy = "\"" + policyName + "\":" + policyValue;
    outfile << newPolicy << std::endl;
    outfile.close();
    return ERR_OK;
}
// LCOV_EXCL_STOP

void ManagedBrowserPolicyPlugin::OnHandlePolicyDone(std::uint32_t funcCode, const std::string &adminName,
    bool isGlobalChanged, int32_t userId)
{
    EDMLOGD("ManagedBrowserPolicyPlugin::OnHandlePolicyDone called");
    PublishEventToBrowser();
}

ErrCode ManagedBrowserPolicyPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    std::string type = data.ReadString();
    EDMLOGI("ManagedBrowserPolicyPlugin::OnGetPolicy type %{public}s", type.c_str());
    std::string bundleName;
    if (type == EdmConstants::Browser::GET_MANAGED_BROWSER_FILE_DATA) {
        bundleName = data.ReadString();
    } else if (!GetCallingBundleName(bundleName)) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (bundleName.empty() || bundleName.find("..") != std::string::npos) {
        EDMLOGI("ManagedBrowserPolicyPlugin::OnGetPolicy bundleName error");
        return EdmReturnErrCode::PARAM_ERROR;
    }

    if (type == EdmConstants::Browser::GET_MANAGED_BROWSER_VERSION) {
        return GetManagedBrowserPolicyVersion(policyData, bundleName, reply);
    } else if (type == EdmConstants::Browser::GET_MANAGED_BROWSER_FILE_DATA ||
        type == EdmConstants::Browser::GET_SELF_MANAGED_BROWSER_FILE_DATA) {
        return GetManagedBrowserPolicyFileData(bundleName, reply);
    } else {
        EDMLOGE("ManagedBrowserPolicyPlugin::OnGetPolicy type error");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
}

// LCOV_EXCL_START
ErrCode ManagedBrowserPolicyPlugin::GetManagedBrowserPolicyFileData(const std::string &bundleName, MessageParcel &reply)
{
    std::string url = MANAGED_BROWSER_POLICY_DIR + bundleName + MANAGED_BROWSER_POLICY_SUFFIX;
    if (!EdmUtils::CheckRealPath(url, MANAGED_BROWSER_POLICY_DIR)) {
        EDMLOGE("ManagedBrowserPolicyPlugin::CheckRealPath fail");
        reply.WriteInt32(ERR_OK);
        reply.WriteInt32(EMPTY_POLICY_SIZE);
        reply.WriteRawData(reinterpret_cast<const void*>(EMPTY_POLICY), EMPTY_POLICY_SIZE);
        return ERR_OK;
    }
    std::ifstream infile(url, std::ios::binary | std::ios::ate);
    if (infile.fail()) {
        EDMLOGE("ManagedBrowserPolicyPlugin::OnGetPolicy open file fail");
        reply.WriteInt32(ERR_OK);
        reply.WriteInt32(EMPTY_POLICY_SIZE);
        reply.WriteRawData(reinterpret_cast<const void*>(EMPTY_POLICY), EMPTY_POLICY_SIZE);
        return ERR_OK;
    }
    std::streamsize size = infile.tellg();
    if (size < 0 || size >= MAX_POLICY_FILE_SIZE) {
        EDMLOGE("ManagedBrowserPolicyPlugin::OnGetPolicy size error.size: %{public}d", (int32_t)size);
        infile.close();
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    infile.seekg(0, std::ios::beg);
    std::string line;
    std::vector<char> fileData;
    fileData.push_back('{');
    while (std::getline(infile, line)) {
        fileData.insert(fileData.end(), line.begin(), line.end());
        if (fileData.back() == '\n') {
            fileData.pop_back();
        }
        fileData.push_back(',');
    }
    if (fileData.back() == ',') {
        fileData.pop_back();
    }
    fileData.push_back('}');
    fileData.push_back('\0');
    infile.close();
    if (fileData.size() < 0 || fileData.size() >= MAX_POLICY_FILE_SIZE) {
        EDMLOGE("ManagedBrowserPolicyPlugin::OnGetPolicy fileData.size error.size: %{public}d",
            (int32_t)fileData.size());
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteInt32(fileData.size());
    reply.WriteRawData(reinterpret_cast<const void*>(fileData.data()), fileData.size());
    return ERR_OK;
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
ErrCode ManagedBrowserPolicyPlugin::GetManagedBrowserPolicyVersion(const std::string &policyData,
    const std::string &bundleName, MessageParcel &reply)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    std::map<std::string, ManagedBrowserPolicyType> policies;
    if (!serializer->Deserialize(policyData, policies)) {
        EDMLOGE("ManagedBrowserPolicyPlugin::OnGetPolicy Deserialize fail");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    reply.WriteInt32(ERR_OK);
    auto it = policies.find(bundleName);
    if (it == policies.end()) {
        int32_t emptyVersion = 0;
        reply.WriteInt32(emptyVersion);
    } else {
        reply.WriteInt32((int32_t)it->second.version);
    }
    return ERR_OK;
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
bool ManagedBrowserPolicyPlugin::FindPolicyNameInLine(const std::string &line, std::string &policyNameInLine)
{
    size_t pos = line.find(':');
    if (pos != std::string::npos && pos > 0) {
        policyNameInLine = line.substr(0, pos);
        return true;
    }
    return false;
}
// LCOV_EXCL_STOP

bool ManagedBrowserPolicyPlugin::GetCallingBundleName(std::string &bundleName)
{
    auto bundleMgr = std::make_shared<EdmBundleManagerImpl>();
    int uid = IPCSkeleton::GetCallingUid();
    if (bundleMgr->GetNameForUid(uid, bundleName) != ERR_OK || bundleName.empty()) {
        EDMLOGW("ManagedBrowserPolicyPlugin::OnGetPolicy failed: get bundleName for uid %{public}d fail.", uid);
        return false;
    }
    return true;
}

ErrCode ManagedBrowserPolicyPlugin::OnAdminRemove(const std::string &adminName,
    const std::string &policyData, const std::string &mergeData, int32_t userId)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    std::map<std::string, ManagedBrowserPolicyType> policies;
    if (!serializer->Deserialize(policyData, policies)) {
        EDMLOGE("ManagedBrowserPolicyPlugin::OnAdminRemove Deserialize fail");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    for (auto& it : policies) {
        std::string url = MANAGED_BROWSER_POLICY_DIR + it.first + MANAGED_BROWSER_POLICY_SUFFIX;
        if (remove(url.c_str()) != 0) {
            EDMLOGE("ManagedBrowserPolicyPlugin::OnAdminRemove remove failed.bundleName:%{public}s", it.first.c_str());
        }
    }
    PublishEventToBrowser();
    return ERR_OK;
}

// LCOV_EXCL_START
bool ManagedBrowserPolicyPlugin::UpdatePolicyFile(std::map<std::string, ManagedBrowserPolicyType> &policies,
    const std::string &bundleName, std::string &url, std::string &tempUrl)
{
    if (remove(url.c_str()) != 0) {
        remove(tempUrl.c_str());
        EDMLOGE("ManagedBrowserPolicyPlugin::updatePolicyFile remove inFile fail");
        return false;
    }

    if (rename(tempUrl.c_str(), url.c_str()) != 0) {
        remove(tempUrl.c_str());
        policies.erase(bundleName);
        EDMLOGE("ManagedBrowserPolicyPlugin::updatePolicyFile rename tempFile fail");
        return false;
    }
    return true;
}
// LCOV_EXCL_STOP

void ManagedBrowserPolicyPlugin::PublishEventToBrowser()
{
    AAFwk::Want want;
    want.SetAction(BROWSER_POLICY_CHANGED_EVENT);
    EventFwk::CommonEventData eventData;
    eventData.SetWant(want);
    if (!EventFwk::CommonEventManager::PublishCommonEvent(eventData)) {
        EDMLOGE("NotifyBrowserPolicyChanged failed.");
    }
}
} // namespace EDM
} // namespace OHOS
