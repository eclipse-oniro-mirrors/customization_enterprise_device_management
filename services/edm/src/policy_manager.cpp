/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "policy_manager.h"
#include <algorithm>
#include <ctime>
#include <fstream>
#include <unistd.h>
#include "directory_ex.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
const std::string EDM_POLICY_JSON_FILE = "/data/service/el1/public/edm/device_policies.json";
const std::string EDM_POLICY_JSON_FILE_BAK = "/data/service/el1/public/edm/device_policies.json.bak";
constexpr unsigned int INVALID_INDEX = -1;

std::shared_ptr<PolicyManager> PolicyManager::instance_;
std::mutex PolicyManager::mutexLock_;

PolicyManager::PolicyManager()
{
    EDMLOGD("PolicyManager::PolicyManager\n");
}

PolicyManager::~PolicyManager()
{
    EDMLOGD("PolicyManager::~PolicyManager\n");
}

bool PolicyManager::ParsePolicyItems(const Json::Value &items, PolicyItemsMap &itemsMap)
{
    if (!items.isObject()) {
        EDMLOGW("ParsePolicyItems items is not object");
        return false;
    }

    Json::Value::Members mem = items.getMemberNames();
    for (const auto &i : mem) {
        Json::StreamWriterBuilder builder;
        builder["indentation"] = "    ";
        std::string arrayToString = Json::writeString(builder, items[i]);
        itemsMap.insert(std::pair<std::string, std::string>(i, arrayToString));
    }
    return true;
}

bool PolicyManager::ParseAdminList(const std::string &adminName, const PolicyItemsMap &itemsMap)
{
    for (const auto &iter : itemsMap) {
        std::string policyName = iter.first;
        std::string policyValue = iter.second;
        auto it = policyAdmins_.find(policyName);
        if (it == policyAdmins_.end()) {
            /* policy first added into map */
            AdminValueItemsMap adminValueItem;
            adminValueItem.insert(std::pair<std::string, std::string>(adminName, policyValue));
            policyAdmins_.insert(std::pair<std::string, AdminValueItemsMap>(policyName, adminValueItem));
        } else {
            AdminValueItemsMap &adminValueRef = it->second;
            auto iterValue = adminValueRef.find(adminName);
            if (iterValue != adminValueRef.end()) {
                EDMLOGW("AdminName:%{public}s PolicyName:%{public}s should not repetitive\n",
                        adminName.c_str(), policyName.c_str());
                iterValue->second = policyValue;
            } else {
                adminValueRef.insert(std::pair<std::string, std::string>(adminName, policyValue));
            }
        }
    }
    return true;
}

bool PolicyManager::ParseAdminPolicy(const Json::Value &admin)
{
    std::string adminName;
    PolicyItemsMap itemsMap;
    if (!admin.isObject()) {
        EDMLOGI("admin root policy is not object\n");
        return false;
    }

    if (admin.isMember("AdminName") && admin["AdminName"].isString()) {
        adminName = admin["AdminName"].asString();
    }

    bool isParsePolicySuccess = false;
    bool isParseAdminListSuccess = false;
    if (admin.isMember("PolicyItems") && admin["PolicyItems"].isObject() && !adminName.empty()) {
        isParsePolicySuccess = ParsePolicyItems(admin["PolicyItems"], itemsMap);
        adminPolicies_.insert(std::pair<std::string, PolicyItemsMap>(adminName, itemsMap));
        isParseAdminListSuccess = ParseAdminList(adminName, itemsMap);
    }
    return isParsePolicySuccess && isParseAdminListSuccess;
}

bool PolicyManager::ParseCombinedPolicy(const Json::Value &combined)
{
    if (!combined.isObject()) {
        EDMLOGI("combined root is not object\n");
        return false;
    }
    return ParsePolicyItems(combined, combinedPolicies_);
}

ErrCode PolicyManager::ParseDevicePolicyJsonFile(const Json::Value &policyRoot)
{
    if (!policyRoot.isObject()) {
        EDMLOGW("json root is not object\n");
        return ERR_EDM_POLICY_PARSE_JSON_FAILED;
    }

    bool isParseAdminSuccess = false;
    bool isParseCombinedSuccess = false;
    if (policyRoot.isMember("AdminPolicies") && policyRoot["AdminPolicies"].isArray()) {
        for (const auto &item : policyRoot["AdminPolicies"]) {
            if (!item.isObject()) {
                EDMLOGI("is not object");
                return ERR_EDM_POLICY_PARSE_JSON_FAILED;
            }
            isParseAdminSuccess = ParseAdminPolicy(item);
            if (!isParseAdminSuccess) {
                EDMLOGI("AdminPolicies parse failed object");
                return ERR_EDM_POLICY_PARSE_JSON_FAILED;
            }
        }
    }

    if (isParseAdminSuccess) {
        if (policyRoot.isMember("CombinedPolicies") && policyRoot["CombinedPolicies"].isObject()) {
            isParseCombinedSuccess = ParseCombinedPolicy(policyRoot["CombinedPolicies"]);
        }
    } else {
        EDMLOGW("ParseAdminPolicy failed\n");
    }

    if (isParseAdminSuccess && isParseCombinedSuccess) {
        return ERR_OK;
    }
    return ERR_EDM_POLICY_PARSE_JSON_FAILED;
}

ErrCode PolicyManager::LoadPolicy()
{
    if (access(EDM_POLICY_JSON_FILE.c_str(), F_OK) != 0) {
        EDMLOGI("LoadPolicy: create an empty json file\n");
        CreateEmptyJsonFile();
    }

    std::ifstream ifs(EDM_POLICY_JSON_FILE);
    if (!ifs.is_open()) {
        EDMLOGE("LoadPolicy: open edm policy json file failed\n");
        return ERR_EDM_POLICY_OPEN_JSON_FAILED;
    }

    Json::String errs;
    Json::CharReaderBuilder builder;
    if (!parseFromStream(builder, ifs, &policyRoot_, &errs)) {
        EDMLOGW("parse from stream failed: %{public}s\n", errs.c_str());
        ifs.close();
        return ERR_EDM_POLICY_LOAD_JSON_FAILED;
    }
    ifs.close();
    return ParseDevicePolicyJsonFile(policyRoot_);
}

void PolicyManager::SavePolicy()
{
    /* the default file permission is 600, no need to change  */
    std::ofstream ofs(EDM_POLICY_JSON_FILE_BAK, std::ofstream::binary);
    if (!ofs.is_open()) {
        EDMLOGW("SavePolicy open edm policy json file failed\n");
        return;
    }

    double time1 = clock();
    Json::StreamWriterBuilder builder;
    /* use 4 spaces instead of tab for indentation */
    builder["indentation"] = "    ";
    const std::unique_ptr<Json::StreamWriter> writer(builder.newStreamWriter());
    writer->write(policyRoot_, &ofs);

    ofs.flush();
    ofs.close();
    double time2 = clock();
    std::rename(EDM_POLICY_JSON_FILE_BAK.c_str(), EDM_POLICY_JSON_FILE.c_str());
    if (!ChangeModeFile(EDM_POLICY_JSON_FILE, S_IRUSR | S_IWUSR)) {
        EDMLOGW("PolicyManager::ChangeModeFile failed");
    }
    double time3 = clock();
    EDMLOGI("SavePolicy spend time %{public}f, %{public}f", (time2 - time1) / CLOCKS_PER_SEC,
        (time3 - time2) / CLOCKS_PER_SEC);
}

ErrCode PolicyManager::GetAdminByPolicyName(const std::string &policyName, AdminValueItemsMap &adminValueItems)
{
    auto iter = policyAdmins_.find(policyName);
    if (iter != policyAdmins_.end()) {
        adminValueItems = iter->second;
        return ERR_OK;
    }
    return ERR_EDM_POLICY_NOT_FOUND;
}

ErrCode PolicyManager::GetAllPolicyByAdmin(const std::string &adminName, PolicyItemsMap &allAdminPolicy)
{
    auto iter = adminPolicies_.find(adminName);
    if (iter != adminPolicies_.end()) {
        allAdminPolicy = iter->second;
        return ERR_OK;
    }
    return ERR_EDM_POLICY_NOT_FIND;
}

ErrCode PolicyManager::GetAdminPolicy(const std::string &adminName, const std::string &policyName,
    std::string &policyValue)
{
    auto iter = adminPolicies_.find(adminName);
    if (iter != adminPolicies_.end()) {
        PolicyItemsMap &policyItem = iter->second;
        auto it = policyItem.find(policyName);
        if (it != policyItem.end()) {
            policyValue = it->second;
            return ERR_OK;
        }
    }
    return ERR_EDM_POLICY_NOT_FIND;
}

ErrCode PolicyManager::GetCombinedPolicy(const std::string &policyName, std::string &policyValue)
{
    auto it = combinedPolicies_.find(policyName);
    if (it != combinedPolicies_.end()) {
        policyValue = it->second;
        return ERR_OK;
    }
    return ERR_EDM_POLICY_NOT_FIND;
}

bool PolicyManager::GetAdminItemJsonObject(const Json::Value &admin, const std::string &adminName)
{
    if (admin.isMember("AdminName") && admin["AdminName"].isString()) {
        std::string adminItemName = admin["AdminName"].asString();
        if ((adminItemName == adminName) && (admin.isMember("PolicyItems") && admin["PolicyItems"].isObject())) {
            return true;
        }
    }
    return false;
}

ErrCode PolicyManager::GetPolicy(const std::string &adminName, const std::string &policyName,
    std::string &policyValue)
{
    if (adminName.empty()) {
        return GetCombinedPolicy(policyName, policyValue);
    } else {
        return GetAdminPolicy(adminName, policyName, policyValue);
    }
}

void PolicyManager::SetAdminList(const std::string &adminName, const std::string &policyName,
    const std::string &policyValue)
{
    auto iter = policyAdmins_.find(policyName);
    if (iter == policyAdmins_.end()) {
        /* policy first added into map */
        AdminValueItemsMap adminValueItem;
        adminValueItem.insert(std::pair<std::string, std::string>(adminName, policyValue));
        policyAdmins_.insert(std::pair<std::string, AdminValueItemsMap>(policyName, adminValueItem));
        return;
    }

    AdminValueItemsMap &adminValueRef = iter->second;
    auto it = adminValueRef.find(adminName);
    if (it != adminValueRef.end()) {
        it->second = policyValue;
    } else {
        adminValueRef.insert(std::pair<std::string, std::string>(adminName, policyValue));
    }
}

bool PolicyManager::SetAdminPolicyItemJsonValue(Json::Value &admin, const std::string &adminName,
    const std::string &policyName, const std::string &policyValue)
{
    if (GetAdminItemJsonObject(admin, adminName)) {
        Json::Value policyValueRoot;
        if (ParseJsonString(policyValue, policyValueRoot) != ERR_OK) {
            return false;
        }
        Json::Value &adminObject = admin["PolicyItems"];
        adminObject[policyName] = policyValueRoot;
        return true;
    }
    return false;
}

ErrCode PolicyManager::ParseJsonString(const std::string &policyValue, Json::Value &policyValueRoot)
{
    const auto policyValueLength = static_cast<int>(policyValue.length());
    JSONCPP_STRING err;
    Json::CharReaderBuilder builder;
    const std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    if (!reader->parse(policyValue.c_str(), policyValue.c_str() + policyValueLength, &policyValueRoot, &err)) {
        policyValueRoot = Json::Value(policyValue);
    }
    return ERR_OK;
}

ErrCode PolicyManager::SetAdminJsonValue(const std::string &adminName, const std::string &policyName,
    const std::string &policyValue)
{
    if (policyRoot_.isMember("AdminPolicies") && policyRoot_["AdminPolicies"].isArray()) {
        for (auto &admin : policyRoot_["AdminPolicies"]) {
            if (admin.isObject() && SetAdminPolicyItemJsonValue(admin, adminName, policyName, policyValue)) {
                EDMLOGW("SetAdminJsonValue exist:%{public}s %{public}s ", adminName.c_str(), policyName.c_str());
                return ERR_OK;
            }
        }
        EDMLOGI("SetAdminJsonValue new object:%{public}s %{public}s ", adminName.c_str(), policyName.c_str());
        Json::Value policyValueRoot;
        if (ParseJsonString(policyValue, policyValueRoot) != ERR_OK) {
            return ERR_EDM_POLICY_SET_FAILED;
        }

        Json::Value adminObject;
        Json::Value policyItemsObject;
        adminObject["AdminName"] = adminName;
        policyItemsObject[policyName] = policyValueRoot;
        adminObject["PolicyItems"] = policyItemsObject;
        policyRoot_["AdminPolicies"].append(adminObject);
        return ERR_OK;
    }
    return ERR_EDM_POLICY_SET_FAILED;
}

ErrCode PolicyManager::SetAdminPolicy(const std::string &adminName, const std::string &policyName,
    const std::string &policyValue)
{
    SetAdminList(adminName, policyName, policyValue);
    auto iter = adminPolicies_.find(adminName);
    if (iter == adminPolicies_.end()) {
        PolicyItemsMap itemMap;
        itemMap.insert(std::pair<std::string, std::string>(policyName, policyValue));
        adminPolicies_.insert(std::pair<std::string, PolicyItemsMap>(adminName, itemMap));
        return SetAdminJsonValue(adminName, policyName, policyValue);
    }

    PolicyItemsMap &policyItem = iter->second;
    auto it = policyItem.find(policyName);
    if (it != policyItem.end()) {
        it->second = policyValue;
    } else {
        policyItem.insert(std::pair<std::string, std::string>(policyName, policyValue));
    }
    return SetAdminJsonValue(adminName, policyName, policyValue);
}

ErrCode PolicyManager::SetCombinedJsonValue(const std::string &policyName, const std::string &policyValue)
{
    if (policyRoot_.isMember("CombinedPolicies") && policyRoot_["CombinedPolicies"].isObject()) {
        Json::Value policyValueRoot;
        if (ParseJsonString(policyValue, policyValueRoot) != ERR_OK) {
            return ERR_EDM_POLICY_SET_FAILED;
        }
        policyRoot_["CombinedPolicies"][policyName] = policyValueRoot;
        return ERR_OK;
    }
    return ERR_EDM_POLICY_SET_FAILED;
}

ErrCode PolicyManager::SetCombinedPolicy(const std::string &policyName, const std::string &policyValue)
{
    auto it = combinedPolicies_.find(policyName);
    if (it != combinedPolicies_.end()) {
        it->second = policyValue;
    } else {
        combinedPolicies_.insert(std::pair<std::string, std::string>(policyName, policyValue));
    }
    return SetCombinedJsonValue(policyName, policyValue);
}

void PolicyManager::DeleteAdminList(const std::string &adminName, const std::string &policyName)
{
    auto iter = policyAdmins_.find(policyName);
    if (iter == policyAdmins_.end()) {
        return;
    }

    AdminValueItemsMap &adminValueRef = iter->second;
    auto it = adminValueRef.find(adminName);
    if (it == adminValueRef.end()) {
        return;
    }

    adminValueRef.erase(it);
    if (adminValueRef.empty()) {
        policyAdmins_.erase(iter);
    }
}

bool PolicyManager::DeleteAdminPolicyItemJsonValue(Json::Value &admin, const std::string &adminName,
    const std::string &policyName, unsigned int &policyItemsNum)
{
    if (GetAdminItemJsonObject(admin, adminName)) {
        Json::Value &adminObject = admin["PolicyItems"];
        if (adminObject.isMember(policyName)) {
            adminObject.removeMember(policyName);
            policyItemsNum = adminObject.size();
            return true;
        }
    }
    return false;
}

ErrCode PolicyManager::DeleteAdminJsonValue(const std::string &adminName, const std::string &policyName)
{
    if (!policyRoot_.isMember("AdminPolicies") || !policyRoot_["AdminPolicies"].isArray()) {
        return ERR_EDM_POLICY_DEL_FAILED;
    }
    unsigned int policyItemsNum = 0;
    unsigned int deleteIndex = INVALID_INDEX;
    unsigned int policyRootSize = policyRoot_["AdminPolicies"].size();
    for (Json::ArrayIndex i = 0; i < policyRootSize; i++) {
        Json::Value &admin = policyRoot_["AdminPolicies"][i];
        if (admin.isObject() && DeleteAdminPolicyItemJsonValue(admin, adminName, policyName, policyItemsNum)) {
            if (policyItemsNum == 0) {
                deleteIndex = i;
                break;
            }
        }
    }
    if (deleteIndex != INVALID_INDEX) {
        policyRoot_["AdminPolicies"].removeIndex(deleteIndex, nullptr);
    }
    return ERR_OK;
}

ErrCode PolicyManager::DeleteAdminPolicy(const std::string &adminName, const std::string &policyName)
{
    auto iter = adminPolicies_.find(adminName);
    if (iter != adminPolicies_.end()) {
        PolicyItemsMap &policyItem = iter->second;
        auto it = policyItem.find(policyName);
        if (it != policyItem.end()) {
            policyItem.erase(it);
        }

        if (iter->second.empty()) {
            adminPolicies_.erase(iter);
        }

        DeleteAdminList(adminName, policyName);
        return DeleteAdminJsonValue(adminName, policyName);
    }
    return ERR_OK;
}

ErrCode PolicyManager::DeleteCombinedJsonValue(const std::string &policyName)
{
    if (policyRoot_.isMember("CombinedPolicies") && policyRoot_["CombinedPolicies"].isObject()) {
        Json::Value &rootObject = policyRoot_["CombinedPolicies"];
        if (rootObject.isMember(policyName)) {
            rootObject.removeMember(policyName);
            return true;
        }
    }
    return ERR_EDM_POLICY_DEL_FAILED;
}

ErrCode PolicyManager::DeleteCombinedPolicy(const std::string &policyName)
{
    auto it = combinedPolicies_.find(policyName);
    if (it != combinedPolicies_.end()) {
        combinedPolicies_.erase(it);
    }
    return DeleteCombinedJsonValue(policyName);
}

void PolicyManager::DumpAdminPolicy()
{
    std::for_each(adminPolicies_.begin(), adminPolicies_.end(), [](auto iter) {
        EDMLOGD("AdminName: %{public}s\n", iter.first.c_str());
        std::unordered_map<std::string, std::string> map = iter.second;
        std::for_each(map.begin(), map.end(),
            [](auto subIter) { EDMLOGD("%{public}s : %{public}s\n", subIter.first.c_str(), subIter.second.c_str()); });
    });
}

void PolicyManager::DumpAdminList()
{
    std::for_each(policyAdmins_.begin(), policyAdmins_.end(), [](auto iter) {
        EDMLOGD("PolicyName: %{public}s\n", iter.first.c_str());
        std::unordered_map<std::string, std::string> map = iter.second;
        std::for_each(map.begin(), map.end(),
            [](auto subIter) { EDMLOGD("%{public}s : %{public}s\n", subIter.first.c_str(), subIter.second.c_str()); });
    });
}

void PolicyManager::DumpCombinedPolicy()
{
    std::for_each(combinedPolicies_.begin(), combinedPolicies_.end(),
        [](auto iter) { EDMLOGD("%{public}s : %{public}s\n", iter.first.c_str(), iter.second.c_str()); });
}

ErrCode PolicyManager::SetPolicy(const std::string &adminName, const std::string &policyName,
    const std::string &adminPolicy, const std::string &mergedPolicy)
{
    if (policyName.empty()) {
        return ERR_EDM_POLICY_SET_FAILED;
    }

    ErrCode err;
    if (mergedPolicy.empty()) {
        err = DeleteCombinedPolicy(policyName);
    } else {
        err = SetCombinedPolicy(policyName, mergedPolicy);
    }
    if (FAILED(err)) {
        EDMLOGW("Set or delete combined policy failed:%{public}d, merged policy:%{public}s\n",
            err, mergedPolicy.c_str());
    }

    if (!adminName.empty()) {
        if (adminPolicy.empty()) {
            err = DeleteAdminPolicy(adminName, policyName);
        } else {
            err = SetAdminPolicy(adminName, policyName, adminPolicy);
        }
    }
    if (FAILED(err)) {
        EDMLOGW("Set or delete admin policy failed:%{public}d, admin policy:%{public}s\n",
            err, adminPolicy.c_str());
    }

    SavePolicy();
    return err;
}

void PolicyManager::CreateEmptyJsonFile()
{
    Json::Value adminObject(Json::arrayValue);
    Json::Value combinedObject(Json::objectValue);
    policyRoot_["AdminPolicies"] = adminObject;
    policyRoot_["CombinedPolicies"] = combinedObject;
    SavePolicy();
}

void PolicyManager::Init()
{
    LoadPolicy();
}

std::shared_ptr<PolicyManager> PolicyManager::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutexLock_);
        if (instance_ == nullptr) {
            instance_.reset(new (std::nothrow) PolicyManager());
        }
    }
    return instance_;
}
} // namespace EDM
} // namespace OHOS
