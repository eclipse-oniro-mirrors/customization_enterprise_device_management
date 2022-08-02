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

#ifndef SERVICES_EDM_INCLUDE_EDM_POLICY_MANAGER_H
#define SERVICES_EDM_INCLUDE_EDM_POLICY_MANAGER_H

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include "edm_errors.h"
#include "json/json.h"

namespace OHOS {
namespace EDM {
using PolicyItemsMap = std::unordered_map<std::string, std::string>;     /* PolicyName and PolicyValue pair */
using AdminValueItemsMap = std::unordered_map<std::string, std::string>; /* AdminName and PolicyValue pair */

/*
 * This class is used to load and store /data/service/el1/public/edm/device_policies.json file.
 * provide the Get and Set api to operate on json file, the read and write json
 * file depend on jsoncpp library
 */
class PolicyManager : public std::enable_shared_from_this<PolicyManager> {
public:
    /*
     * The static function used to get singleton instance of PolicyManager.
     *
     * @return return thr shared pointer of PolicyManager
     */
    static std::shared_ptr<PolicyManager> GetInstance();

    /*
     * This function is used to get all policy items of an admin, an admin represent an EDM application
     *
     * @param adminName the application's bundle name
     * @param allAdminPolicy the all policy item packaged in std::unordered_map
     * @return return thr ErrCode of this function
     */
    ErrCode GetAllPolicyByAdmin(const std::string &adminName, PolicyItemsMap &allAdminPolicy);

    /*
     * This function is used to get policy items by admin name policy name
     * If the adminName is null, will get the combined policy, otherwise will
     * get the admin policy
     *
     * @param adminName the application's bundle name
     * @param policyName the policy item name
     * @param policyValue the policy value which the caller wanted to get
     * @return return thr ErrCode of this function
     */
    ErrCode GetPolicy(const std::string &adminName, const std::string &policyName, std::string &policyValue);

    /*
     * This function is used to set policy items by admin name policy name. If the adminName is null,
     * will set the combined policy. If the policyName is null, will set the admin policy, otherwise will
     * set both the admin policy and merged policy, if the policy value is null, the policy item will be
     * deleted, this function will write json file. write merged policy and admin policy simultaneously
     * is very useful for atomic operation
     *
     * @param adminName the application's bundle name
     * @param policyName the policy item name
     * @param adminPolicyValue the admin policy value which the caller wanted to set
     * @param mergedPolicyValue the merged policy value which the caller wanted to set
     * @return return thr ErrCode of this function
     */
    ErrCode SetPolicy(const std::string &adminName, const std::string &policyName, const std::string &adminPolicyValue,
        const std::string &mergedPolicyValue);

    /*
     * This function is used to get admin name by policy name, then the caller will know
     * which application set the policy
     *
     * @param policyName the policy item name
     * @param adminValueItems the all admin name and policy value packaged in std::unordered_map
     * @return return thr ErrCode of this function
     */
    ErrCode GetAdminByPolicyName(const std::string &policyName, AdminValueItemsMap &adminValueItems);

    /*
     * This function is used to init the PolicyManager, must be called before any of other api
     * init function will read and parse json file and construct some std::unordered_map to
     * provide get and set operation
     */
    void Init();

    /*
     * This function is debug api used to print all admin policy
     */
    void DumpAdminPolicy();

    /*
     * This function is debug api used to print all admin list
     */
    void DumpAdminList();

    /*
     * This function is debug api used to print all combined policy
     */
    void DumpCombinedPolicy();

    virtual ~PolicyManager();

private:
    PolicyManager();
    bool DeleteAdminPolicyItemJsonValue(Json::Value &admin, const std::string &adminName,
        const std::string &policyName, unsigned int &policyItemsNum);
    bool GetAdminItemJsonObject(const Json::Value &admin, const std::string &adminName);
    bool ParseAdminList(const std::string &adminName, const PolicyItemsMap &itemsMap);
    bool ParseAdminPolicy(const Json::Value &admin);
    bool ParseCombinedPolicy(const Json::Value &combined);
    bool ParsePolicyItems(const Json::Value &items, PolicyItemsMap &itemsMap);
    bool SetAdminPolicyItemJsonValue(Json::Value &admin, const std::string &adminName, const std::string &policyName,
        const std::string &policyValue);

    ErrCode DeleteAdminJsonValue(const std::string &adminName, const std::string &policyName);
    ErrCode DeleteAdminPolicy(const std::string &adminName, const std::string &policyName);
    ErrCode DeleteCombinedJsonValue(const std::string &policyName);
    ErrCode DeleteCombinedPolicy(const std::string &policyName);
    ErrCode GetAdminPolicy(const std::string &adminName, const std::string &policyName, std::string &policyValue);
    ErrCode GetCombinedPolicy(const std::string &policyName, std::string &policyValue);
    ErrCode LoadPolicy();
    ErrCode SetAdminJsonValue(const std::string &adminName, const std::string &policyName,
        const std::string &policyValue);
    ErrCode SetAdminPolicy(const std::string &adminName, const std::string &policyName, const std::string &policyValue);
    ErrCode SetCombinedJsonValue(const std::string &policyName, const std::string &policyValue);
    ErrCode SetCombinedPolicy(const std::string &policyName, const std::string &policyValue);
    ErrCode ParseDevicePolicyJsonFile(const Json::Value &policyRoot);
    ErrCode ParseJsonString(const std::string &policyValue, Json::Value &policyValueRoot);

    void CreateEmptyJsonFile();
    void DeleteAdminList(const std::string &adminName, const std::string &policyName);
    void SavePolicy();
    void SetAdminList(const std::string &adminName, const std::string &policyName, const std::string &policyValue);

    /*
     * This member is the combined policy and combined value pair
     */
    PolicyItemsMap combinedPolicies_;

    /*
     * This member is the admin name and policyName, policyValue pairs
     */
    std::unordered_map<std::string, PolicyItemsMap> adminPolicies_;

    /*
     * This member is the policy name and adminName, policyValue pairs
     */
    std::unordered_map<std::string, AdminValueItemsMap> policyAdmins_;

    /*
     * This member is the json root, used to parse and write json file
     */
    Json::Value policyRoot_;

    /*
     * This member is the singleton instance of PolicyManager
     */
    static std::shared_ptr<PolicyManager> instance_;

    /*
     * This member is the mutex lock used to ensure the instance_ is unique
     */
    static std::mutex mutexLock_;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_EDM_POLICY_MANAGER_H
