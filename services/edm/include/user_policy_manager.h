/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef SERVICES_EDM_INCLUDE_EDM_USER_POLICY_MANAGER_H
#define SERVICES_EDM_INCLUDE_EDM_USER_POLICY_MANAGER_H

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include "device_policies_storage_rdb.h"
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
class UserPolicyManager {
public:
    UserPolicyManager(int32_t userId);

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

private:
    UserPolicyManager();
    ErrCode DeleteAdminPolicy(const std::string &adminName, const std::string &policyName);
    ErrCode DeleteCombinedPolicy(const std::string &policyName);
    ErrCode GetAdminPolicy(const std::string &adminName, const std::string &policyName, std::string &policyValue);
    ErrCode GetCombinedPolicy(const std::string &policyName, std::string &policyValue);
    ErrCode SetAdminPolicy(const std::string &adminName, const std::string &policyName, const std::string &policyValue);
    ErrCode SetCombinedPolicy(const std::string &policyName, const std::string &policyValue);
    void DeleteAdminList(const std::string &adminName, const std::string &policyName);
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

    int32_t userIdState_ = 100;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_EDM_USER_POLICY_MANAGER_H
