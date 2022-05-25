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

#include "enterprise_device_mgr_ability.h"
#include <bundle_info.h>
#include <bundle_mgr_interface.h>
#include <ipc_skeleton.h>
#include <iservice_registry.h>
#include <message_parcel.h>
#include <permission/permission_kit.h>
#include <string_ex.h>
#include <system_ability.h>
#include <system_ability_definition.h>

#include "accesstoken_kit.h"
#include "bundle_mgr_proxy.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "edm_log.h"
#include "matching_skills.h"
#include "parameters.h"
#include "plugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT =
    SystemAbility::MakeAndRegisterAbility(EnterpriseDeviceMgrAbility::GetInstance().GetRefPtr());

std::mutex EnterpriseDeviceMgrAbility::mutexLock_;

sptr<EnterpriseDeviceMgrAbility> EnterpriseDeviceMgrAbility::instance_;

constexpr int32_t DEFAULT_USER_ID = 100;
EnterpriseDeviceEventSubscriber::EnterpriseDeviceEventSubscriber(const EventFwk::CommonEventSubscribeInfo &subscribeInfo,
    EnterpriseDeviceMgrAbility &listener) : EventFwk::CommonEventSubscriber(subscribeInfo), listener_(listener) {}

void EnterpriseDeviceEventSubscriber::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    const std::string action = data.GetWant().GetAction();
    EDMLOGI("OnReceiveEvent get action: %{public}s", action.c_str());
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED) {
        int userIdToRemove = data.GetCode() ;
        if (userIdToRemove != 0) {
            EDMLOGI("OnReceiveEvent user removed userid : %{public}d", userIdToRemove);
            listener_.OnUserRemoved(userIdToRemove);
        }
    } else {
        EDMLOGW("OnReceiveEvent action is invalid");
    }
}

std::shared_ptr<EventFwk::CommonEventSubscriber> EnterpriseDeviceMgrAbility::CreateEnterpriseDeviceEventSubscriber(
    EnterpriseDeviceMgrAbility &listener)
{
    EventFwk::MatchingSkills skill = EventFwk::MatchingSkills();
    skill.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED);
    EventFwk::CommonEventSubscribeInfo info(skill);
    return std::make_shared<EnterpriseDeviceEventSubscriber>(info, listener);
}

void EnterpriseDeviceMgrAbility::OnUserRemoved(int userIdToRemove)
{
    EDMLOGI("OnUserRemoved");
}

sptr<EnterpriseDeviceMgrAbility> EnterpriseDeviceMgrAbility::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> autoLock(mutexLock_);
        if (instance_ == nullptr) {
            EDMLOGD("EnterpriseDeviceMgrAbility:GetInstance instance = new EnterpriseDeviceMgrAbility()");
            instance_ = new EnterpriseDeviceMgrAbility();
        }
    }
    return instance_;
}

EnterpriseDeviceMgrAbility::EnterpriseDeviceMgrAbility() : SystemAbility(ENTERPRISE_DEVICE_MANAGER_SA_ID, true)
{
    EDMLOGI("EnterpriseDeviceMgrAbility:new instance");
}

EnterpriseDeviceMgrAbility::~EnterpriseDeviceMgrAbility()
{
    instance_ = nullptr;

    if (adminMgr_) {
        adminMgr_.reset();
    }

    if (pluginMgr_) {
        pluginMgr_.reset();
    }

    if (policyMgr_) {
        policyMgr_.reset();
    }
    EDMLOGD("instance is destroyed");
}

void EnterpriseDeviceMgrAbility::OnDump() {}

void EnterpriseDeviceMgrAbility::OnStart()
{
    EDMLOGD("EnterpriseDeviceMgrAbility::OnStart() Publish");
    if (!registerToService_) {
        if (!Publish(this)) {
            EDMLOGE("EnterpriseDeviceMgrAbility: res == false");
            return;
        }
        registerToService_ = true;
    }
    if (!adminMgr_) {
        adminMgr_ = AdminManager::GetInstance();
    }
    EDMLOGD("create adminMgr_ success");
    adminMgr_->Init();

    if (!policyMgr_) {
        policyMgr_ = PolicyManager::GetInstance();
    }
    EDMLOGD("create policyMgr_ success");
    policyMgr_->Init();

    if (!pluginMgr_) {
        pluginMgr_ = PluginManager::GetInstance();
    }
    EDMLOGD("create pluginMgr_ success");
    pluginMgr_->Init();

    AddSystemAbilityListener(COMMON_EVENT_SERVICE_ID);
}

void EnterpriseDeviceMgrAbility::OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    EDMLOGD("OnAddSystemAbility systemAbilityId:%{public}d added!", systemAbilityId);
    commonEventSubscriber = CreateEnterpriseDeviceEventSubscriber(*this);
    EventFwk::CommonEventManager::SubscribeCommonEvent(this->commonEventSubscriber);
    EDMLOGI("create commonEventSubscriber success");
}

void EnterpriseDeviceMgrAbility::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
}


void EnterpriseDeviceMgrAbility::OnStop()
{
    EDMLOGD("EnterpriseDeviceMgrAbility::OnStop()");
}

ErrCode EnterpriseDeviceMgrAbility::GetAllPermissionsByAdmin(const std::string &bundleInfoName,
    std::vector<std::string> &permissionList, int32_t userId)
{
    bool ret = false;
    AppExecFwk::BundleInfo bundleInfo;
    auto bundleManager = GetBundleMgr();
    permissionList.clear();
    EDMLOGD("GetAllPermissionsByAdmin GetBundleInfo: bundleInfoName %{public}s userid %{public}d",
        bundleInfoName.c_str(), userId);
    ret = bundleManager->GetBundleInfo(bundleInfoName, AppExecFwk::BundleFlag::GET_BUNDLE_WITH_REQUESTED_PERMISSION,
        bundleInfo, userId);
    if (!ret) {
        EDMLOGW("GetAllPermissionsByAdmin: GetBundleInfo failed %{public}d", ret);
        return ERR_EDM_PARAM_ERROR;
    }
    std::vector<std::string> reqPermission = bundleInfo.reqPermissions;
    if (reqPermission.empty()) {
        EDMLOGW("GetAllPermissionsByAdmin: bundleInfo reqPermissions empty");
        return ERR_OK;
    }

    std::vector<EdmPermission> edmPermissions;
    ErrCode code = adminMgr_->GetReqPermission(reqPermission, edmPermissions);
    if (SUCCEEDED(code)) {
        for (const auto &perm : edmPermissions) {
            permissionList.push_back(perm.getPermissionName());
        }
    }
    return ERR_OK;
}

sptr<AppExecFwk::IBundleMgr> EnterpriseDeviceMgrAbility::GetBundleMgr()
{
    OHOS::sptr<OHOS::ISystemAbilityManager> systemAbilityManager =
        OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    OHOS::sptr<OHOS::IRemoteObject> remoteObject =
        systemAbilityManager->GetSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> proxy(new AppExecFwk::BundleMgrProxy(remoteObject));
    return proxy;
}

ErrCode EnterpriseDeviceMgrAbility::CheckPermission()
{
    if (VerifyCallingPermission("ohos.permission.MANAGE_ADMIN")) {
        EDMLOGD("check permission success");
        return ERR_OK;
    }
    return ERR_EDM_PERMISSION_ERROR;
}

bool EnterpriseDeviceMgrAbility::VerifyCallingPermission(const std::string &permissionName)
{
    EDMLOGD("VerifyCallingPermission permission %{public}s", permissionName.c_str());
    Security::AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    EDMLOGD("callerToken : %{public}u", callerToken);
    Security::AccessToken::ATokenTypeEnum tokenType =
        Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    if (tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE) {
        EDMLOGD("caller tokenType is native, verify success");
        return true;
    }
    int32_t ret = Security::AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, permissionName);
    if (ret == Security::AccessToken::PermissionState::PERMISSION_DENIED) {
        EDMLOGE("permission %{public}s: PERMISSION_DENIED", permissionName.c_str());
        return false;
    }
    EDMLOGD("verify AccessToken success");
    return true;
}

ErrCode EnterpriseDeviceMgrAbility::VerifyActiveAdminCondition(AppExecFwk::ElementName &admin,
    AdminType type, int32_t userId)
{
    std::shared_ptr<Admin> existAdmin = adminMgr_->GetAdminByPkgName(admin.GetBundleName());
    if (type == AdminType::ENT && adminMgr_->IsSuperAdminExist()) {
        if (existAdmin == nullptr || existAdmin->adminInfo_.adminType_ != AdminType::ENT) {
            EDMLOGW("ActiveAdmin: There is another super admin active.");
            return ERR_EDM_ADD_ADMIN_FAILED;
        }
    }

    if (type == AdminType::ENT && userId != DEFAULT_USER_ID) {
        EDMLOGW("ActiveAdmin: Super admin can only be enabled in default user.");
        return ERR_EDM_ADD_ADMIN_FAILED;
    }

    if (existAdmin == nullptr) {
        return ERR_OK;
    }

    /* An application can't active twice with different ability name */
    if (existAdmin->adminInfo_.className_ != admin.GetAbilityName()) {
        EDMLOGW("ActiveAdmin: There is another admin ability active with the same package name.");
        return ERR_EDM_ADD_ADMIN_FAILED;
    }

    /* An existed super admin can't be reactive to normal */
    if ((existAdmin->adminInfo_.adminType_ == AdminType::ENT) && (type == AdminType::NORMAL)) {
        EDMLOGW("ActiveAdmin: The admin is super, can't be reactive to normal.");
        return ERR_EDM_ADD_ADMIN_FAILED;
    }
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::ActiveAdmin(AppExecFwk::ElementName &admin, EntInfo &entInfo, AdminType type,
    int32_t userId)
{
    EDMLOGD("EnterpriseDeviceMgrAbility::ActiveAdmin user id = %{public}d", userId);
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    int32_t ret = CheckPermission();
    if (ret != ERR_OK) {
        EDMLOGW("EnterpriseDeviceMgrAbility::ActiveAdmin check permission failed, ret: %{public}d", ret);
        return ERR_EDM_PERMISSION_ERROR;
    }
    std::vector<AppExecFwk::AbilityInfo> abilityInfo;
    auto bundleManager = GetBundleMgr();
    if (!bundleManager) {
        EDMLOGW("can not get iBundleMgr");
        return ERR_EDM_BMS_ERROR;
    }
    AAFwk::Want want;
    want.SetElement(admin);
    if (!bundleManager->QueryAbilityInfos(want, AppExecFwk::AbilityInfoFlag::GET_ABILITY_INFO_WITH_APPLICATION,
        userId, abilityInfo)) {
        EDMLOGW("ActiveAdmin: GetAbilityInfoByName failed %{public}d", ret);
        return ERR_EDM_BMS_ERROR;
    }
    ret = VerifyActiveAdminCondition(admin, type, userId);
    if (FAILED(ret)) {
        EDMLOGW("ActiveAdmin: VerifyActiveAdminCondition failed.");
        return ERR_EDM_ADD_ADMIN_FAILED;
    }

    /* Get all request and registered permissions */
    std::vector<std::string> permissionList;
    ret = GetAllPermissionsByAdmin(admin.GetBundleName(), permissionList, userId);
    if (FAILED(ret)) {
        EDMLOGW("ActiveAdmin: GetAllPermissionsByAdmin failed %{public}d", ret);
        return ERR_EDM_ADD_ADMIN_FAILED;
    }
    /* Filter permissions with AdminType, such as NORMAL can't request super permission */
    ret = adminMgr_->GetGrantedPermission(abilityInfo.at(0), permissionList, type);
    if (ret != ERR_OK) {
        EDMLOGW("ActiveAdmin: GetGrantedPermission failed %{public}d", ret);
        // permission verify, should throw exception if failed
        return ERR_EDM_ADD_ADMIN_FAILED;
    }

    EDMLOGI("ActiveAdmin: SetAdminValue success %{public}s, type:%{public}d", admin.GetBundleName().c_str(),
        static_cast<uint32_t>(type));
    return adminMgr_->SetAdminValue(abilityInfo.at(0), entInfo, type, permissionList);
}

ErrCode EnterpriseDeviceMgrAbility::RemoveAdminItem(std::string adminName, std::string policyName,
    std::string policyValue)
{
    ErrCode ret;
    std::shared_ptr<IPlugin> plugin = pluginMgr_->GetPluginByPolicyName(policyName);
    if (plugin == nullptr) {
        EDMLOGW("RemoveAdminItem: Get plugin by policy failed: %{public}s\n", policyName.c_str());
        return ERR_EDM_GET_PLUGIN_MGR_FAILED;
    }
    if ((ret = plugin->OnAdminRemove(adminName, policyValue)) != ERR_OK) {
        EDMLOGW("RemoveAdminItem: OnAdminRemove failed, admin:%{public}s, value:%{public}s, res:%{public}d\n",
            adminName.c_str(), policyValue.c_str(), ret);
    }
    if (plugin->NeedSavePolicy()) {
        std::string mergedPolicyData = "";
        if ((ret = plugin->MergePolicyData(adminName, mergedPolicyData)) != ERR_OK) {
            EDMLOGW("RemoveAdminItem: Get admin by policy name failed: %{public}s, ErrCode:%{public}d\n",
                policyName.c_str(), ret);
        }

        ErrCode setRet = ERR_OK;
        std::unordered_map<std::string, std::string> adminListMap;
        ret = policyMgr_->GetAdminByPolicyName(policyName, adminListMap);
        if ((ret == ERR_EDM_POLICY_NOT_FOUND) || adminListMap.empty()) {
            setRet = policyMgr_->SetPolicy("", policyName, "", "");
        } else {
            setRet = policyMgr_->SetPolicy(adminName, policyName, "", mergedPolicyData);
        }

        if (FAILED(setRet)) {
            EDMLOGW("RemoveAdminItem: DeleteAdminPolicy failed, admin:%{public}s, policy:%{public}s, res:%{public}d\n",
                adminName.c_str(), policyName.c_str(), ret);
            return ERR_EDM_DEL_ADMIN_FAILED;
        }
    }
    plugin->OnAdminRemoveDone(adminName, policyValue);
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::RemoveAdmin(const std::string &adminName)
{
    EDMLOGD("RemoveAdmin %{public}s", adminName.c_str());
    std::unordered_map<std::string, std::string> policyItems;
    policyMgr_->GetAllPolicyByAdmin(adminName, policyItems);
    for (auto &policyItem : policyItems) {
        std::string policyItemName = policyItem.first;
        std::string policyItemValue = policyItem.second;
        EDMLOGD("RemoveAdmin: RemoveAdminItem policyName:%{public}s,policyValue:%{public}s", policyItemName.c_str(),
            policyItemValue.c_str());
        if (RemoveAdminItem(adminName, policyItemName, policyItemValue) != ERR_OK) {
            return ERR_EDM_DEL_ADMIN_FAILED;
        }
    }
    if (adminMgr_->DeleteAdmin(adminName) != ERR_OK) {
        return ERR_EDM_DEL_ADMIN_FAILED;
    }
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::DeactiveAdmin(AppExecFwk::ElementName &admin, int32_t userId)
{
    EDMLOGW("EnterpriseDeviceMgrAbility::DeactiveAdmin user id = %{public}d", userId);
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    int32_t checkRet = CheckPermission();
    if (checkRet != ERR_OK) {
        EDMLOGW("EnterpriseDeviceMgrAbility::DeactiveAdmin check permission failed, ret: %{public}d", checkRet);
        return ERR_EDM_PERMISSION_ERROR;
    }

    std::shared_ptr<Admin> adminPtr = adminMgr_->GetAdminByPkgName(admin.GetBundleName());
    if (adminPtr == nullptr) {
        return ERR_EDM_DEL_ADMIN_FAILED;
    }
    if (adminPtr->adminInfo_.adminType_ != AdminType::NORMAL) {
        EDMLOGW("DeactiveAdmin: only remove normal admin.");
        return ERR_EDM_PERMISSION_ERROR;
    }

    return RemoveAdmin(admin.GetBundleName());
}

bool EnterpriseDeviceMgrAbility::IsHdc()
{
    Security::AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    EDMLOGD("callerToken : %{public}u", callerToken);
    Security::AccessToken::NativeTokenInfo nativeTokenInfo;
    Security::AccessToken::AccessTokenKit::GetNativeTokenInfo(callerToken, nativeTokenInfo);
    EDMLOGD("native process name = %{public}s", nativeTokenInfo.processName.c_str());
    if (nativeTokenInfo.processName == "hdcd") {
        return true;
    }
    return false;
}

ErrCode EnterpriseDeviceMgrAbility::CheckCallingUid(std::string &bundleName)
{
    if (IsHdc()) {
        return ERR_OK;
    }

    // super admin can be removed by itself
    int uid = GetCallingUid();
    auto bundleManager = GetBundleMgr();
    std::string callingBundleName;
    if (!bundleManager->GetNameForUid(uid, callingBundleName)) {
        EDMLOGW("CheckCallingUid failed: get bundleName for uid %{public}d fail.", uid);
        return ERR_EDM_PERMISSION_ERROR;
    }
    if (bundleName == callingBundleName) {
        return ERR_OK;
    }
    EDMLOGW("CheckCallingUid failed: only the app %{public}s can remove itself.", callingBundleName.c_str());
    return ERR_EDM_PERMISSION_ERROR;
}

ErrCode EnterpriseDeviceMgrAbility::DeactiveSuperAdmin(std::string &bundleName)
{
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    std::shared_ptr<Admin> admin = adminMgr_->GetAdminByPkgName(bundleName);
    if (admin == nullptr) {
        return ERR_EDM_DEL_ADMIN_FAILED;
    }
    if (admin->adminInfo_.adminType_ != AdminType::ENT) {
        EDMLOGW("DeactiveSuperAdmin: only remove super admin.");
        return ERR_EDM_PERMISSION_ERROR;
    }
    int32_t checkRet = CheckCallingUid(admin->adminInfo_.packageName_);
    if (checkRet != ERR_OK) {
        EDMLOGW("DeactiveSuperAdmin: CheckCallingUid failed: %{public}d", checkRet);
        return ERR_EDM_PERMISSION_ERROR;
    }

    return RemoveAdmin(bundleName);
}

bool EnterpriseDeviceMgrAbility::IsSuperAdmin(std::string &bundleName)
{
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    std::shared_ptr<Admin> admin = adminMgr_->GetAdminByPkgName(bundleName);
    if (admin == nullptr) {
        EDMLOGW("IsSuperAdmin: admin == nullptr.");
        return false;
    }
    if (admin->adminInfo_.adminType_ == AdminType::ENT) {
        EDMLOGW("IsSuperAdmin: admin->adminInfo_.adminType_ == AdminType::ENT.");
        return true;
    }
    return false;
}

bool EnterpriseDeviceMgrAbility::IsAdminActive(AppExecFwk::ElementName &admin, int32_t userId)
{
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    std::shared_ptr<Admin> existAdmin = adminMgr_->GetAdminByPkgName(admin.GetBundleName());
    if (existAdmin != nullptr) {
        EDMLOGD("IsAdminActive: get admin successed");
        return true;
    }
    return false;
}

ErrCode EnterpriseDeviceMgrAbility::HandleDevicePolicy(uint32_t code, AppExecFwk::ElementName &admin,
    MessageParcel &data)
{
    std::shared_ptr<Admin> deviceAdmin = adminMgr_->GetAdminByPkgName(admin.GetBundleName());
    if (deviceAdmin == nullptr) {
        EDMLOGW("HandleDevicePolicy: get admin failed");
        return ERR_EDM_GET_ADMIN_MGR_FAILED;
    }
    std::shared_ptr<IPlugin> plugin = pluginMgr_->GetPluginByFuncCode(code);
    if (plugin == nullptr) {
        EDMLOGW("HandleDevicePolicy: get plugin failed, code:%{public}d", code);
        return ERR_EDM_GET_PLUGIN_MGR_FAILED;
    }
    EDMLOGD("HandleDevicePolicy: plugin info:%{public}d , %{public}s , %{public}s", plugin->GetCode(),
        plugin->GetPolicyName().c_str(), plugin->GetPermission().c_str());
    if (!deviceAdmin->CheckPermission(plugin->GetPermission())) {
        EDMLOGW("HandleDevicePolicy: check permission failed");
        return ERR_EDM_PERMISSION_ERROR;
    }
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    std::string policyName = plugin->GetPolicyName();
    std::string policyValue = "";
    policyMgr_->GetPolicy(admin.GetBundleName(), policyName, policyValue);
    bool isChanged = false;
    if (plugin->OnHandlePolicy(code, data, policyValue, isChanged) != ERR_OK) {
        EDMLOGW("HandleDevicePolicy: OnHandlePolicy failed");
        return ERR_EDM_HANDLE_POLICY_FAILED;
    }

    EDMLOGD("HandleDevicePolicy: isChanged:%{public}d, needSave:%{public}d, policyValue:%{public}s\n", isChanged,
        plugin->NeedSavePolicy(), policyValue.c_str());
    std::string oldCombinePolicy = "";
    policyMgr_->GetPolicy("", policyName, oldCombinePolicy);
    std::string mergedPolicy = policyValue;
    bool isGlobalChanged = false;
    if (plugin->NeedSavePolicy() && isChanged) {
        ErrCode res = plugin->MergePolicyData(admin.GetBundleName(), mergedPolicy);
        if (res != ERR_OK) {
            EDMLOGW("HandleDevicePolicy: MergePolicyData failed error:%{public}d", res);
            return ERR_EDM_HANDLE_POLICY_FAILED;
        }
        policyMgr_->SetPolicy(admin.GetBundleName(), policyName, policyValue, mergedPolicy);
        isGlobalChanged = (oldCombinePolicy != mergedPolicy);
    }
    plugin->OnHandlePolicyDone(code, admin.GetBundleName(), isGlobalChanged);
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::GetDevicePolicy(uint32_t code, AppExecFwk::ElementName *admin,
    MessageParcel &reply)
{
    std::shared_ptr<IPlugin> plugin = pluginMgr_->GetPluginByFuncCode(code);
    if (plugin == nullptr) {
        EDMLOGW("GetDevicePolicy: get plugin failed");
        reply.WriteInt32(ERR_EDM_GET_PLUGIN_MGR_FAILED);
        return ERR_EDM_GET_PLUGIN_MGR_FAILED;
    }
    std::string policyName = plugin->GetPolicyName();
    std::string policyValue;
    std::string adminName = (admin == nullptr) ? "" : admin->GetBundleName();
    if (policyMgr_->GetPolicy(adminName, policyName, policyValue) != ERR_OK) {
        EDMLOGW("GetDevicePolicy: get policy failed");
        reply.WriteInt32(ERR_EDM_POLICY_NOT_FIND);
    } else {
        reply.WriteInt32(ERR_OK);
        plugin->WritePolicyToParcel(policyValue, reply);
    }

    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::GetActiveAdmin(AdminType type, std::vector<std::string> &activeAdminList)
{
    std::vector<std::string> superList;
    std::vector<std::string> normalList;
    switch (type) {
        case AdminType::NORMAL:
            adminMgr_->GetActiveAdmin(AdminType::NORMAL, normalList);
            adminMgr_->GetActiveAdmin(AdminType::ENT, superList);
            break;
        case AdminType::ENT:
            adminMgr_->GetActiveAdmin(AdminType::ENT, superList);
            break;
        case AdminType::UNKNOWN:
            break;
        default:
            return ERR_EDM_PARAM_ERROR;
    }
    if (!superList.empty()) {
        activeAdminList.insert(activeAdminList.begin(), superList.begin(), superList.end());
    }
    if (!normalList.empty()) {
        activeAdminList.insert(activeAdminList.begin(), normalList.begin(), normalList.end());
    }
    for (const auto &activeAdmin : activeAdminList) {
        EDMLOGD("GetActiveAdmin: %{public}s", activeAdmin.c_str());
    }
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::GetEnterpriseInfo(AppExecFwk::ElementName &admin, MessageParcel &reply)
{
    EntInfo entInfo;
    ErrCode code = adminMgr_->GetEntInfo(admin.GetBundleName(), entInfo);
    if (code != ERR_OK) {
        reply.WriteInt32(ERR_EDM_GET_ENTINFO_FAILED);
        return ERR_EDM_GET_ENTINFO_FAILED;
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteParcelable(&entInfo);
    EDMLOGD("EnterpriseDeviceMgrAbility::GetEnterpriseInfo: entInfo->enterpriseName %{public}s, "
        "entInfo->description:%{public}s",
        entInfo.enterpriseName.c_str(), entInfo.description.c_str());
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::SetEnterpriseInfo(AppExecFwk::ElementName &admin, EntInfo &entInfo)
{
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    std::shared_ptr<Admin> adminItem = adminMgr_->GetAdminByPkgName(admin.GetBundleName());
    if (adminItem == nullptr) {
        return ERR_EDM_SET_ENTINFO_FAILED;
    }
    int32_t ret = CheckCallingUid(adminItem->adminInfo_.packageName_);
    if (ret != ERR_OK) {
        EDMLOGW("SetEnterpriseInfo: CheckCallingUid failed: %{public}d", ret);
        return ERR_EDM_PERMISSION_ERROR;
    }
    ErrCode code = adminMgr_->SetEntInfo(admin.GetBundleName(), entInfo);
    return (code != ERR_OK) ? ERR_EDM_SET_ENTINFO_FAILED : ERR_OK;
}
} // namespace EDM
} // namespace OHOS