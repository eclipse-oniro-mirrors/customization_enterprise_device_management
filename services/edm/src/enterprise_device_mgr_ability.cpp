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

#include "enterprise_device_mgr_ability.h"

#include <bundle_info.h>
#include <bundle_mgr_interface.h>
#include <ipc_skeleton.h>
#include <iservice_registry.h>
#include <message_parcel.h>
#include <string_ex.h>
#include <system_ability.h>
#include <system_ability_definition.h>

#include "accesstoken_kit.h"
#include "application_state_observer.h"
#include "bundle_mgr_proxy.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "device_policies_storage_rdb.h"
#include "directory_ex.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_log.h"
#include "edm_sys_manager.h"
#include "enterprise_admin_connection.h"
#include "enterprise_bundle_connection.h"
#include "enterprise_conn_manager.h"
#include "matching_skills.h"
#include "os_account_manager.h"
#include "parameters.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT =
    SystemAbility::MakeAndRegisterAbility(EnterpriseDeviceMgrAbility::GetInstance().GetRefPtr());

const std::string PERMISSION_MANAGE_ENTERPRISE_DEVICE_ADMIN = "ohos.permission.MANAGE_ENTERPRISE_DEVICE_ADMIN";
const std::string PERMISSION_SET_ENTERPRISE_INFO = "ohos.permission.SET_ENTERPRISE_INFO";
const std::string PERMISSION_ENTERPRISE_SUBSCRIBE_MANAGED_EVENT = "ohos.permission.ENTERPRISE_SUBSCRIBE_MANAGED_EVENT";
const std::string PARAM_EDM_ENABLE = "persist.edm.edm_enable";
const std::string PARAM_SECURITY_MODE = "ohos.boot.advsecmode.state";
const std::string SYSTEM_UPDATE_FOR_POLICY = "usual.event.DUE_SA_FIRMWARE_UPDATE_FOR_POLICY";
const std::string FIRMWARE_EVENT_INFO_NAME = "version";
const std::string FIRMWARE_EVENT_INFO_TYPE = "packageType";
const std::string FIRMWARE_EVENT_INFO_CHECK_TIME = "firstReceivedTime";

std::mutex EnterpriseDeviceMgrAbility::mutexLock_;

sptr<EnterpriseDeviceMgrAbility> EnterpriseDeviceMgrAbility::instance_;

void EnterpriseDeviceMgrAbility::AddCommonEventFuncMap()
{
    commonEventFuncMap_[EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED] =
        &EnterpriseDeviceMgrAbility::OnCommonEventUserRemoved;
    commonEventFuncMap_[EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED] =
        &EnterpriseDeviceMgrAbility::OnCommonEventPackageAdded;
    commonEventFuncMap_[EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED] =
        &EnterpriseDeviceMgrAbility::OnCommonEventPackageRemoved;
    commonEventFuncMap_[SYSTEM_UPDATE_FOR_POLICY] =
        &EnterpriseDeviceMgrAbility::OnCommonEventSystemUpdate;
}

void EnterpriseDeviceMgrAbility::OnCommonEventSystemUpdate(const EventFwk::CommonEventData &data)
{
    EDMLOGI("OnCommonEventSystemUpdate");
    UpdateInfo updateInfo;
    updateInfo.version = data.GetWant().GetStringParam(FIRMWARE_EVENT_INFO_NAME);
    updateInfo.firstReceivedTime = data.GetWant().GetLongParam(FIRMWARE_EVENT_INFO_CHECK_TIME, 0);
    updateInfo.packageType = data.GetWant().GetStringParam(FIRMWARE_EVENT_INFO_TYPE);

    ConnectAbilityOnSystemUpdate(updateInfo);
}

void EnterpriseDeviceMgrAbility::ConnectAbilityOnSystemUpdate(const UpdateInfo &updateInfo)
{
    std::unordered_map<int32_t, std::vector<std::shared_ptr<Admin>>> subAdmins;
    adminMgr_->GetAdminBySubscribeEvent(ManagedEvent::SYSTEM_UPDATE, subAdmins);
    if (subAdmins.empty()) {
        EDMLOGW("Get subscriber by common event failed.");
        return;
    }
    AAFwk::Want want;
    for (const auto &subAdmin : subAdmins) {
        for (const auto &it : subAdmin.second) {
            want.SetElementName(it->adminInfo_.packageName_, it->adminInfo_.className_);
            std::shared_ptr<EnterpriseConnManager> manager = DelayedSingleton<EnterpriseConnManager>::GetInstance();
            sptr<IEnterpriseConnection> connection =
                manager->CreateUpdateConnection(want, subAdmin.first, updateInfo);
            manager->ConnectAbility(connection);
        }
    }
}

void EnterpriseDeviceMgrAbility::AddOnAddSystemAbilityFuncMap()
{
    addSystemAbilityFuncMap_[APP_MGR_SERVICE_ID] = &EnterpriseDeviceMgrAbility::OnAppManagerServiceStart;
    addSystemAbilityFuncMap_[COMMON_EVENT_SERVICE_ID] = &EnterpriseDeviceMgrAbility::OnCommonEventServiceStart;
}

EnterpriseDeviceEventSubscriber::EnterpriseDeviceEventSubscriber(
    const EventFwk::CommonEventSubscribeInfo &subscribeInfo,
    EnterpriseDeviceMgrAbility &listener) : EventFwk::CommonEventSubscriber(subscribeInfo), listener_(listener) {}

void EnterpriseDeviceEventSubscriber::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    const std::string action = data.GetWant().GetAction();
    EDMLOGI("EDM OnReceiveEvent get action: %{public}s", action.c_str());
    auto func = listener_.commonEventFuncMap_.find(action);
    if (func != listener_.commonEventFuncMap_.end()) {
        auto commonEventFunc = func->second;
        if (commonEventFunc != nullptr) {
            return (listener_.*commonEventFunc)(data);
        }
    } else {
        EDMLOGW("OnReceiveEvent action is invalid");
    }
}

std::shared_ptr<EventFwk::CommonEventSubscriber> EnterpriseDeviceMgrAbility::CreateEnterpriseDeviceEventSubscriber(
    EnterpriseDeviceMgrAbility &listener)
{
    EventFwk::MatchingSkills skill = EventFwk::MatchingSkills();
    AddCommonEventFuncMap();
    for (auto &item : commonEventFuncMap_) {
        skill.AddEvent(item.first);
        EDMLOGI("CreateEnterpriseDeviceEventSubscriber AddEvent: %{public}s", item.first.c_str());
    }
    EventFwk::CommonEventSubscribeInfo info(skill);
    return std::make_shared<EnterpriseDeviceEventSubscriber>(info, listener);
}

void EnterpriseDeviceMgrAbility::OnCommonEventUserRemoved(const EventFwk::CommonEventData &data)
{
    int userIdToRemove = data.GetCode();
    if (userIdToRemove == 0) {
        return;
    }
    EDMLOGI("OnCommonEventUserRemoved");
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    // include super admin, need to be removed
    std::vector<std::shared_ptr<Admin>> userAdmin;
    adminMgr_->GetAdminByUserId(userIdToRemove, userAdmin);
    for (auto &item : userAdmin) {
        if (FAILED(RemoveAdmin(item->adminInfo_.packageName_, userIdToRemove))) {
            EDMLOGW("EnterpriseDeviceMgrAbility::OnCommonEventUserRemoved remove admin failed packagename = %{public}s",
                item->adminInfo_.packageName_.c_str());
        }
    }
    std::vector<std::shared_ptr<Admin>> subAndSuperAdmin;
    adminMgr_->GetAdminByUserId(DEFAULT_USER_ID, subAndSuperAdmin);
    for (const auto &subAdmin : subAndSuperAdmin) {
        if ((subAdmin->GetAdminType() == AdminType::SUB_SUPER_ADMIN || subAdmin->GetAdminType() == AdminType::ENT) &&
            FAILED(RemoveAdmin(subAdmin->adminInfo_.packageName_, userIdToRemove))) {
            EDMLOGW("EnterpriseDeviceMgrAbility::OnCommonEventUserRemoved: remove sub and super admin policy failed.");
        }
    }
}

void EnterpriseDeviceMgrAbility::OnCommonEventPackageAdded(const EventFwk::CommonEventData &data)
{
    EDMLOGI("OnCommonEventPackageAdded");
    std::string bundleName = data.GetWant().GetElement().GetBundleName();
    ConnectAbilityOnSystemEvent(bundleName, ManagedEvent::BUNDLE_ADDED);
}

void EnterpriseDeviceMgrAbility::OnCommonEventPackageRemoved(const EventFwk::CommonEventData &data)
{
    EDMLOGI("OnCommonEventPackageRemoved");
    std::string bundleName = data.GetWant().GetElement().GetBundleName();
    int32_t userId = data.GetWant().GetIntParam(AppExecFwk::Constants::USER_ID, AppExecFwk::Constants::INVALID_USERID);
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    std::shared_ptr<Admin> admin = adminMgr_->GetAdminByPkgName(bundleName, userId);
    if (admin != nullptr) {
        if (admin->adminInfo_.adminType_ == AdminType::NORMAL) {
            RemoveAdmin(bundleName, userId);
        }
        if (admin->adminInfo_.adminType_ == AdminType::SUB_SUPER_ADMIN && userId == DEFAULT_USER_ID) {
            RemovePolicyAndAdmin(bundleName);
        }
        if (admin->adminInfo_.adminType_ == AdminType::ENT && userId == DEFAULT_USER_ID) {
            // remove sub-super admin
            std::vector<std::string> subAdmins;
            adminMgr_->GetSubSuperAdminsByParentName(bundleName, subAdmins);
            for (auto const &subAdminName : subAdmins) {
                RemovePolicyAndAdmin(subAdminName);
            }
            // remove super admin
            RemovePolicyAndAdmin(bundleName);
        }
        if (!adminMgr_->IsAdminExist()) {
            system::SetParameter(PARAM_EDM_ENABLE, "false");
        }
    }
    ConnectAbilityOnSystemEvent(bundleName, ManagedEvent::BUNDLE_REMOVED);
}

void EnterpriseDeviceMgrAbility::ConnectAbilityOnSystemEvent(const std::string &bundleName, ManagedEvent event)
{
    std::unordered_map<int32_t, std::vector<std::shared_ptr<Admin>>> subAdmins;
    adminMgr_->GetAdminBySubscribeEvent(event, subAdmins);
    if (subAdmins.empty()) {
        EDMLOGW("Get subscriber by common event failed.");
        return;
    }
    AAFwk::Want want;
    for (const auto &subAdmin : subAdmins) {
        for (const auto &it : subAdmin.second) {
            want.SetElementName(it->adminInfo_.packageName_, it->adminInfo_.className_);
            std::shared_ptr<EnterpriseConnManager> manager = DelayedSingleton<EnterpriseConnManager>::GetInstance();
            sptr<IEnterpriseConnection> connection =
                manager->CreateBundleConnection(want, static_cast<uint32_t>(event), subAdmin.first, bundleName);
            manager->ConnectAbility(connection);
        }
    }
}

sptr<EnterpriseDeviceMgrAbility> EnterpriseDeviceMgrAbility::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> autoLock(mutexLock_);
        if (instance_ == nullptr) {
            EDMLOGD("EnterpriseDeviceMgrAbility:GetInstance instance = new EnterpriseDeviceMgrAbility()");
            instance_ = new (std::nothrow) EnterpriseDeviceMgrAbility();
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

int32_t EnterpriseDeviceMgrAbility::Dump(int32_t fd, const std::vector<std::u16string> &args)
{
    EDMLOGI("EnterpriseDeviceMgrAbility::Dump");
    if (fd < 0) {
        EDMLOGE("Dump fd invalid");
        return ERR_EDM_DUMP_FAILED;
    }
    std::string result;
    result.append("Ohos enterprise device manager service: \n");
    std::vector<std::string> enabledAdminList;
    GetEnabledAdmin(AdminType::NORMAL, enabledAdminList);
    if (enabledAdminList.empty()) {
        result.append("There is no admin enabled\n");
    } else {
        result.append("Enabled admin exist :\n");
        for (const auto &enabledAdmin : enabledAdminList) {
            result.append(enabledAdmin);
            result.append("\n");
        }
    }
    int32_t ret = dprintf(fd, "%s", result.c_str());
    if (ret < 0) {
        EDMLOGE("dprintf to dump fd failed");
        return ERR_EDM_DUMP_FAILED;
    }
    return ERR_OK;
}

void EnterpriseDeviceMgrAbility::OnStart()
{
    std::lock_guard<std::mutex> autoLock(mutexLock_);
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
    InitAllPolices();

    if (!pluginMgr_) {
        pluginMgr_ = PluginManager::GetInstance();
    }
    EDMLOGD("create pluginMgr_ success");
    pluginMgr_->Init();

    AddOnAddSystemAbilityFuncMap();
    AddSystemAbilityListener(COMMON_EVENT_SERVICE_ID);
    AddSystemAbilityListener(APP_MGR_SERVICE_ID);
}

void EnterpriseDeviceMgrAbility::InitAllPolices()
{
    std::vector<int32_t> userIds;
    auto devicePolicies = DevicePoliciesStorageRdb::GetInstance();
    if (devicePolicies == nullptr) {
        EDMLOGE("OnAddSystemAbility::InitAllPolices:get rdbStore failed.");
        return;
    }
    devicePolicies->QueryAllUserId(userIds);
    for (auto userId : userIds) {
        if (userId < DEFAULT_USER_ID) {
            continue;
        }
        GetAndSwitchPolicyManagerByUserId(userId);
    }
    policyMgr_ = GetAndSwitchPolicyManagerByUserId(DEFAULT_USER_ID);
}

void EnterpriseDeviceMgrAbility::OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    EDMLOGD("OnAddSystemAbility systemAbilityId:%{public}d added!", systemAbilityId);
    auto func = addSystemAbilityFuncMap_.find(systemAbilityId);
    if (func != addSystemAbilityFuncMap_.end()) {
        auto memberFunc = func->second;
        if (memberFunc != nullptr) {
            return (this->*memberFunc)(systemAbilityId, deviceId);
        }
    }
}

void EnterpriseDeviceMgrAbility::OnAppManagerServiceStart(int32_t systemAbilityId, const std::string &deviceId)
{
    EDMLOGI("OnAppManagerServiceStart");
    std::unordered_map<int32_t, std::vector<std::shared_ptr<Admin>>> subAdmins;
    adminMgr_->GetAdminBySubscribeEvent(ManagedEvent::APP_START, subAdmins);
    adminMgr_->GetAdminBySubscribeEvent(ManagedEvent::APP_STOP, subAdmins);
    if (!subAdmins.empty()) {
        EDMLOGI("the admin that listened the APP_START or APP_STOP event is existed");
        SubscribeAppState();
    }
}

void EnterpriseDeviceMgrAbility::OnCommonEventServiceStart(int32_t systemAbilityId, const std::string &deviceId)
{
    commonEventSubscriber = CreateEnterpriseDeviceEventSubscriber(*this);
    EventFwk::CommonEventManager::SubscribeCommonEvent(this->commonEventSubscriber);
    EDMLOGI("create commonEventSubscriber success");
}

void EnterpriseDeviceMgrAbility::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId) {}

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

sptr<AppExecFwk::IAppMgr> EnterpriseDeviceMgrAbility::GetAppMgr()
{
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(OHOS::APP_MGR_SERVICE_ID);
    return iface_cast<AppExecFwk::IAppMgr>(remoteObject);
}

sptr<AppExecFwk::IBundleMgr> EnterpriseDeviceMgrAbility::GetBundleMgr()
{
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    return proxy;
}

bool EnterpriseDeviceMgrAbility::SubscribeAppState()
{
    if (appStateObserver_) {
        EDMLOGD("appStateObserver has subscribed");
        return true;
    }
    sptr<AppExecFwk::IAppMgr> appMgr = GetAppMgr();
    if (!appMgr) {
        EDMLOGE("GetAppMgr failed");
        return false;
    }
    appStateObserver_ = new (std::nothrow) ApplicationStateObserver(*this);
    if (!appStateObserver_) {
        EDMLOGE("new ApplicationStateObserver failed");
        return false;
    }
    if (appMgr->RegisterApplicationStateObserver(appStateObserver_) != ERR_OK) {
        EDMLOGE("RegisterApplicationStateObserver fail!");
        appStateObserver_.clear();
        appStateObserver_ = nullptr;
        return false;
    }
    return true;
}

bool EnterpriseDeviceMgrAbility::UnsubscribeAppState()
{
    if (!appStateObserver_) {
        EDMLOGD("appStateObserver has subscribed");
        return true;
    }
    std::unordered_map<int32_t, std::vector<std::shared_ptr<Admin>>> subAdmins;
    adminMgr_->GetAdminBySubscribeEvent(ManagedEvent::APP_START, subAdmins);
    adminMgr_->GetAdminBySubscribeEvent(ManagedEvent::APP_STOP, subAdmins);
    if (!subAdmins.empty()) {
        return true;
    }
    sptr<AppExecFwk::IAppMgr> appMgr = GetAppMgr();
    if (!appMgr || appMgr->UnregisterApplicationStateObserver(appStateObserver_) != ERR_OK) {
        EDMLOGE("UnregisterApplicationStateObserver fail!");
        return false;
    }
    appStateObserver_.clear();
    appStateObserver_ = nullptr;
    return true;
}

bool EnterpriseDeviceMgrAbility::VerifyCallingPermission(const std::string &permissionName)
{
    EDMLOGD("VerifyCallingPermission permission %{public}s", permissionName.c_str());
    Security::AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t ret = Security::AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, permissionName);
    if (ret == Security::AccessToken::PermissionState::PERMISSION_GRANTED) {
        EDMLOGI("permission %{public}s: PERMISSION_GRANTED", permissionName.c_str());
        return true;
    }
    EDMLOGW("verify AccessToken failed");
    return false;
}

ErrCode EnterpriseDeviceMgrAbility::VerifyEnableAdminCondition(AppExecFwk::ElementName &admin, AdminType type,
    int32_t userId)
{
    if (type == AdminType::UNKNOWN) {
        EDMLOGW("EnableAdmin: admin type is invalid.");
        return ERR_EDM_ADD_ADMIN_FAILED;
    }
    if (type == AdminType::ENT && userId != DEFAULT_USER_ID) {
        EDMLOGW("EnableAdmin: Super admin can only be enabled in default user.");
        return ERR_EDM_ADD_ADMIN_FAILED;
    }

    if (type != AdminType::ENT && system::GetBoolParameter(PARAM_SECURITY_MODE, false)) {
        EDMLOGW("EnableAdmin: The current mode is not supported.");
        return ERR_EDM_ADD_ADMIN_FAILED;
    }

    std::shared_ptr<Admin> existAdmin = adminMgr_->GetAdminByPkgName(admin.GetBundleName(), userId);
    if (existAdmin != nullptr) {
        if (existAdmin->GetAdminType() == AdminType::SUB_SUPER_ADMIN) {
            EDMLOGW("EnableAdmin: sub-super admin can not be enabled as a normal or super admin.");
            return ERR_EDM_ADD_ADMIN_FAILED;
        }
        if (existAdmin->GetAdminType() == AdminType::ENT && (type != AdminType::ENT || userId != DEFAULT_USER_ID)) {
            EDMLOGW("EnableAdmin: an exist super admin can't be enabled twice with different role or user id.");
            return ERR_EDM_ADD_ADMIN_FAILED;
        }
        /* An application can't be enabled twice with different ability name */
        if (existAdmin->adminInfo_.className_ != admin.GetAbilityName()) {
            EDMLOGW("EnableAdmin: There is another admin ability enabled with the same package name.");
            return ERR_EDM_ADD_ADMIN_FAILED;
        }
    }
    if (type == AdminType::ENT && adminMgr_->IsSuperAdminExist()) {
        if (existAdmin == nullptr || existAdmin->adminInfo_.adminType_ != AdminType::ENT) {
            EDMLOGW("EnableAdmin: There is another super admin enabled.");
            return ERR_EDM_ADD_ADMIN_FAILED;
        }
    }
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::EnableAdmin(AppExecFwk::ElementName &admin, EntInfo &entInfo, AdminType type,
    int32_t userId)
{
    EDMLOGD("EnterpriseDeviceMgrAbility::EnableAdmin user id = %{public}d", userId);
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    if (!VerifyCallingPermission(PERMISSION_MANAGE_ENTERPRISE_DEVICE_ADMIN)) {
        EDMLOGW("EnterpriseDeviceMgrAbility::EnableAdmin check permission failed");
        return EdmReturnErrCode::PERMISSION_DENIED;
    }
    std::vector<AppExecFwk::ExtensionAbilityInfo> abilityInfo;
    auto bundleManager = GetBundleMgr();
    if (!bundleManager) {
        EDMLOGW("can not get iBundleMgr");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    AAFwk::Want want;
    want.SetElement(admin);
    if (!bundleManager->QueryExtensionAbilityInfos(want, AppExecFwk::ExtensionAbilityType::ENTERPRISE_ADMIN,
        AppExecFwk::ExtensionAbilityInfoFlag::GET_EXTENSION_INFO_WITH_PERMISSION, userId, abilityInfo) ||
        abilityInfo.empty()) {
        EDMLOGW("EnableAdmin: QueryExtensionAbilityInfos failed");
        return EdmReturnErrCode::COMPONENT_INVALID;
    }
    if (FAILED(VerifyEnableAdminCondition(admin, type, userId))) {
        EDMLOGW("EnableAdmin: VerifyEnableAdminCondition failed.");
        return EdmReturnErrCode::ENABLE_ADMIN_FAILED;
    }

    /* Get all request and registered permissions */
    std::vector<std::string> permissionList;
    if (FAILED(GetAllPermissionsByAdmin(admin.GetBundleName(), permissionList, userId))) {
        EDMLOGW("EnableAdmin: GetAllPermissionsByAdmin failed");
        return EdmReturnErrCode::COMPONENT_INVALID;
    }
    /* Filter permissions with AdminType, such as NORMAL can't request super permission */
    if (FAILED(adminMgr_->GetGrantedPermission(permissionList, type))) {
        EDMLOGW("EnableAdmin: GetGrantedPermission failed");
        // permission verify, should throw exception if failed
        return EdmReturnErrCode::ENABLE_ADMIN_FAILED;
    }
    if (FAILED(adminMgr_->SetAdminValue(abilityInfo.at(0), entInfo, type, permissionList, userId))) {
        EDMLOGE("EnableAdmin: SetAdminValue failed.");
        return EdmReturnErrCode::ENABLE_ADMIN_FAILED;
    }
    system::SetParameter(PARAM_EDM_ENABLE, "true");
    EDMLOGI("EnableAdmin: SetAdminValue success %{public}s, type:%{public}d", admin.GetBundleName().c_str(),
        static_cast<uint32_t>(type));
    AAFwk::Want connectWant;
    connectWant.SetElementName(admin.GetBundleName(), admin.GetAbilityName());
    std::shared_ptr<EnterpriseConnManager> manager = DelayedSingleton<EnterpriseConnManager>::GetInstance();
    sptr<IEnterpriseConnection> connection =
        manager->CreateAdminConnection(connectWant, IEnterpriseAdmin::COMMAND_ON_ADMIN_ENABLED, userId);
    manager->ConnectAbility(connection);
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::RemoveAdminItem(const std::string &adminName, const std::string &policyName,
    const std::string &policyValue, int32_t userId)
{
    ErrCode ret;
    std::shared_ptr<IPlugin> plugin = pluginMgr_->GetPluginByPolicyName(policyName);
    if (plugin == nullptr) {
        EDMLOGW("RemoveAdminItem: Get plugin by policy failed: %{public}s\n", policyName.c_str());
        return ERR_EDM_GET_PLUGIN_MGR_FAILED;
    }
    if ((ret = plugin->OnAdminRemove(adminName, policyValue, userId)) != ERR_OK) {
        EDMLOGW("RemoveAdminItem: OnAdminRemove failed, admin:%{public}s, value:%{public}s, res:%{public}d\n",
            adminName.c_str(), policyValue.c_str(), ret);
    }
    if (plugin->NeedSavePolicy()) {
        std::string mergedPolicyData;
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
    plugin->OnAdminRemoveDone(adminName, policyValue, userId);
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::RemoveAdmin(const std::string &adminName, int32_t userId)
{
    EDMLOGD("RemoveAdmin %{public}s, user id = %{public}d", adminName.c_str(), userId);
    std::unordered_map<std::string, std::string> policyItems;
    policyMgr_ = GetAndSwitchPolicyManagerByUserId(userId);
    policyMgr_->GetAllPolicyByAdmin(adminName, policyItems);
    for (const auto &policyItem : policyItems) {
        std::string policyItemName = policyItem.first;
        std::string policyItemValue = policyItem.second;
        EDMLOGD("RemoveAdmin: RemoveAdminItem policyName:%{public}s,policyValue:%{public}s", policyItemName.c_str(),
            policyItemValue.c_str());
        if (RemoveAdminItem(adminName, policyItemName, policyItemValue, userId) != ERR_OK) {
            return ERR_EDM_DEL_ADMIN_FAILED;
        }
    }

    if (adminMgr_->IsSuperOrSubSuperAdmin(adminName) && userId != DEFAULT_USER_ID) {
        EDMLOGI("Remove super admin %{public}s and user id = %{public}d", adminName.c_str(), userId);
        return ERR_OK;
    }

    bool shouldUnsubscribeAppState = ShouldUnsubscribeAppState(adminName, userId);
    if (adminMgr_->DeleteAdmin(adminName, userId) != ERR_OK) {
        return ERR_EDM_DEL_ADMIN_FAILED;
    }
    if (shouldUnsubscribeAppState) {
        UnsubscribeAppState();
    }
    policyMgr_ = GetAndSwitchPolicyManagerByUserId(DEFAULT_USER_ID);
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::RemovePolicyAndAdmin(const std::string &bundleName)
{
    for (auto it = policyMgrMap_.rbegin(); it != policyMgrMap_.rend(); ++it) {
        EDMLOGD("RemovePolicyAndAdmin: policyMgrMap_ it->first %{public}d", it->first);
        if (FAILED(RemoveAdmin(bundleName, it->first))) {
            return ERR_EDM_DEL_ADMIN_FAILED;
        }
    }
    return ERR_OK;
}

bool EnterpriseDeviceMgrAbility::ShouldUnsubscribeAppState(const std::string &adminName, int32_t userId)
{
    std::shared_ptr<Admin> adminPtr = adminMgr_->GetAdminByPkgName(adminName, userId);
    return std::any_of(adminPtr->adminInfo_.managedEvents_.begin(), adminPtr->adminInfo_.managedEvents_.end(),
        [](ManagedEvent event) { return event == ManagedEvent::APP_START || event == ManagedEvent::APP_STOP; });
}

ErrCode EnterpriseDeviceMgrAbility::DisableAdmin(AppExecFwk::ElementName &admin, int32_t userId)
{
    EDMLOGW("EnterpriseDeviceMgrAbility::DisableAdmin user id = %{public}d", userId);
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    if (!VerifyCallingPermission(PERMISSION_MANAGE_ENTERPRISE_DEVICE_ADMIN)) {
        EDMLOGW("EnterpriseDeviceMgrAbility::DisableAdmin check permission failed");
        return EdmReturnErrCode::PERMISSION_DENIED;
    }

    std::shared_ptr<Admin> adminPtr = adminMgr_->GetAdminByPkgName(admin.GetBundleName(), userId);
    if (adminPtr == nullptr) {
        return EdmReturnErrCode::DISABLE_ADMIN_FAILED;
    }
    if (adminPtr->adminInfo_.adminType_ != AdminType::NORMAL) {
        EDMLOGW("DisableAdmin: only remove normal admin.");
        return EdmReturnErrCode::DISABLE_ADMIN_FAILED;
    }

    if (FAILED(RemoveAdmin(admin.GetBundleName(), userId))) {
        EDMLOGW("DisableAdmin: disable admin failed.");
        return EdmReturnErrCode::DISABLE_ADMIN_FAILED;
    }
    if (!adminMgr_->IsAdminExist()) {
        system::SetParameter(PARAM_EDM_ENABLE, "false");
    }
    AAFwk::Want want;
    want.SetElementName(admin.GetBundleName(), admin.GetAbilityName());
    std::shared_ptr<EnterpriseConnManager> manager = DelayedSingleton<EnterpriseConnManager>::GetInstance();
    sptr<IEnterpriseConnection> connection =
        manager->CreateAdminConnection(want, IEnterpriseAdmin::COMMAND_ON_ADMIN_DISABLED, userId);
    manager->ConnectAbility(connection);
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::CheckCallingUid(const std::string &bundleName)
{
    // super admin can be removed by itself
    int uid = GetCallingUid();
    auto bundleManager = GetBundleMgr();
    std::string callingBundleName;
    if (bundleManager->GetNameForUid(uid, callingBundleName) != ERR_OK) {
        EDMLOGW("CheckCallingUid failed: get bundleName for uid %{public}d fail.", uid);
        return ERR_EDM_PERMISSION_ERROR;
    }
    if (bundleName == callingBundleName) {
        return ERR_OK;
    }
    EDMLOGW("CheckCallingUid failed: only the app %{public}s can remove itself.", callingBundleName.c_str());
    return ERR_EDM_PERMISSION_ERROR;
}

ErrCode EnterpriseDeviceMgrAbility::DisableSuperAdmin(const std::string &bundleName)
{
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    if (!VerifyCallingPermission(PERMISSION_MANAGE_ENTERPRISE_DEVICE_ADMIN)) {
        EDMLOGW("EnterpriseDeviceMgrAbility::DisableSuperAdmin check permission failed.");
        return EdmReturnErrCode::PERMISSION_DENIED;
    }
    std::shared_ptr<Admin> admin = adminMgr_->GetAdminByPkgName(bundleName, DEFAULT_USER_ID);
    if (admin == nullptr) {
        return EdmReturnErrCode::DISABLE_ADMIN_FAILED;
    }
    if (admin->adminInfo_.adminType_ != AdminType::ENT) {
        EDMLOGW("DisableSuperAdmin: only remove super admin.");
        return EdmReturnErrCode::DISABLE_ADMIN_FAILED;
    }
    // disable sub-super admin
    std::vector<std::string> subAdmins;
    adminMgr_->GetSubSuperAdminsByParentName(bundleName, subAdmins);
    for (auto const &subAdminName : subAdmins) {
        if (FAILED(RemovePolicyAndAdmin(subAdminName))) {
            EDMLOGW("DisableSuperAdmin: remove sub-super admin failed.");
            return EdmReturnErrCode::DISABLE_ADMIN_FAILED;
        }
    }
    // disable super admin
    if (FAILED(RemovePolicyAndAdmin(bundleName))) {
        EDMLOGW("DisableSuperAdmin: remove super admin failed.");
        return EdmReturnErrCode::DISABLE_ADMIN_FAILED;
    }
    if (!adminMgr_->IsAdminExist()) {
        system::SetParameter(PARAM_EDM_ENABLE, "false");
    }
    AAFwk::Want want;
    want.SetElementName(admin->adminInfo_.packageName_, admin->adminInfo_.className_);
    std::shared_ptr<EnterpriseConnManager> manager = DelayedSingleton<EnterpriseConnManager>::GetInstance();
    sptr<IEnterpriseConnection> connection =
        manager->CreateAdminConnection(want, IEnterpriseAdmin::COMMAND_ON_ADMIN_DISABLED, DEFAULT_USER_ID);
    manager->ConnectAbility(connection);
    return ERR_OK;
}

bool EnterpriseDeviceMgrAbility::IsSuperAdmin(const std::string &bundleName)
{
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    std::shared_ptr<Admin> admin = adminMgr_->GetAdminByPkgName(bundleName, DEFAULT_USER_ID);
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

bool EnterpriseDeviceMgrAbility::IsAdminEnabled(AppExecFwk::ElementName &admin, int32_t userId)
{
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    std::shared_ptr<Admin> existAdmin = adminMgr_->GetAdminByPkgName(admin.GetBundleName(), userId);
    if (existAdmin != nullptr) {
        EDMLOGD("IsAdminEnabled: get admin successed");
        return true;
    }
    return false;
}

int32_t EnterpriseDeviceMgrAbility::GetCurrentUserId()
{
    std::vector<int32_t> ids;
    ErrCode ret = AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids);
    if (FAILED(ret) || ids.empty()) {
        EDMLOGE("EnterpriseDeviceMgrAbility GetCurrentUserId failed");
        return -1;
    }
    EDMLOGD("EnterpriseDeviceMgrAbility GetCurrentUserId user id = %{public}d", ids.at(0));
    return (ids.at(0));
}

std::shared_ptr<PolicyManager> EnterpriseDeviceMgrAbility::GetAndSwitchPolicyManagerByUserId(int32_t userId)
{
    auto iter = policyMgrMap_.find(userId);
    std::shared_ptr<PolicyManager> policyMgr;
    if (iter == policyMgrMap_.end()) {
        policyMgr.reset(new (std::nothrow) PolicyManager(userId));
        policyMgrMap_.insert(std::make_pair(userId, policyMgr));
        EDMLOGI("get policyMgr failed create success userId : %{public}d", userId);
        policyMgr->Init();
    } else {
        policyMgr = iter->second;
    }
    IPolicyManager::policyManagerInstance_ = policyMgr.get();
    return policyMgr;
}

ErrCode EnterpriseDeviceMgrAbility::UpdateDevicePolicy(uint32_t code, AppExecFwk::ElementName &admin,
    MessageParcel &data, MessageParcel &reply, int32_t userId)
{
    std::shared_ptr<IPlugin> plugin = pluginMgr_->GetPluginByFuncCode(code);
    if (plugin == nullptr) {
        EDMLOGW("UpdateDevicePolicy: get plugin failed, code:%{public}d", code);
        return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
    }

    // Set policy to other users except 100
    policyMgr_ = GetAndSwitchPolicyManagerByUserId(userId);
    std::string policyName = plugin->GetPolicyName();
    std::string policyValue;
    policyMgr_->GetPolicy(admin.GetBundleName(), policyName, policyValue);
    bool isChanged = false;
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, policyValue, isChanged, userId);
    if (FAILED(ret)) {
        EDMLOGW("UpdateDevicePolicy: OnHandlePolicy failed");
        return ret;
    }
    EDMLOGD("UpdateDevicePolicy: isChanged:%{public}d, needSave:%{public}d\n", isChanged, plugin->NeedSavePolicy());
    std::string oldCombinePolicy;
    policyMgr_->GetPolicy("", policyName, oldCombinePolicy);
    std::string mergedPolicy = policyValue;
    bool isGlobalChanged = false;
    if (plugin->NeedSavePolicy() && isChanged) {
        ret = plugin->MergePolicyData(admin.GetBundleName(), mergedPolicy);
        if (FAILED(ret)) {
            EDMLOGW("UpdateDevicePolicy: MergePolicyData failed error:%{public}d", ret);
            return ret;
        }
        policyMgr_->SetPolicy(admin.GetBundleName(), policyName, policyValue, mergedPolicy);
        isGlobalChanged = (oldCombinePolicy != mergedPolicy);
    }
    plugin->OnHandlePolicyDone(code, admin.GetBundleName(), isGlobalChanged, userId);
    // Reset to 100 policyMgr
    policyMgr_ = GetAndSwitchPolicyManagerByUserId(DEFAULT_USER_ID);
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::HandleDevicePolicy(uint32_t code, AppExecFwk::ElementName &admin,
    MessageParcel &data, MessageParcel &reply, int32_t userId)
{
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    bool isUserExist = false;
    AccountSA::OsAccountManager::IsOsAccountExists(userId, isUserExist);
    if (!isUserExist) {
        return EdmReturnErrCode::PARAM_ERROR;
    }
    EDMLOGI("HandleDevicePolicy: HandleDevicePolicy userId = %{public}d", userId);
    std::shared_ptr<Admin> deviceAdmin = adminMgr_->GetAdminByPkgName(admin.GetBundleName(), GetCurrentUserId());
    if (deviceAdmin == nullptr) {
        EDMLOGW("HandleDevicePolicy: get admin failed");
        return EdmReturnErrCode::ADMIN_INACTIVE;
    }
    if (FAILED(CheckCallingUid(deviceAdmin->adminInfo_.packageName_))) {
        EDMLOGW("HandleDevicePolicy: CheckCallingUid failed.");
        return EdmReturnErrCode::PERMISSION_DENIED;
    }
    std::shared_ptr<IPlugin> plugin = pluginMgr_->GetPluginByFuncCode(code);
    if (plugin == nullptr) {
        EDMLOGW("HandleDevicePolicy: get plugin failed, code:%{public}d", code);
        return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
    }
    EDMLOGD("HandleDevicePolicy: plugin info:%{public}d , %{public}s , %{public}s", plugin->GetCode(),
        plugin->GetPolicyName().c_str(), plugin->GetPermission(FuncOperateType::SET).c_str());
    if (!deviceAdmin->CheckPermission(plugin->GetPermission(FuncOperateType::SET)) ||
        (deviceAdmin->adminInfo_.adminType_ != AdminType::ENT &&
            deviceAdmin->adminInfo_.adminType_ != AdminType::SUB_SUPER_ADMIN && userId != GetCurrentUserId())) {
        EDMLOGW("HandleDevicePolicy: admin check permission failed");
        return EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED;
    }
    if (!VerifyCallingPermission(plugin->GetPermission(FuncOperateType::SET))) {
        EDMLOGW("HandleDevicePolicy: VerifyCallingPermission failed");
        return EdmReturnErrCode::PERMISSION_DENIED;
    }
    return UpdateDevicePolicy(code, admin, data, reply, userId);
}

ErrCode EnterpriseDeviceMgrAbility::GetDevicePolicy(uint32_t code, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    bool isUserExist = false;
    AccountSA::OsAccountManager::IsOsAccountExists(userId, isUserExist);
    if (!isUserExist) {
        reply.WriteInt32(EdmReturnErrCode::PARAM_ERROR);
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::shared_ptr<IPlugin> plugin = pluginMgr_->GetPluginByFuncCode(code);
    if (plugin == nullptr) {
        EDMLOGW("GetDevicePolicy: get plugin failed");
        reply.WriteInt32(EdmReturnErrCode::INTERFACE_UNSUPPORTED);
        return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
    }
    std::string adminName;
    std::string getPermission = plugin->GetPermission(FuncOperateType::GET);
    // has admin
    if (data.ReadInt32() == 0) {
        ErrCode ret = CheckGetPolicyPermission(data, reply, getPermission, adminName, userId);
        if (FAILED(ret)) {
            return ret;
        }
    }
    if (!getPermission.empty() && !VerifyCallingPermission(getPermission)) {
        EDMLOGW("GetDevicePolicy: VerifyCallingPermission failed");
        reply.WriteInt32(EdmReturnErrCode::PERMISSION_DENIED);
        return EdmReturnErrCode::PERMISSION_DENIED;
    }
    std::string policyName = plugin->GetPolicyName();
    std::string policyValue;

    policyMgr_ = GetAndSwitchPolicyManagerByUserId(userId);
    if (plugin->NeedSavePolicy()) {
        policyMgr_->GetPolicy(adminName, policyName, policyValue);
    }
    ErrCode ret = plugin->OnGetPolicy(policyValue, data, reply, userId);
    policyMgr_ = GetAndSwitchPolicyManagerByUserId(DEFAULT_USER_ID);
    return ret;
}

ErrCode EnterpriseDeviceMgrAbility::CheckGetPolicyPermission(MessageParcel &data, MessageParcel &reply,
    const std::string &getPermission, std::string &adminName, const int32_t userId)
{
    std::unique_ptr<AppExecFwk::ElementName> admin(data.ReadParcelable<AppExecFwk::ElementName>());
    if (!admin) {
        EDMLOGW("GetDevicePolicy: ReadParcelable failed");
        reply.WriteInt32(EdmReturnErrCode::PARAM_ERROR);
        return ERR_EDM_PARAM_ERROR;
    }
    std::shared_ptr<Admin> deviceAdmin = adminMgr_->GetAdminByPkgName(admin->GetBundleName(), userId);
    if (deviceAdmin == nullptr) {
        EDMLOGW("GetDevicePolicy: get admin failed");
        reply.WriteInt32(EdmReturnErrCode::ADMIN_INACTIVE);
        return EdmReturnErrCode::ADMIN_INACTIVE;
    }
    if (FAILED(CheckCallingUid(deviceAdmin->adminInfo_.packageName_))) {
        EDMLOGW("GetDevicePolicy: CheckCallingUid failed.");
        reply.WriteInt32(EdmReturnErrCode::PERMISSION_DENIED);
        return EdmReturnErrCode::PERMISSION_DENIED;
    }
    if (!getPermission.empty() && !deviceAdmin->CheckPermission(getPermission)) {
        EDMLOGW("GetDevicePolicy: admin check permission failed %{public}s", getPermission.c_str());
        reply.WriteInt32(EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED);
        return EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED;
    }
    adminName = admin->GetBundleName();
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::GetEnabledAdmin(AdminType type, std::vector<std::string> &enabledAdminList)
{
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    std::vector<std::string> superList;
    std::vector<std::string> normalList;
    switch (type) {
        case AdminType::NORMAL:
            adminMgr_->GetEnabledAdmin(AdminType::NORMAL, normalList, GetCurrentUserId());
            adminMgr_->GetEnabledAdmin(AdminType::ENT, superList, DEFAULT_USER_ID);
            break;
        case AdminType::ENT:
            adminMgr_->GetEnabledAdmin(AdminType::ENT, superList, DEFAULT_USER_ID);
            break;
        case AdminType::UNKNOWN:
            break;
        default:
            return ERR_EDM_PARAM_ERROR;
    }
    if (!superList.empty()) {
        enabledAdminList.insert(enabledAdminList.begin(), superList.begin(), superList.end());
    }
    if (!normalList.empty()) {
        enabledAdminList.insert(enabledAdminList.begin(), normalList.begin(), normalList.end());
    }
    for (const auto &enabledAdmin : enabledAdminList) {
        EDMLOGD("GetEnabledAdmin: %{public}s", enabledAdmin.c_str());
    }
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::GetEnterpriseInfo(AppExecFwk::ElementName &admin, MessageParcel &reply)
{
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    EntInfo entInfo;
    int32_t userId = adminMgr_->IsSuperOrSubSuperAdmin(admin.GetBundleName()) ? DEFAULT_USER_ID : GetCurrentUserId();
    ErrCode code = adminMgr_->GetEntInfo(admin.GetBundleName(), entInfo, userId);
    if (code != ERR_OK) {
        reply.WriteInt32(EdmReturnErrCode::ADMIN_INACTIVE);
        return EdmReturnErrCode::ADMIN_INACTIVE;
    }
    reply.WriteInt32(ERR_OK);
    entInfo.Marshalling(reply);
    EDMLOGD(
        "EnterpriseDeviceMgrAbility::GetEnterpriseInfo: entInfo->enterpriseName %{public}s, "
        "entInfo->description:%{public}s",
        entInfo.enterpriseName.c_str(), entInfo.description.c_str());
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::SetEnterpriseInfo(AppExecFwk::ElementName &admin, EntInfo &entInfo)
{
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    if (!VerifyCallingPermission(PERMISSION_SET_ENTERPRISE_INFO)) {
        EDMLOGW("EnterpriseDeviceMgrAbility::SetEnterpriseInfo: check permission failed");
        return EdmReturnErrCode::PERMISSION_DENIED;
    }
    int32_t userId = adminMgr_->IsSuperOrSubSuperAdmin(admin.GetBundleName()) ? DEFAULT_USER_ID : GetCurrentUserId();
    std::shared_ptr<Admin> adminItem = adminMgr_->GetAdminByPkgName(admin.GetBundleName(), userId);
    if (adminItem == nullptr) {
        return EdmReturnErrCode::ADMIN_INACTIVE;
    }
    int32_t ret = CheckCallingUid(adminItem->adminInfo_.packageName_);
    if (ret != ERR_OK) {
        EDMLOGW("SetEnterpriseInfo: CheckCallingUid failed: %{public}d", ret);
        return EdmReturnErrCode::PERMISSION_DENIED;
    }
    ErrCode code = adminMgr_->SetEntInfo(admin.GetBundleName(), entInfo, userId);
    return (code != ERR_OK) ? EdmReturnErrCode::ADMIN_INACTIVE : ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::HandleApplicationEvent(const std::vector<uint32_t> &events, bool subscribe)
{
    bool shouldHandleAppState = std::any_of(events.begin(), events.end(), [](uint32_t event) {
        return event == static_cast<uint32_t>(ManagedEvent::APP_START) ||
            event == static_cast<uint32_t>(ManagedEvent::APP_STOP);
    });
    if (!shouldHandleAppState) {
        return ERR_OK;
    }
    if (subscribe) {
        return SubscribeAppState() ? ERR_OK : EdmReturnErrCode::SYSTEM_ABNORMALLY;
    } else {
        return UnsubscribeAppState() ? ERR_OK : EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
}

ErrCode EnterpriseDeviceMgrAbility::SubscribeManagedEvent(const AppExecFwk::ElementName &admin,
    const std::vector<uint32_t> &events)
{
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    RETURN_IF_FAILED(VerifyManagedEvent(admin, events));
    RETURN_IF_FAILED(HandleApplicationEvent(events, true));
    int32_t userId = adminMgr_->IsSuperOrSubSuperAdmin(admin.GetBundleName()) ? DEFAULT_USER_ID : GetCurrentUserId();
    adminMgr_->SaveSubscribeEvents(events, admin.GetBundleName(), userId);
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::UnsubscribeManagedEvent(const AppExecFwk::ElementName &admin,
    const std::vector<uint32_t> &events)
{
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    RETURN_IF_FAILED(VerifyManagedEvent(admin, events));
    int32_t userId = adminMgr_->IsSuperOrSubSuperAdmin(admin.GetBundleName()) ? DEFAULT_USER_ID : GetCurrentUserId();
    adminMgr_->RemoveSubscribeEvents(events, admin.GetBundleName(), userId);
    return HandleApplicationEvent(events, false);
}

ErrCode EnterpriseDeviceMgrAbility::VerifyManagedEvent(const AppExecFwk::ElementName &admin,
    const std::vector<uint32_t> &events)
{
    if (!VerifyCallingPermission(PERMISSION_ENTERPRISE_SUBSCRIBE_MANAGED_EVENT)) {
        EDMLOGW("EnterpriseDeviceMgrAbility::VerifyManagedEvent: check permission failed");
        return EdmReturnErrCode::PERMISSION_DENIED;
    }
    std::shared_ptr<Admin> adminItem = adminMgr_->GetAdminByPkgName(admin.GetBundleName(), GetCurrentUserId());
    if (adminItem == nullptr) {
        return EdmReturnErrCode::ADMIN_INACTIVE;
    }
    int32_t ret = CheckCallingUid(adminItem->adminInfo_.packageName_);
    if (ret != ERR_OK) {
        EDMLOGW("VerifyManagedEvent: CheckCallingUid failed: %{public}d", ret);
        return EdmReturnErrCode::PERMISSION_DENIED;
    }
    if (events.empty()) {
        return EdmReturnErrCode::MANAGED_EVENTS_INVALID;
    }
    auto iter =
        std::find_if(events.begin(), events.end(), [this](uint32_t event) { return !CheckManagedEvent(event); });
    if (iter != std::end(events)) {
        return EdmReturnErrCode::MANAGED_EVENTS_INVALID;
    }
    return ERR_OK;
}

bool EnterpriseDeviceMgrAbility::CheckManagedEvent(uint32_t event)
{
    switch (event) {
        case static_cast<uint32_t>(ManagedEvent::BUNDLE_ADDED):
        case static_cast<uint32_t>(ManagedEvent::BUNDLE_REMOVED):
        case static_cast<uint32_t>(ManagedEvent::APP_START):
        case static_cast<uint32_t>(ManagedEvent::APP_STOP):
        case static_cast<uint32_t>(ManagedEvent::SYSTEM_UPDATE):
            break;
        default:
            return false;
    }
    return true;
}

ErrCode EnterpriseDeviceMgrAbility::AuthorizeAdmin(const AppExecFwk::ElementName &admin, const std::string &bundleName)
{
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    if (!VerifyCallingPermission(PERMISSION_MANAGE_ENTERPRISE_DEVICE_ADMIN)) {
        EDMLOGW("EnterpriseDeviceMgrAbility::AuthorizeAdmin: check permission failed");
        return EdmReturnErrCode::PERMISSION_DENIED;
    }
    std::shared_ptr<Admin> adminItem = adminMgr_->GetAdminByPkgName(admin.GetBundleName(), GetCurrentUserId());
    if (adminItem == nullptr) {
        EDMLOGW("EnterpriseDeviceMgrAbility::AuthorizeAdmin: not active admin.");
        return EdmReturnErrCode::ADMIN_INACTIVE;
    }
    if (adminItem->GetAdminType() != AdminType::ENT) {
        EDMLOGW("AuthorizeAdmin: Caller is not super admin.");
        return EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED;
    }
    if (FAILED(CheckCallingUid(admin.GetBundleName()))) {
        EDMLOGW("AuthorizeAdmin: CheckCallingUid failed.");
        return EdmReturnErrCode::PERMISSION_DENIED;
    }
    /* Get all request and registered permissions */
    std::vector<std::string> permissionList;
    if (FAILED(GetAllPermissionsByAdmin(bundleName, permissionList, DEFAULT_USER_ID))) {
        EDMLOGW("EnableAdmin: GetAllPermissionsByAdmin failed.");
        return EdmReturnErrCode::AUTHORIZE_PERMISSION_FAILED;
    }
    if (FAILED(adminMgr_->SaveAuthorizedAdmin(bundleName, permissionList, admin.GetBundleName()))) {
        EDMLOGW("EnableAdmin: SaveAuthorizedAdmin failed.");
        return EdmReturnErrCode::AUTHORIZE_PERMISSION_FAILED;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS