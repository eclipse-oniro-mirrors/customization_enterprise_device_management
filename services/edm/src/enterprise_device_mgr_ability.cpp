/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include <cstring>
#include <iservice_registry.h>
#include <message_parcel.h>
#include <string_ex.h>
#include <system_ability.h>
#include <system_ability_definition.h>

#include "application_state_observer.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "device_policies_storage_rdb.h"
#include "directory_ex.h"
#include "matching_skills.h"
#include "parameters.h"
#include "security_report.h"

#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "edm_sys_manager.h"
#include "enterprise_admin_connection.h"
#include "enterprise_bundle_connection.h"
#include "enterprise_conn_manager.h"
#include "func_code_utils.h"
#include "password_policy_serializer.h"
#include "user_auth_client.h"

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
const std::string DEVELOP_MODE_STATE = "const.security.developermode.state";

const std::vector<uint32_t> codeList = {
    EdmInterfaceCode::RESET_FACTORY,
    EdmInterfaceCode::DISABLED_PRINTER,
    EdmInterfaceCode::DISABLED_HDC,
    EdmInterfaceCode::NTP_SERVER,
};

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
    addSystemAbilityFuncMap_[ABILITY_MGR_SERVICE_ID] = &EnterpriseDeviceMgrAbility::OnAbilityManagerServiceStart;
    addSystemAbilityFuncMap_[SUBSYS_USERIAM_SYS_ABILITY_USERAUTH] =
        &EnterpriseDeviceMgrAbility::OnUserAuthFrameworkStart;
}

#ifdef COMMON_EVENT_SERVICE_EDM_ENABLE
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
#endif

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
        if (FAILED(RemoveAdminAndAdminPolicy(item->adminInfo_.packageName_, userIdToRemove))) {
            EDMLOGW("EnterpriseDeviceMgrAbility::OnCommonEventUserRemoved remove admin failed packagename = %{public}s",
                item->adminInfo_.packageName_.c_str());
        }
    }
    std::vector<std::shared_ptr<Admin>> subAndSuperAdmin;
    adminMgr_->GetAdminByUserId(DEFAULT_USER_ID, subAndSuperAdmin);
    for (const auto &subAdmin : subAndSuperAdmin) {
        if ((subAdmin->GetAdminType() == AdminType::SUB_SUPER_ADMIN || subAdmin->GetAdminType() == AdminType::ENT) &&
            FAILED(RemoveAdminAndAdminPolicy(subAdmin->adminInfo_.packageName_, userIdToRemove))) {
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
            RemoveAdminAndAdminPolicy(bundleName, userId);
        }
        if (admin->adminInfo_.adminType_ == AdminType::SUB_SUPER_ADMIN && userId == DEFAULT_USER_ID) {
            // remove sub super admin and sub super admin policy
            RemoveSubSuperAdminAndAdminPolicy(bundleName);
        }
        if (admin->adminInfo_.adminType_ == AdminType::ENT && userId == DEFAULT_USER_ID) {
            // remove super admin and super admin policy
            RemoveSuperAdminAndAdminPolicy(bundleName);
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

    if (!pluginMgr_) {
        pluginMgr_ = PluginManager::GetInstance();
    }
    EDMLOGD("create pluginMgr_ success");
    pluginMgr_->Init();

    if (!policyMgr_) {
        policyMgr_ = std::make_shared<PolicyManager>();
        IPolicyManager::policyManagerInstance_ = policyMgr_.get();
    }
    InitAllPolices();

    AddOnAddSystemAbilityFuncMap();
    AddSystemAbilityListener(COMMON_EVENT_SERVICE_ID);
    AddSystemAbilityListener(APP_MGR_SERVICE_ID);
    AddSystemAbilityListener(ABILITY_MGR_SERVICE_ID);
    AddSystemAbilityListener(SUBSYS_USERIAM_SYS_ABILITY_USERAUTH);
    RemoveAllDebugAdmin();
}

void EnterpriseDeviceMgrAbility::InitAllPolices()
{
    std::vector<int32_t> userIds;
    auto devicePolicies = DevicePoliciesStorageRdb::GetInstance();
    if (devicePolicies == nullptr) {
        EDMLOGW("OnAddSystemAbility::InitAllPolices:get rdbStore failed.");
        return;
    }
    EDMLOGI("InitAllPolices userIds size %{public}zu", userIds.size());
    devicePolicies->QueryAllUserId(userIds);
    policyMgr_->Init(userIds);
}

void EnterpriseDeviceMgrAbility::RemoveAllDebugAdmin()
{
    bool isDebug = system::GetBoolParameter(DEVELOP_MODE_STATE, false);
    if (!isDebug) {
        std::vector<std::shared_ptr<Admin>> userAdmin;
        adminMgr_->GetAdminByUserId(DEFAULT_USER_ID, userAdmin);
        for (const auto &item: userAdmin) {
            if (item->adminInfo_.isDebug_) {
                EDMLOGD("remove debug admin %{public}s", item->adminInfo_.packageName_.c_str());
                RemoveSuperAdminAndAdminPolicy(item->adminInfo_.packageName_);
            }
        }
    }
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

void EnterpriseDeviceMgrAbility::OnAbilityManagerServiceStart(int32_t systemAbilityId, const std::string &deviceId)
{
    EDMLOGI("OnAbilityManagerServiceStart");
    auto superAdmin = adminMgr_->GetSuperAdmin();
    if (superAdmin != nullptr) {
        AAFwk::Want connectWant;
        connectWant.SetElementName(superAdmin->adminInfo_.packageName_, superAdmin->adminInfo_.className_);
        std::shared_ptr<EnterpriseConnManager> manager = DelayedSingleton<EnterpriseConnManager>::GetInstance();
        sptr<IEnterpriseConnection> connection = manager->CreateAdminConnection(connectWant,
            IEnterpriseAdmin::COMMAND_ON_ADMIN_ENABLED, DEFAULT_USER_ID, false);
        manager->ConnectAbility(connection);
    }
}

void EnterpriseDeviceMgrAbility::OnCommonEventServiceStart(int32_t systemAbilityId, const std::string &deviceId)
{
#ifdef COMMON_EVENT_SERVICE_EDM_ENABLE
    commonEventSubscriber = CreateEnterpriseDeviceEventSubscriber(*this);
    EventFwk::CommonEventManager::SubscribeCommonEvent(this->commonEventSubscriber);
    EDMLOGI("create commonEventSubscriber success");
#else
    EDMLOGW("EnterpriseDeviceMgrAbility::OnCommonEventServiceStart Unsupported Capabilities.");
    return;
#endif
}

void EnterpriseDeviceMgrAbility::OnUserAuthFrameworkStart(int32_t systemAbilityId, const std::string &deviceId)
{
    EDMLOGI("OnUserAuthFrameworkStart");
    std::string policyData;
    policyMgr_->GetPolicy("", "password_policy", policyData, EdmConstants::DEFAULT_USER_ID);
    auto serializer_ = PasswordSerializer::GetInstance();
    PasswordPolicy policy;
    serializer_->Deserialize(policyData, policy);
    UserIam::UserAuth::GlobalConfigParam param;
    param.type = UserIam::UserAuth::GlobalConfigType::PIN_EXPIRED_PERIOD;
    param.value.pinExpiredPeriod = policy.validityPeriod;
    int32_t ret = UserIam::UserAuth::UserAuthClient::GetInstance().SetGlobalConfigParam(param);
    if (ret != 0) {
        EDMLOGW("SetGlobalConfigParam Error");
    }
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
    if (permissionList.size() > 0) {
        permissionList.clear();
    }
    EDMLOGD("GetAllPermissionsByAdmin GetBundleInfo: bundleInfoName %{public}s userid %{public}d",
        bundleInfoName.c_str(), userId);
    ret = GetBundleMgr()->GetBundleInfo(bundleInfoName, AppExecFwk::BundleFlag::GET_BUNDLE_WITH_REQUESTED_PERMISSION,
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

std::shared_ptr<IEdmBundleManager> EnterpriseDeviceMgrAbility::GetBundleMgr()
{
    return GetExternalManagerFactory()->CreateBundleManager();
}

std::shared_ptr<IEdmAppManager> EnterpriseDeviceMgrAbility::GetAppMgr()
{
    return GetExternalManagerFactory()->CreateAppManager();
}

std::shared_ptr<IEdmOsAccountManager> EnterpriseDeviceMgrAbility::GetOsAccountMgr()
{
    return GetExternalManagerFactory()->CreateOsAccountManager();
}

bool EnterpriseDeviceMgrAbility::SubscribeAppState()
{
    if (appStateObserver_) {
        EDMLOGD("appStateObserver has subscribed");
        return true;
    }
    appStateObserver_ = new (std::nothrow) ApplicationStateObserver(*this);
    if (!appStateObserver_) {
        EDMLOGE("new ApplicationStateObserver failed");
        return false;
    }
    if (GetAppMgr()->RegisterApplicationStateObserver(appStateObserver_)) {
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
    if (GetAppMgr()->UnregisterApplicationStateObserver(appStateObserver_)) {
        EDMLOGE("UnregisterApplicationStateObserver fail!");
        return false;
    }
    appStateObserver_.clear();
    appStateObserver_ = nullptr;
    return true;
}

ErrCode EnterpriseDeviceMgrAbility::VerifyEnableAdminCondition(AppExecFwk::ElementName &admin, AdminType type,
    int32_t userId, bool isDebug)
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
        if (isDebug != existAdmin->adminInfo_.isDebug_) {
            EDMLOGW("EnableAdmin: debug parameter can not be changed.");
            return ERR_EDM_ADD_ADMIN_FAILED;
        }
        /* An application can't be enabled twice with different ability name */
        if (existAdmin->adminInfo_.className_ != admin.GetAbilityName()) {
            EDMLOGW("EnableAdmin: There is another admin ability enabled with the same package name.");
            return ERR_EDM_ADD_ADMIN_FAILED;
        }
    }
    if (!isDebug && type == AdminType::ENT && adminMgr_->IsSuperAdminExist()) {
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
    bool isDebug = GetAccessTokenMgr()->IsDebug();
    if (!isDebug && !GetAccessTokenMgr()->VerifyCallingPermission(PERMISSION_MANAGE_ENTERPRISE_DEVICE_ADMIN)) {
        EDMLOGW("EnterpriseDeviceMgrAbility::EnableAdmin check permission failed");
        return EdmReturnErrCode::PERMISSION_DENIED;
    }
    std::vector<AppExecFwk::ExtensionAbilityInfo> abilityInfo;
    AAFwk::Want want;
    want.SetElement(admin);
    if (!GetBundleMgr()->QueryExtensionAbilityInfos(want, AppExecFwk::ExtensionAbilityType::ENTERPRISE_ADMIN,
        AppExecFwk::ExtensionAbilityInfoFlag::GET_EXTENSION_INFO_WITH_PERMISSION, userId, abilityInfo) ||
        abilityInfo.empty()) {
        EDMLOGW("EnableAdmin: QueryExtensionAbilityInfos failed");
        return EdmReturnErrCode::COMPONENT_INVALID;
    }
    if (FAILED(VerifyEnableAdminCondition(admin, type, userId, isDebug))) {
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
    Admin edmAdmin(abilityInfo.at(0), type, entInfo, permissionList, isDebug);
    if (FAILED(adminMgr_->SetAdminValue(userId, edmAdmin))) {
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
        ret = policyMgr_->GetAdminByPolicyName(policyName, adminListMap, userId);
        if ((ret == ERR_EDM_POLICY_NOT_FOUND) || adminListMap.empty()) {
            setRet = policyMgr_->SetPolicy("", policyName, "", "", userId);
        } else {
            setRet = policyMgr_->SetPolicy(adminName, policyName, "", mergedPolicyData, userId);
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

ErrCode EnterpriseDeviceMgrAbility::RemoveAdminAndAdminPolicy(const std::string &adminName, int32_t userId)
{
    EDMLOGD("RemoveAdminAndAdminPolicy:admin: %{public}s, user id:%{public}d.", adminName.c_str(), userId);
    ErrCode removeAdminPolicyRet = RemoveAdminPolicy(adminName, userId);
    if (FAILED(removeAdminPolicyRet)) {
        EDMLOGE("Remove admin %{public}s policy with user id = %{public}d fail.", adminName.c_str(), userId);
        return removeAdminPolicyRet;
    }

    ErrCode removeAdminRet = RemoveAdmin(adminName, userId);
    if (FAILED(removeAdminRet)) {
        EDMLOGE("Remove admin %{public}s with user id = %{public}d fail.", adminName.c_str(), userId);
        return removeAdminRet;
    }
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::RemoveAdmin(const std::string &adminName, int32_t userId)
{
    bool shouldUnsubscribeAppState = ShouldUnsubscribeAppState(adminName, userId);
    auto ret = adminMgr_->DeleteAdmin(adminName, userId);
    if (ret != ERR_OK && ret != ERR_EDM_UNKNOWN_ADMIN) {
        return ERR_EDM_DEL_ADMIN_FAILED;
    }
    if (shouldUnsubscribeAppState) {
        UnsubscribeAppState();
    }
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::RemoveAdminPolicy(const std::string &adminName, int32_t userId)
{
    std::unordered_map<std::string, std::string> policyItems;
    policyMgr_->GetAllPolicyByAdmin(adminName, policyItems, userId);
    for (const auto &policyItem : policyItems) {
        std::string policyItemName = policyItem.first;
        std::string policyItemValue = policyItem.second;
        EDMLOGD("RemoveAdminPolicy:policyName:%{public}s", policyItemName.c_str());
        if (RemoveAdminItem(adminName, policyItemName, policyItemValue, userId) != ERR_OK) {
            return ERR_EDM_DEL_ADMIN_FAILED;
        }
    }
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::RemoveSubSuperAdminAndAdminPolicy(const std::string &bundleName)
{
    std::vector<int32_t> userIds;
    policyMgr_->GetPolicyUserIds(userIds);
    return RemoveSubOrSuperAdminAndAdminPolicy(bundleName, userIds);
}

ErrCode EnterpriseDeviceMgrAbility::RemoveSuperAdminAndAdminPolicy(const std::string &bundleName)
{
    std::vector<int32_t> userIds;
    policyMgr_->GetPolicyUserIds(userIds);
    // remove sub-super admin
    std::vector<std::string> subAdmins;
    adminMgr_->GetSubSuperAdminsByParentName(bundleName, subAdmins);
    for (auto const &subAdminName : subAdmins) {
        if (RemoveSubOrSuperAdminAndAdminPolicy(subAdminName, userIds) != ERR_OK) {
            return ERR_EDM_DEL_ADMIN_FAILED;
        }
    }
    // remove super admin on other userid
    return RemoveSubOrSuperAdminAndAdminPolicy(bundleName, userIds);
}

ErrCode EnterpriseDeviceMgrAbility::RemoveSubOrSuperAdminAndAdminPolicy(const std::string &bundleName,
    const std::vector<int32_t> &nonDefaultUserIds)
{
    // remove super admin on other userid
    for (auto const &userId : nonDefaultUserIds) {
        if (RemoveAdminAndAdminPolicy(bundleName, userId) != ERR_OK) {
            return ERR_EDM_DEL_ADMIN_FAILED;
        }
    }
    // remove super admin default userid
    return RemoveAdminAndAdminPolicy(bundleName, DEFAULT_USER_ID);
}

bool EnterpriseDeviceMgrAbility::ShouldUnsubscribeAppState(const std::string &adminName, int32_t userId)
{
    std::shared_ptr<Admin> adminPtr = adminMgr_->GetAdminByPkgName(adminName, userId);
    return std::any_of(adminPtr->adminInfo_.managedEvents_.begin(), adminPtr->adminInfo_.managedEvents_.end(),
        [](ManagedEvent event) { return event == ManagedEvent::APP_START || event == ManagedEvent::APP_STOP; });
}

ErrCode EnterpriseDeviceMgrAbility::DisableAdmin(AppExecFwk::ElementName &admin, int32_t userId)
{
    EDMLOGI("EnterpriseDeviceMgrAbility::DisableAdmin user id = %{public}d", userId);
    bool isSDA = IsSuperAdmin(admin.GetBundleName());
    userId = isSDA ? DEFAULT_USER_ID : userId;
    AdminType adminType = isSDA ? AdminType::ENT : AdminType::NORMAL;
    return DoDisableAdmin(admin.GetBundleName(), userId, adminType);
}

ErrCode EnterpriseDeviceMgrAbility::CheckCallingUid(const std::string &bundleName)
{
    // super admin can be removed by itself
    int uid = GetCallingUid();
    std::string callingBundleName;
    if (GetBundleMgr()->GetNameForUid(uid, callingBundleName) != ERR_OK) {
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
    EDMLOGI("EnterpriseDeviceMgrAbility::DisableSuperAdmin bundle name = %{public}s", bundleName.c_str());
    return DoDisableAdmin(bundleName, DEFAULT_USER_ID, AdminType::ENT);
}

ErrCode EnterpriseDeviceMgrAbility::DoDisableAdmin(const std::string &bundleName, int32_t userId, AdminType adminType)
{
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    bool isDebug = GetAccessTokenMgr()->IsDebug();
    if (!isDebug && !GetAccessTokenMgr()->VerifyCallingPermission(PERMISSION_MANAGE_ENTERPRISE_DEVICE_ADMIN)) {
        EDMLOGW("DoDisableAdmin::DisableSuperAdmin check permission failed.");
        return EdmReturnErrCode::PERMISSION_DENIED;
    }
    std::shared_ptr<Admin> admin = adminMgr_->GetAdminByPkgName(bundleName, userId);
    if (admin == nullptr) {
        return EdmReturnErrCode::DISABLE_ADMIN_FAILED;
    }
    if (isDebug && !admin->adminInfo_.isDebug_) {
        EDMLOGW("DoDisableAdmin: shell command can only remove debug super admin.");
        return EdmReturnErrCode::DISABLE_ADMIN_FAILED;
    }
    if (admin->adminInfo_.adminType_ != adminType) {
        EDMLOGW("DoDisableAdmin: only remove the certain admin.");
        return EdmReturnErrCode::DISABLE_ADMIN_FAILED;
    }
    if (adminType == AdminType::ENT && FAILED(RemoveSuperAdminAndAdminPolicy(bundleName))) {
        EDMLOGW("DoDisableAdmin: remove admin failed.");
        return EdmReturnErrCode::DISABLE_ADMIN_FAILED;
    } else if (adminType == AdminType::NORMAL && FAILED(RemoveAdminAndAdminPolicy(bundleName, userId))) {
        EDMLOGW("DoDisableAdmin: disable admin failed.");
        return EdmReturnErrCode::DISABLE_ADMIN_FAILED;
    }
    if (!adminMgr_->IsAdminExist()) {
        system::SetParameter(PARAM_EDM_ENABLE, "false");
    }
    AAFwk::Want want;
    want.SetElementName(admin->adminInfo_.packageName_, admin->adminInfo_.className_);
    std::shared_ptr<EnterpriseConnManager> manager = DelayedSingleton<EnterpriseConnManager>::GetInstance();
    sptr<IEnterpriseConnection> connection =
        manager->CreateAdminConnection(want, IEnterpriseAdmin::COMMAND_ON_ADMIN_DISABLED, userId);
    manager->ConnectAbility(connection);
    return ERR_OK;
}

bool EnterpriseDeviceMgrAbility::IsSuperAdmin(const std::string &bundleName)
{
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    return adminMgr_->IsSuperAdmin(bundleName);
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
    ErrCode ret = GetOsAccountMgr()->QueryActiveOsAccountIds(ids);
    if (FAILED(ret) || ids.empty()) {
        EDMLOGE("EnterpriseDeviceMgrAbility GetCurrentUserId failed");
        return -1;
    }
    EDMLOGD("EnterpriseDeviceMgrAbility GetCurrentUserId user id = %{public}d", ids.at(0));
    return (ids.at(0));
}

ErrCode EnterpriseDeviceMgrAbility::UpdateDevicePolicy(uint32_t code, AppExecFwk::ElementName &admin,
    MessageParcel &data, MessageParcel &reply, int32_t userId)
{
    std::shared_ptr<IPlugin> plugin = pluginMgr_->GetPluginByFuncCode(code);
    if (plugin == nullptr) {
        EDMLOGW("UpdateDevicePolicy: get plugin failed, code:%{public}d", code);
        return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
    }

    std::string policyName = plugin->GetPolicyName();
    HandlePolicyData handlePolicyData{"", false};
    policyMgr_->GetPolicy(admin.GetBundleName(), policyName, handlePolicyData.policyData, userId);
    ErrCode ret = plugin->GetExecuteStrategy()->OnSetExecute(code, data, reply, handlePolicyData, userId);
    if (FAILED(ret)) {
        EDMLOGW("UpdateDevicePolicy: OnHandlePolicy failed");
        return ret;
    }
    EDMLOGD("UpdateDevicePolicy: isChanged:%{public}d, needSave:%{public}d", handlePolicyData.isChanged,
        plugin->NeedSavePolicy());
    std::string oldCombinePolicy;
    policyMgr_->GetPolicy("", policyName, oldCombinePolicy, userId);
    std::string mergedPolicy = handlePolicyData.policyData;
    bool isGlobalChanged = false;
    if (plugin->NeedSavePolicy() && handlePolicyData.isChanged) {
        ret = plugin->MergePolicyData(admin.GetBundleName(), mergedPolicy);
        if (FAILED(ret)) {
            EDMLOGW("UpdateDevicePolicy: MergePolicyData failed error:%{public}d", ret);
            return ret;
        }
        policyMgr_->SetPolicy(admin.GetBundleName(), policyName, handlePolicyData.policyData, mergedPolicy, userId);
        isGlobalChanged = (oldCombinePolicy != mergedPolicy);
    }
    plugin->OnHandlePolicyDone(code, admin.GetBundleName(), isGlobalChanged, userId);
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::HandleDevicePolicy(uint32_t code, AppExecFwk::ElementName &admin,
    MessageParcel &data, MessageParcel &reply, int32_t userId)
{
    std::lock_guard<std::mutex> autoLock(mutexLock_);
#ifndef EDM_FUZZ_TEST
    bool isUserExist = false;
    GetOsAccountMgr()->IsOsAccountExists(userId, isUserExist);
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
    std::string permissionTag = data.ReadString();
    std::string setPermission = plugin->GetPermission(FuncOperateType::SET, permissionTag);
    if (setPermission == NONE_PERMISSION_MATCH) {
        EDMLOGE("HandleDevicePolicy: GetPermission failed!");
        return EdmReturnErrCode::PERMISSION_DENIED;
    }
    EDMLOGD("HandleDevicePolicy: plugin info:%{public}d , %{public}s , %{public}s", plugin->GetCode(),
        plugin->GetPolicyName().c_str(), setPermission.c_str());
    if (plugin->GetApiType(FuncOperateType::SET) == IPlugin::ApiType::SYSTEM &&
        !GetAccessTokenMgr()->IsSystemAppOrNative()) {
        EDMLOGE("HandleDevicePolicy: not system app or native process");
        return EdmReturnErrCode::SYSTEM_API_DENIED;
    }
    if (!deviceAdmin->CheckPermission(setPermission) ||
        (deviceAdmin->adminInfo_.adminType_ != AdminType::ENT &&
            deviceAdmin->adminInfo_.adminType_ != AdminType::SUB_SUPER_ADMIN && userId != GetCurrentUserId())) {
        EDMLOGW("HandleDevicePolicy: admin check permission failed");
        return EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED;
    }
    if (!GetAccessTokenMgr()->VerifyCallingPermission(setPermission)) {
        EDMLOGW("HandleDevicePolicy: VerifyCallingPermission failed");
        return EdmReturnErrCode::PERMISSION_DENIED;
    }
    CreateSecurityContent(deviceAdmin, plugin);
#endif
    return UpdateDevicePolicy(code, admin, data, reply, userId);
}

void EnterpriseDeviceMgrAbility::CreateSecurityContent(std::shared_ptr<Admin> deviceAdmin,
    std::shared_ptr<IPlugin> plugin)
{
    if (std::find(codeList.begin(), codeList.end(), plugin->GetCode()) == codeList.end()) {
        EDMLOGE("EnterpriseDeviceMgrAbility::CreateSecurityContent code not in list: %{public}d", plugin->GetCode());
        return;
    }
    std::string bundleName = deviceAdmin->adminInfo_.packageName_;
    std::string abilityName = deviceAdmin->adminInfo_.className_;
    std::string policyName = plugin->GetPolicyName();
    SecurityReport::ReportSecurityInfo(bundleName, abilityName, policyName);
}

ErrCode EnterpriseDeviceMgrAbility::GetDevicePolicy(uint32_t code, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    bool isUserExist = false;
    GetOsAccountMgr()->IsOsAccountExists(userId, isUserExist);
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
    if (plugin->GetApiType(FuncOperateType::GET) == IPlugin::ApiType::SYSTEM &&
        !GetAccessTokenMgr()->IsSystemAppOrNative()) {
        EDMLOGE("GetDevicePolicy: not system app or native process");
        return EdmReturnErrCode::SYSTEM_API_DENIED;
    }
    std::string permissionTag = data.ReadString();
    std::string adminName;
    std::string getPermission = plugin->GetPermission(FuncOperateType::GET, permissionTag);
    // has admin
    if (data.ReadInt32() == 0) {
        if (getPermission == NONE_PERMISSION_MATCH) {
            EDMLOGE("GetDevicePolicy: GetPermission failed!");
            return EdmReturnErrCode::PERMISSION_DENIED;
        }
        ErrCode ret = CheckGetPolicyPermission(data, reply, getPermission, adminName, userId);
        if (FAILED(ret)) {
            return ret;
        }
    }
    std::string policyName = plugin->GetPolicyName();
    std::string policyValue;

    if (plugin->NeedSavePolicy()) {
        policyMgr_->GetPolicy(adminName, policyName, policyValue, userId);
    }
    return plugin->GetExecuteStrategy()->OnGetExecute(code, policyValue, data, reply, userId);
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
    if (!GetAccessTokenMgr()->VerifyCallingPermission(PERMISSION_SET_ENTERPRISE_INFO)) {
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
    if (!GetAccessTokenMgr()->VerifyCallingPermission(PERMISSION_ENTERPRISE_SUBSCRIBE_MANAGED_EVENT)) {
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
    if (!GetAccessTokenMgr()->VerifyCallingPermission(PERMISSION_MANAGE_ENTERPRISE_DEVICE_ADMIN)) {
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
        EDMLOGW("AuthorizeAdmin: GetAllPermissionsByAdmin failed.");
        return EdmReturnErrCode::AUTHORIZE_PERMISSION_FAILED;
    }
    if (FAILED(adminMgr_->SaveAuthorizedAdmin(bundleName, permissionList, admin.GetBundleName()))) {
        EDMLOGW("AuthorizeAdmin: SaveAuthorizedAdmin failed.");
        return EdmReturnErrCode::AUTHORIZE_PERMISSION_FAILED;
    }
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::GetSuperAdmin(MessageParcel &reply)
{
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    auto superAdmin = adminMgr_->GetSuperAdmin();
    reply.WriteInt32(ERR_OK);
    if (superAdmin == nullptr) {
        reply.WriteString("");
        reply.WriteString("");
    } else {
        reply.WriteString(superAdmin->adminInfo_.packageName_);
        reply.WriteString(superAdmin->adminInfo_.className_);
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS