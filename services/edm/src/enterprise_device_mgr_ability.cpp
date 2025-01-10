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
#include <string_ex.h>
#include <thread>

#include "application_state_observer.h"
#include "bundle_info.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "device_policies_storage_rdb.h"
#include "directory_ex.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "matching_skills.h"
#include "message_parcel.h"
#include "mock_session_manager_service_interface.h"
#include "parameters.h"
#include "system_ability.h"
#include "system_ability_definition.h"

#include "array_string_serializer.h"
#include "edm_constants.h"
#include "edm_data_ability_utils.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "edm_sys_manager.h"
#include "enterprise_admin_connection.h"
#include "enterprise_bundle_connection.h"
#include "enterprise_conn_manager.h"
#include "func_code_utils.h"
#include "plugin_policy_reader.h"

#ifdef PASTEBOARD_EDM_ENABLE
#include "clipboard_policy_serializer.h"
#include "clipboard_utils.h"
#endif

#ifdef NET_MANAGER_BASE_EDM_ENABLE
#include "map_string_serializer.h"
#include "net_policy_client.h"
#endif
#ifdef USERIAM_EDM_ENABLE
#include "fingerprint_policy.h"
#include "fingerprint_policy_serializer.h"
#include "password_policy_serializer.h"
#include "usb_device_id.h"
#include "user_auth_client.h"
#endif

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT =
    SystemAbility::MakeAndRegisterAbility(EnterpriseDeviceMgrAbility::GetInstance().GetRefPtr());

const std::string PERMISSION_MANAGE_ENTERPRISE_DEVICE_ADMIN = "ohos.permission.MANAGE_ENTERPRISE_DEVICE_ADMIN";
const std::string PERMISSION_SET_ENTERPRISE_INFO = "ohos.permission.SET_ENTERPRISE_INFO";
const std::string PERMISSION_ENTERPRISE_SUBSCRIBE_MANAGED_EVENT = "ohos.permission.ENTERPRISE_SUBSCRIBE_MANAGED_EVENT";
const std::string PERMISSION_UPDATE_SYSTEM = "ohos.permission.UPDATE_SYSTEM";
const std::string PERMISSION_SET_DELEGATED_POLICY = "ohos.permission.ENTERPRISE_MANAGE_DELEGATED_POLICY";
const std::string PERMISSION_GET_ADMINPROVISION_INFO = "ohos.permission.START_PROVISIONING_MESSAGE";
const std::string PARAM_EDM_ENABLE = "persist.edm.edm_enable";
const std::string PARAM_SECURITY_MODE = "ohos.boot.advsecmode.state";
const std::string SYSTEM_UPDATE_FOR_POLICY = "usual.event.DUE_SA_FIRMWARE_UPDATE_FOR_POLICY";
const std::string FIRMWARE_EVENT_INFO_NAME = "version";
const std::string FIRMWARE_EVENT_INFO_TYPE = "packageType";
const std::string FIRMWARE_EVENT_INFO_CHECK_TIME = "firstReceivedTime";
const std::string DEVELOP_MODE_STATE = "const.security.developermode.state";
const std::string EDM_ADMIN_ENABLED_EVENT = "com.ohos.edm.edmadminenabled";
const std::string EDM_ADMIN_DISABLED_EVENT = "com.ohos.edm.edmadmindisabled";
const std::string APP_TYPE_ENTERPRISE_MDM = "enterprise_mdm";
const std::string APP_TYPE_ENTERPRISE_NORMAL = "enterprise_normal";
const char* const KEY_EDM_DISPLAY = "com.enterprise.enterprise_device_manager_display";
const std::string DISALLOWED_UNINSTALL_POLICY =  "disallowed_uninstall_bundles";

std::mutex EnterpriseDeviceMgrAbility::mutexLock_;

sptr<EnterpriseDeviceMgrAbility> EnterpriseDeviceMgrAbility::instance_;

constexpr int32_t TIMER_TIMEOUT = 360000; // 6 * 60 * 1000;

void EnterpriseDeviceMgrAbility::AddCommonEventFuncMap()
{
    commonEventFuncMap_[EventFwk::CommonEventSupport::COMMON_EVENT_USER_ADDED] =
        [](EnterpriseDeviceMgrAbility* that, const EventFwk::CommonEventData &data) {
            that->OnCommonEventUserAdded(data);
        };
    commonEventFuncMap_[EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED] =
        [](EnterpriseDeviceMgrAbility* that, const EventFwk::CommonEventData &data) {
            that->OnCommonEventUserSwitched(data);
        };
    commonEventFuncMap_[EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED] =
        [](EnterpriseDeviceMgrAbility* that, const EventFwk::CommonEventData &data) {
            that->OnCommonEventUserRemoved(data);
        };
    commonEventFuncMap_[EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED] =
        [](EnterpriseDeviceMgrAbility* that, const EventFwk::CommonEventData &data) {
            that->OnCommonEventPackageAdded(data);
        };
    commonEventFuncMap_[EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED] =
        [](EnterpriseDeviceMgrAbility* that, const EventFwk::CommonEventData &data) {
            that->OnCommonEventPackageRemoved(data);
        };
    commonEventFuncMap_[SYSTEM_UPDATE_FOR_POLICY] =
        [](EnterpriseDeviceMgrAbility* that, const EventFwk::CommonEventData &data) {
            that->OnCommonEventSystemUpdate(data);
        };
    commonEventFuncMap_[EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED] =
        [](EnterpriseDeviceMgrAbility* that, const EventFwk::CommonEventData &data) {
            that->OnCommonEventPackageChanged(data);
        };
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
    AdminManager::GetInstance()->GetAdminBySubscribeEvent(ManagedEvent::SYSTEM_UPDATE, subAdmins);
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
    addSystemAbilityFuncMap_[APP_MGR_SERVICE_ID] =
        [](EnterpriseDeviceMgrAbility* that, int32_t systemAbilityId, const std::string &deviceId) {
            that->OnAppManagerServiceStart();
        };
    addSystemAbilityFuncMap_[COMMON_EVENT_SERVICE_ID] =
        [](EnterpriseDeviceMgrAbility* that, int32_t systemAbilityId, const std::string &deviceId) {
            that->OnCommonEventServiceStart();
        };
    addSystemAbilityFuncMap_[ABILITY_MGR_SERVICE_ID] =
        [](EnterpriseDeviceMgrAbility* that, int32_t systemAbilityId, const std::string &deviceId) {
            that->OnAbilityManagerServiceStart();
        };
    addSystemAbilityFuncMap_[WINDOW_MANAGER_SERVICE_ID] =
        [](EnterpriseDeviceMgrAbility* that, int32_t systemAbilityId, const std::string &deviceId) {
            that->OnWindowManagerServiceStart();
        };
#ifdef PASTEBOARD_EDM_ENABLE
    addSystemAbilityFuncMap_[PASTEBOARD_SERVICE_ID] =
        [](EnterpriseDeviceMgrAbility* that, int32_t systemAbilityId, const std::string &deviceId) {
            that->OnPasteboardServiceStart();
        };
#endif
#ifdef NET_MANAGER_BASE_EDM_ENABLE
    addSystemAbilityFuncMap_[COMM_NET_POLICY_MANAGER_SYS_ABILITY_ID] =
        [](EnterpriseDeviceMgrAbility* that, int32_t systemAbilityId, const std::string &deviceId) {
            that->OnNetManagerBaseServiceStart();
        };
#endif
#ifdef USB_EDM_ENABLE
    addSystemAbilityFuncMap_[USB_SYSTEM_ABILITY_ID] =
        [](EnterpriseDeviceMgrAbility* that, int32_t systemAbilityId, const std::string &deviceId) {
            that->OnUsbServiceStart();
        };
#endif
    addSystemAbilityFuncMap_[RENDER_SERVICE] =
        [](EnterpriseDeviceMgrAbility* that, int32_t systemAbilityId, const std::string &deviceId) {
            that->OnRenderSystemStart();
        };
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
            return commonEventFunc(&listener_, data);
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
        if (item.first == SYSTEM_UPDATE_FOR_POLICY) {
            continue;
        }
        skill.AddEvent(item.first);
        EDMLOGI("CreateEnterpriseDeviceEventSubscriber AddEvent: %{public}s", item.first.c_str());
    }
    EventFwk::CommonEventSubscribeInfo info(skill);
    return std::make_shared<EnterpriseDeviceEventSubscriber>(info, listener);
}
#endif

void EnterpriseDeviceMgrAbility::OnCommonEventUserAdded(const EventFwk::CommonEventData &data)
{
    int userIdToAdd = data.GetCode();
    if (userIdToAdd < 0) {
        EDMLOGE("EnterpriseDeviceMgrAbility OnCommonEventUserAdded error userid:%{public}d", userIdToAdd);
        return;
    }
    EDMLOGI("EnterpriseDeviceMgrAbility OnCommonEventUserAdded %{public}d", userIdToAdd);
    ConnectAbilityOnSystemAccountEvent(userIdToAdd, ManagedEvent::USER_ADDED);
}

void EnterpriseDeviceMgrAbility::OnCommonEventUserSwitched(const EventFwk::CommonEventData &data)
{
    int userIdToSwitch = data.GetCode();
    if (userIdToSwitch < 0) {
        EDMLOGE("EnterpriseDeviceMgrAbility OnCommonEventUserSwitched error userid:%{public}d", userIdToSwitch);
        return;
    }
    EDMLOGI("EnterpriseDeviceMgrAbility OnCommonEventUserSwitched %{public}d", userIdToSwitch);
    ConnectAbilityOnSystemAccountEvent(userIdToSwitch, ManagedEvent::USER_SWITCHED);
}

void EnterpriseDeviceMgrAbility::OnCommonEventUserRemoved(const EventFwk::CommonEventData &data)
{
    int userIdToRemove = data.GetCode();
    if (userIdToRemove < 0) {
        EDMLOGE("EnterpriseDeviceMgrAbility OnCommonEventUserRemoved error userid:%{public}d", userIdToRemove);
        return;
    }
    EDMLOGI("OnCommonEventUserRemoved");
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    // include super admin, need to be removed
    std::vector<std::shared_ptr<Admin>> userAdmin;
    AdminManager::GetInstance()->GetAdminByUserId(userIdToRemove, userAdmin);
    for (auto &item : userAdmin) {
        if (FAILED(RemoveAdminAndAdminPolicy(item->adminInfo_.packageName_, userIdToRemove))) {
            EDMLOGW("EnterpriseDeviceMgrAbility::OnCommonEventUserRemoved remove admin failed packagename = %{public}s",
                item->adminInfo_.packageName_.c_str());
        }
    }
    std::vector<std::shared_ptr<Admin>> subAndSuperAdmin;
    AdminManager::GetInstance()->GetAdminByUserId(EdmConstants::DEFAULT_USER_ID, subAndSuperAdmin);
    for (const auto &subAdmin : subAndSuperAdmin) {
        if ((subAdmin->GetAdminType() == AdminType::SUB_SUPER_ADMIN || subAdmin->GetAdminType() == AdminType::ENT ||
            subAdmin->GetAdminType() == AdminType::VIRTUAL_ADMIN) &&
            FAILED(RemoveAdminAndAdminPolicy(subAdmin->adminInfo_.packageName_, userIdToRemove))) {
            EDMLOGW("EnterpriseDeviceMgrAbility::OnCommonEventUserRemoved: remove sub and super admin policy failed.");
        }
    }
    ConnectAbilityOnSystemAccountEvent(userIdToRemove, ManagedEvent::USER_REMOVED);
}

void EnterpriseDeviceMgrAbility::OnCommonEventPackageAdded(const EventFwk::CommonEventData &data)
{
    EDMLOGI("OnCommonEventPackageAdded");
    AAFwk::Want want = data.GetWant();
    std::string bundleName = want.GetElement().GetBundleName();
    int32_t userId = want.GetIntParam(AppExecFwk::Constants::USER_ID, AppExecFwk::Constants::INVALID_USERID);
    if (userId == AppExecFwk::Constants::INVALID_USERID) {
        EDMLOGE("OnCommonEventPackageAdded get INVALID_USERID");
        return;
    }
    ConnectAbilityOnSystemEvent(bundleName, ManagedEvent::BUNDLE_ADDED, userId);
}

void EnterpriseDeviceMgrAbility::OnCommonEventPackageRemoved(const EventFwk::CommonEventData &data)
{
    EDMLOGI("OnCommonEventPackageRemoved");
    std::string bundleName = data.GetWant().GetElement().GetBundleName();
    int32_t userId = data.GetWant().GetIntParam(AppExecFwk::Constants::USER_ID, AppExecFwk::Constants::INVALID_USERID);
    if (userId == AppExecFwk::Constants::INVALID_USERID) {
        EDMLOGE("OnCommonEventPackageRemoved get INVALID_USERID");
        return;
    }
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    std::shared_ptr<Admin> admin = AdminManager::GetInstance()->GetAdminByPkgName(bundleName, userId);
    if (admin != nullptr) {
        if (admin->adminInfo_.adminType_ == AdminType::NORMAL) {
            RemoveAdminAndAdminPolicy(bundleName, userId);
        }
        if ((admin->adminInfo_.adminType_ == AdminType::SUB_SUPER_ADMIN ||
            admin->adminInfo_.adminType_ == AdminType::VIRTUAL_ADMIN) && userId == EdmConstants::DEFAULT_USER_ID) {
            // remove sub super admin and sub super admin policy
            RemoveSubSuperAdminAndAdminPolicy(bundleName);
        }
        if (admin->adminInfo_.adminType_ == AdminType::ENT && userId == EdmConstants::DEFAULT_USER_ID) {
            // remove super admin and super admin policy
            RemoveSuperAdminAndAdminPolicy(bundleName);
        }
        if (admin->adminInfo_.adminType_ == AdminType::BYOD && userId == EdmConstants::DEFAULT_USER_ID) {
            RemoveAdminAndAdminPolicy(bundleName, userId);
        }
        if (!AdminManager::GetInstance()->IsAdminExist()) {
            system::SetParameter(PARAM_EDM_ENABLE, "false");
            NotifyAdminEnabled(false);
        }
    }
    ConnectAbilityOnSystemEvent(bundleName, ManagedEvent::BUNDLE_REMOVED, userId);
}

void EnterpriseDeviceMgrAbility::OnCommonEventPackageChanged(const EventFwk::CommonEventData &data)
{
    EDMLOGI("OnCommonEventPackageChanged");
    std::string bundleName = data.GetWant().GetElement().GetBundleName();
    int32_t userId = data.GetWant().GetIntParam(AppExecFwk::Constants::USER_ID, AppExecFwk::Constants::INVALID_USERID);
    std::shared_ptr<Admin> admin = AdminManager::GetInstance()->GetAdminByPkgName(bundleName, userId);
    if (admin != nullptr && admin->GetAdminType() == AdminType::ENT) {
        OnAdminEnabled(admin->adminInfo_.packageName_, admin->adminInfo_.className_,
            IEnterpriseAdmin::COMMAND_ON_ADMIN_ENABLED, userId, false);
    }
}

void EnterpriseDeviceMgrAbility::OnAdminEnabled(const std::string &bundleName, const std::string &abilityName,
    uint32_t code, int32_t userId, bool isAdminEnabled)
{
    AAFwk::Want connectWant;
    connectWant.SetElementName(bundleName, abilityName);
    std::shared_ptr<EnterpriseConnManager> manager = DelayedSingleton<EnterpriseConnManager>::GetInstance();
    sptr<IEnterpriseConnection> connection = manager->CreateAdminConnection(connectWant, code, userId, isAdminEnabled);
    manager->ConnectAbility(connection);
}

void EnterpriseDeviceMgrAbility::ConnectAbilityOnSystemAccountEvent(const int32_t accountId, ManagedEvent event)
{
    std::unordered_map<int32_t, std::vector<std::shared_ptr<Admin>>> subAdmins;
    AdminManager::GetInstance()->GetAdminBySubscribeEvent(event, subAdmins);
    if (subAdmins.empty()) {
        EDMLOGW("SystemEventSubscriber Get subscriber by common event failed.");
        return;
    }
    AAFwk::Want want;
    for (const auto &subAdmin : subAdmins) {
        for (const auto &it : subAdmin.second) {
            want.SetElementName(it->adminInfo_.packageName_, it->adminInfo_.className_);
            std::shared_ptr<EnterpriseConnManager> manager = DelayedSingleton<EnterpriseConnManager>::GetInstance();
            sptr<IEnterpriseConnection> connection =
                manager->CreateAccountConnection(want, static_cast<uint32_t>(event), GetCurrentUserId(), accountId);
            manager->ConnectAbility(connection);
        }
    }
}

void EnterpriseDeviceMgrAbility::ConnectAbilityOnSystemEvent(const std::string &bundleName,
    ManagedEvent event, int32_t userId)
{
    std::unordered_map<int32_t, std::vector<std::shared_ptr<Admin>>> subAdmins;
    AdminManager::GetInstance()->GetAdminBySubscribeEvent(event, subAdmins);
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
                manager->CreateBundleConnection(want, static_cast<uint32_t>(event), subAdmin.first, bundleName, userId);
            manager->ConnectAbility(connection);
        }
    }
}

void EnterpriseDeviceMgrAbility::NotifyAdminEnabled(bool isEnabled)
{
    EDMLOGI("EnterpriseDeviceMgrAbility notify admin enabled: %{public}d.", isEnabled);
    AAFwk::Want want;
    if (isEnabled) {
        want.SetAction(EDM_ADMIN_ENABLED_EVENT);
    } else {
        want.SetAction(EDM_ADMIN_DISABLED_EVENT);
    }
    EventFwk::CommonEventData eventData;
    eventData.SetWant(want);
    if (!EventFwk::CommonEventManager::PublishCommonEvent(eventData)) {
        EDMLOGE("EnterpriseDeviceMgrAbility notify admin enabled failed.");
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

    if (AdminManager::GetInstance()) {
        AdminManager::GetInstance().reset();
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
    InitAllAdmins();
    InitAllPolices();
    RemoveAllDebugAdmin();
    if (!registerToService_) {
        if (!Publish(this)) {
            EDMLOGE("EnterpriseDeviceMgrAbility: res == false");
            return;
        }
        registerToService_ = true;
    }
    AddOnAddSystemAbilityFuncMap();
    AddSystemAbilityListeners();
}

void EnterpriseDeviceMgrAbility::InitAllAdmins()
{
    AdminManager::GetInstance()->Init();
    EDMLOGD("create AdminManager::GetInstance() success");
}

void EnterpriseDeviceMgrAbility::InitAllPlugins()
{
    if (!pluginMgr_) {
        pluginMgr_ = PluginManager::GetInstance();
    }
    EDMLOGD("create pluginMgr_ success");
    lastCallTime_ = std::chrono::system_clock::now();
    if (pluginHasInit_) {
        std::unique_lock<std::mutex> lock(waitMutex_);
        notifySignal_ = true;
        waitSignal_.notify_one();
    } else {
        pluginMgr_->LoadPlugin();
        pluginHasInit_ = true;
        std::thread timerThread([this]() {
            this->UnloadPluginTask();
        });
        timerThread.detach();
    }
}

void EnterpriseDeviceMgrAbility::UnloadPluginTask()
{
    while (pluginHasInit_) {
        {
            std::unique_lock<std::mutex> lock(waitMutex_);
            notifySignal_ = false;
            waitSignal_.wait_for(lock, std::chrono::milliseconds(TIMER_TIMEOUT), [this] {
                return this->notifySignal_;
            });
        }
        auto now = std::chrono::system_clock::now();
        auto diffTime = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastCallTime_).count();
        if (diffTime >= std::chrono::milliseconds(TIMER_TIMEOUT).count()) {
            std::lock_guard<std::mutex> autoLock(mutexLock_);
            if (pluginMgr_) {
                pluginMgr_->UnloadPlugin();
            }
            pluginHasInit_ = false;
        }
    }
}

void EnterpriseDeviceMgrAbility::InitAllPolices()
{
    if (!policyMgr_) {
        policyMgr_ = std::make_shared<PolicyManager>();
        IPolicyManager::policyManagerInstance_ = policyMgr_.get();
    }
    std::vector<int32_t> userIds;
    auto devicePolicies = DevicePoliciesStorageRdb::GetInstance();
    if (devicePolicies == nullptr) {
        EDMLOGW("OnAddSystemAbility::InitAllPolices:get rdbStore failed.");
        return;
    }
    EDMLOGI("InitAllPolices userIds size %{public}zu", userIds.size());
    devicePolicies->QueryAllUserId(userIds);
    policyMgr_->Init(userIds);
    allowDelegatedPolicies_ = { "disallow_add_local_account", "disallow_add_os_account_by_user",
        "disallow_running_bundles", "manage_auto_start_apps", "allowed_bluetooth_devices", "set_browser_policies",
        "allowed_install_bundles", "disallowed_install_bundles", "disallowed_uninstall_bundles", "snapshot_skip",
        "location_policy", "disabled_network_interface", "global_proxy", "disabled_bluetooth",
        "disallow_modify_datetime", "disabled_printer", "policy_screen_shot", "disabled_hdc", "disable_microphone",
        "fingerprint_auth", "disable_usb", "disable_wifi", "disallowed_tethering", "inactive_user_freeze",
        "password_policy", "clipboard_policy", "ntp_server", "set_update_policy", "notify_upgrade_packages",
        "allowed_usb_devices", "usb_read_only", "disallowed_usb_devices", "get_device_info", "watermark_image_policy",
        "policy_screen_record" };
}

void EnterpriseDeviceMgrAbility::RemoveAllDebugAdmin()
{
    bool isDebug = system::GetBoolParameter(DEVELOP_MODE_STATE, false);
    if (!isDebug) {
        std::vector<std::shared_ptr<Admin>> userAdmin;
        AdminManager::GetInstance()->GetAdminByUserId(EdmConstants::DEFAULT_USER_ID, userAdmin);
        for (const auto &item: userAdmin) {
            if (item->adminInfo_.isDebug_) {
                EDMLOGD("remove debug admin %{public}s", item->adminInfo_.packageName_.c_str());
                RemoveSuperAdminAndAdminPolicy(item->adminInfo_.packageName_);
            }
        }
    }
}

void EnterpriseDeviceMgrAbility::AddSystemAbilityListeners()
{
    AddSystemAbilityListener(COMMON_EVENT_SERVICE_ID);
    AddSystemAbilityListener(APP_MGR_SERVICE_ID);
    AddSystemAbilityListener(ABILITY_MGR_SERVICE_ID);
    AddSystemAbilityListener(SUBSYS_USERIAM_SYS_ABILITY_USERAUTH);
    AddSystemAbilityListener(WINDOW_MANAGER_SERVICE_ID);
#ifdef PASTEBOARD_EDM_ENABLE
    AddSystemAbilityListener(PASTEBOARD_SERVICE_ID);
#endif
#ifdef NET_MANAGER_BASE_EDM_ENABLE
    AddSystemAbilityListener(COMM_NET_POLICY_MANAGER_SYS_ABILITY_ID);
#endif
#ifdef USB_EDM_ENABLE
    AddSystemAbilityListener(USB_SYSTEM_ABILITY_ID);
#endif
    AddSystemAbilityListener(RENDER_SERVICE);
}

void EnterpriseDeviceMgrAbility::OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    EDMLOGD("OnAddSystemAbility systemAbilityId:%{public}d added!", systemAbilityId);
    auto func = addSystemAbilityFuncMap_.find(systemAbilityId);
    if (func != addSystemAbilityFuncMap_.end()) {
        auto memberFunc = func->second;
        if (memberFunc != nullptr) {
            return memberFunc(this, systemAbilityId, deviceId);
        }
    }
}

void EnterpriseDeviceMgrAbility::OnAppManagerServiceStart()
{
    EDMLOGI("OnAppManagerServiceStart");
    std::unordered_map<int32_t, std::vector<std::shared_ptr<Admin>>> subAdmins;
    AdminManager::GetInstance()->GetAdminBySubscribeEvent(ManagedEvent::APP_START, subAdmins);
    AdminManager::GetInstance()->GetAdminBySubscribeEvent(ManagedEvent::APP_STOP, subAdmins);
    if (!subAdmins.empty()) {
        EDMLOGI("the admin that listened the APP_START or APP_STOP event is existed");
        SubscribeAppState();
    }
}

void EnterpriseDeviceMgrAbility::OnAbilityManagerServiceStart()
{
    EDMLOGI("OnAbilityManagerServiceStart");
    auto superAdmin = AdminManager::GetInstance()->GetSuperAdmin();
    if (superAdmin != nullptr) {
        OnAdminEnabled(superAdmin->adminInfo_.packageName_, superAdmin->adminInfo_.className_,
            IEnterpriseAdmin::COMMAND_ON_ADMIN_ENABLED, DEFAULT_USER_ID, false);
    }
}

void EnterpriseDeviceMgrAbility::OnCommonEventServiceStart()
{
#ifdef COMMON_EVENT_SERVICE_EDM_ENABLE
    commonEventSubscriber = CreateEnterpriseDeviceEventSubscriber(*this);
    EventFwk::CommonEventManager::SubscribeCommonEvent(this->commonEventSubscriber);
    EDMLOGI("create commonEventSubscriber success");

    EventFwk::MatchingSkills skill = EventFwk::MatchingSkills();
    skill.AddEvent(SYSTEM_UPDATE_FOR_POLICY);
    EDMLOGI("CreateEnterpriseDeviceEventSubscriber AddEvent: %{public}s", SYSTEM_UPDATE_FOR_POLICY.c_str());
    EventFwk::CommonEventSubscribeInfo info(skill);
    info.SetPermission(PERMISSION_UPDATE_SYSTEM);
    EventFwk::CommonEventManager::SubscribeCommonEvent(std::make_shared<EnterpriseDeviceEventSubscriber>(info, *this));
#else
    EDMLOGW("EnterpriseDeviceMgrAbility::OnCommonEventServiceStart Unsupported Capabilities.");
    return;
#endif
}

#ifdef PASTEBOARD_EDM_ENABLE
void EnterpriseDeviceMgrAbility::OnPasteboardServiceStart()
{
    EDMLOGI("OnPasteboardServiceStart");
    std::string policyData;
    policyMgr_->GetPolicy("", "clipboard_policy", policyData, EdmConstants::DEFAULT_USER_ID);
    auto clipboardSerializer_ = ClipboardSerializer::GetInstance();
    std::map<int32_t, ClipboardPolicy> policyMap;
    clipboardSerializer_->Deserialize(policyData, policyMap);
    ClipboardUtils::HandlePasteboardPolicy(policyMap);
}
#endif

#ifdef NET_MANAGER_BASE_EDM_ENABLE
void EnterpriseDeviceMgrAbility::OnNetManagerBaseServiceStart()
{
    EDMLOGI("EnterpriseDeviceMgrAbility::OnNetManagerBaseServiceStart");
    std::string policyData;
    policyMgr_->GetPolicy("", "disabled_network_interface", policyData, EdmConstants::DEFAULT_USER_ID);
    std::map<std::string, std::string> policyMap;
    MapStringSerializer::GetInstance()->Deserialize(policyData, policyMap);
    HandleDisallowedNetworkInterface(policyMap);
}

void EnterpriseDeviceMgrAbility::HandleDisallowedNetworkInterface(const std::map<std::string, std::string> policyMap)
{
    std::vector<std::string> netList;
    for (const auto& iter : policyMap) {
        netList.emplace_back(iter.first);
        EDMLOGD("HandleDisallowedNetworkInterface %{public}s", iter.first.c_str());
    }
    auto netPolicyClient = DelayedSingleton<NetManagerStandard::NetPolicyClient>::GetInstance();
    if (netPolicyClient != nullptr) {
        if (FAILED(netPolicyClient->SetNicTrafficAllowed(netList, false))) {
            EDMLOGE("EnterpriseDeviceMgrAbility::HandleDisallowedNetworkInterface SetNicTrafficAllowed failed.");
        } else {
            EDMLOGE("EnterpriseDeviceMgrAbility::HandleDisallowedNetworkInterface get NetPolicyClient failed.");
        }
    }
}
#endif

#ifdef USERIAM_EDM_ENABLE
void EnterpriseDeviceMgrAbility::OnUserAuthFrameworkStart()
{
    EDMLOGI("OnUserAuthFrameworkStart");
    SetPasswordPolicy();
    SetFingerprintPolicy();
}

void EnterpriseDeviceMgrAbility::SetPasswordPolicy()
{
    std::string policyData;
    policyMgr_->GetPolicy("", "password_policy", policyData, EdmConstants::DEFAULT_USER_ID);
    auto serializer_ = PasswordSerializer::GetInstance();
    PasswordPolicy policy;
    serializer_->Deserialize(policyData, policy);
    UserIam::UserAuth::GlobalConfigParam param;
    param.type = UserIam::UserAuth::GlobalConfigType::PIN_EXPIRED_PERIOD;
    param.authTypes.push_back(UserIam::UserAuth::AuthType::PIN);
    param.value.pinExpiredPeriod = policy.validityPeriod;
    int32_t ret = UserIam::UserAuth::UserAuthClient::GetInstance().SetGlobalConfigParam(param);
    if (ret != 0) {
        EDMLOGW("SetGlobalConfigParam SetPasswordPolicy Error");
    }
}

void EnterpriseDeviceMgrAbility::SetFingerprintPolicy()
{
    std::string policyData;
    policyMgr_->GetPolicy("", "fingerprint_auth", policyData, EdmConstants::DEFAULT_USER_ID);
    auto serializer_ = FingerprintPolicySerializer::GetInstance();
    FingerprintPolicy policy;
    serializer_->Deserialize(policyData, policy);
    std::vector<int32_t> userIds(policy.accountIds.size());
    std::copy(policy.accountIds.begin(), policy.accountIds.end(), userIds.begin());
    UserIam::UserAuth::GlobalConfigParam param;
    param.userIds = userIds;
    param.authTypes.push_back(UserIam::UserAuth::AuthType::FINGERPRINT);
    param.type = UserIam::UserAuth::GlobalConfigType::ENABLE_STATUS;
    param.value.enableStatus = !policy.globalDisallow && userIds.size() == 0;
    int32_t ret = UserIam::UserAuth::UserAuthClient::GetInstance().SetGlobalConfigParam(param);
    if (ret != ERR_OK) {
        EDMLOGW("SetGlobalConfigParam SetFingerprintPolicy Error");
    }
}
#endif

#ifdef USB_EDM_ENABLE
void EnterpriseDeviceMgrAbility::OnUsbServiceStart()
{
    EDMLOGI("OnUsbServiceStart");
    std::string disableUsbPolicy;
    policyMgr_->GetPolicy("", "disable_usb", disableUsbPolicy, EdmConstants::DEFAULT_USER_ID);
    bool isUsbDisabled = false;
    BoolSerializer::GetInstance()->Deserialize(policyData, isUsbDisabled);
    if (isUsbDisabled) {
        ErrCode disableUsbRet = UsbPolicyUtils::SetUsbDisabled(isUsbDisabled);
        if (disableUsbRet != ERR_OK) {
            EDMLOGW("SetUsbDisabled Error: %{public}d", disableUsbRet);
        }
        return;
    }

    std::string allowUsbDevicePolicy;
    policyMgr_->GetPolicy("", "allowed_usb_devices", allowUsbDevicePolicy, EdmConstants::DEFAULT_USER_ID);
    std::vector<UsbDeviceId> usbDeviceIds;
    ArrayUsbDeviceIdSerializer::GetInstance()->Deserialize(policyData, usbDeviceIds);
    if (!usbDeviceIds.empty()) {
        ErrCode allowedUsbRet = UsbPolicyUtils::AddAllowedUsbDevices(usbDeviceIds);
        if (allowedUsbRet != ERR_OK) {
            EDMLOGW("AddAllowedUsbDevices Error: %{public}d", disableUsbRet);
        }
        return;
    }

    std::string usbStoragePolicy;
    policyMgr_->GetPolicy("", "usb_read_only", usbStoragePolicy, EdmConstants::DEFAULT_USER_ID);

    std::string disallowUsbDevicePolicy;
    policyMgr_->GetPolicy("", "disallowed_usb_devices", disallowUsbDevicePolicy, EdmConstants::DEFAULT_USER_ID);
    std::vector<USB::UsbDeviceType> disallowedDevices;
    ArrayUsbDeviceTypeSerializer::GetInstance()->Deserialize(policyData, disallowedDevices);
    if (usbStoragePolicy == std::to_string(EdmConstants::STORAGE_USB_POLICY_DISABLED)) {
        USB::UsbDeviceType storageType;
        storageType.baseClass = USB_DEVICE_TYPE_BASE_CLASS_STORAGE;
        storageType.subClass = USB_DEVICE_TYPE_BASE_CLASS_STORAGE;
        storageType.protocol = USB_DEVICE_TYPE_BASE_CLASS_STORAGE;
        storageType.isDeviceType = false;
        disallowedDevices.emplace_back(storageType);
    }
    if (!disallowedDevices.empty()) {
        ErrCode disallowedUsbRet = UsbPolicyUtils::SetDisallowedUsbDevices(disallowedDevices);
        if (disallowedUsbRet != ERR_OK) {
            EDMLOGW("SetDisallowedUsbDevices Error: %{public}d", disableUsbRet);
        }
    }
}
#endif

void EnterpriseDeviceMgrAbility::OnRenderSystemStart()
{
    EDMLOGI("OnRenderSystemStart");
    InitAllPlugins();
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::WATERMARK_IMAGE);
    auto plugin = pluginMgr_->GetPluginByFuncCode(funcCode);
    if (plugin == nullptr) {
        EDMLOGE("get watermarkPlugin fail");
        return;
    }
    MessageParcel data;
    data.WriteString(EdmConstants::SecurityManager::SET_ALL_WATERMARK_TYPE);
    MessageParcel reply;
    HandlePolicyData policyData;
    plugin->OnHandlePolicy(funcCode, data, reply, policyData, EdmConstants::DEFAULT_USER_ID);
}

void EnterpriseDeviceMgrAbility::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId) {}

void EnterpriseDeviceMgrAbility::OnWindowManagerServiceStart()
{
    auto serializer = ArrayStringSerializer::GetInstance();
    std::vector<int32_t> userIds = { EdmConstants::DEFAULT_USER_ID };
    policyMgr_->GetPolicyUserIds(userIds);
    EDMLOGD("OnWindowManagerServiceStart userIds size %{public}zu", userIds.size());
    std::unordered_map<int32_t, std::vector<std::string>> policyMap;
    for (int32_t userId : userIds) {
        std::string policyData;
        policyMgr_->GetPolicy("", "snapshot_skip", policyData, userId);
        std::vector<std::string> vecData;
        serializer->Deserialize(policyData, vecData);
        if (vecData.empty()) {
            continue;
        }
        policyMap.insert(make_pair(userId, vecData));
    }
    if (!policyMap.empty()) {
        auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(WINDOW_MANAGER_SERVICE_ID);
        if (remoteObject == nullptr) {
            EDMLOGE("OnWindowManagerServiceStart wms obj get fial");
            return;
        }
        auto mockSessionManagerServiceProxy = iface_cast<OHOS::Rosen::IMockSessionManagerInterface>(remoteObject);
        if (mockSessionManagerServiceProxy == nullptr) {
            EDMLOGE("OnWindowManagerServiceStart wms obj cast fial");
            return;
        }
        EDMLOGI("OnWindowManagerServiceStart init snap shot skip policy when wms restart");
        mockSessionManagerServiceProxy->SetSnapshotSkipByIdNamesMap(policyMap);
    } else {
        EDMLOGI("OnWindowManagerServiceStart no policy to update");
    }
}

void EnterpriseDeviceMgrAbility::OnStop()
{
    EDMLOGD("EnterpriseDeviceMgrAbility::OnStop()");
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    if (pluginHasInit_) {
        pluginHasInit_ = false;
        std::unique_lock<std::mutex> lock(waitMutex_);
        notifySignal_ = true;
        waitSignal_.notify_one();
    }
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

std::shared_ptr<PermissionChecker> EnterpriseDeviceMgrAbility::GetPermissionChecker()
{
    return PermissionChecker::GetInstance();
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
    AdminManager::GetInstance()->GetAdminBySubscribeEvent(ManagedEvent::APP_START, subAdmins);
    AdminManager::GetInstance()->GetAdminBySubscribeEvent(ManagedEvent::APP_STOP, subAdmins);
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
    if ((type == AdminType::ENT || type == AdminType::BYOD) && userId != DEFAULT_USER_ID) {
        EDMLOGW("EnableAdmin: Super or byod admin can only be enabled in default user.");
        return ERR_EDM_ADD_ADMIN_FAILED;
    }

    if (type != AdminType::ENT && system::GetBoolParameter(PARAM_SECURITY_MODE, false)) {
        EDMLOGW("EnableAdmin: The current mode is not supported.");
        return ERR_EDM_ADD_ADMIN_FAILED;
    }

    if (isDebug && AdminManager::GetInstance()->IsSuperAdminExist()) {
        EDMLOGW("EnableAdmin: An official super admin exsit, cannot enable another debug admin");
        return ERR_EDM_ADD_ADMIN_FAILED;
    }

    if (VerifyEnableAdminConditionCheckExistAdmin(admin, type, userId, isDebug) != ERR_OK) {
        return ERR_EDM_ADD_ADMIN_FAILED;
    }
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::VerifyEnableAdminConditionCheckExistAdmin(AppExecFwk::ElementName &admin,
    AdminType type, int32_t userId, bool isDebug)
{
    std::shared_ptr<Admin> existAdmin = AdminManager::GetInstance()->GetAdminByPkgName(admin.GetBundleName(), userId);
    if (existAdmin != nullptr) {
        if (type == AdminType::BYOD && existAdmin->GetAdminType() != AdminType::BYOD) {
            EDMLOGW("EnableAdmin: a byod admin can't be enabled when alreadly enabled other admin.");
            return ERR_EDM_ADD_ADMIN_FAILED;
        }
        if (existAdmin->GetAdminType() == AdminType::SUB_SUPER_ADMIN ||
            existAdmin->GetAdminType() == AdminType::VIRTUAL_ADMIN) {
            EDMLOGW("EnableAdmin: sub-super admin can not be enabled as a normal or super admin.");
            return ERR_EDM_ADD_ADMIN_FAILED;
        }
        if (existAdmin->GetAdminType() == AdminType::ENT &&
            (type != AdminType::ENT || userId != EdmConstants::DEFAULT_USER_ID)) {
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
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::CheckReplaceAdmins(AppExecFwk::ElementName &oldAdmin,
    AppExecFwk::ElementName &newAdmin, std::vector<AppExecFwk::ExtensionAbilityInfo> &abilityInfo,
    std::vector<std::string> &permissionList)
{
    Security::AccessToken::AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    if (!GetPermissionChecker()->VerifyCallingPermission(tokenId, PERMISSION_MANAGE_ENTERPRISE_DEVICE_ADMIN)) {
        EDMLOGW("EnterpriseDeviceMgrAbility::ReplaceSuperAdmin check permission failed");
        return EdmReturnErrCode::PERMISSION_DENIED;
    }

    auto edmAdmin = AdminManager::GetInstance()->GetSuperAdmin();
    if (edmAdmin == nullptr || edmAdmin->adminInfo_.packageName_ != oldAdmin.GetBundleName() ||
        edmAdmin->adminInfo_.className_ != oldAdmin.GetAbilityName()) {
        EDMLOGE("CheckReplaceAdmins param oldAdmin is not super admin");
        return EdmReturnErrCode::ADMIN_INACTIVE;
    }

    AAFwk::Want want;
    want.SetElement(newAdmin);
    if (!GetBundleMgr()->QueryExtensionAbilityInfos(want, AppExecFwk::ExtensionAbilityType::ENTERPRISE_ADMIN,
        AppExecFwk::ExtensionAbilityInfoFlag::GET_EXTENSION_INFO_WITH_PERMISSION, DEFAULT_USER_ID, abilityInfo) ||
        abilityInfo.empty()) {
        EDMLOGW("ReplaceSuperAdmin: QueryExtensionAbilityInfos_newAdmin failed");
        return EdmReturnErrCode::COMPONENT_INVALID;
    }

    if (FAILED(VerifyEnableAdminCondition(newAdmin, AdminType::ENT, DEFAULT_USER_ID, false))) {
        EDMLOGW("ReplaceSuperAdmin: VerifyEnableAdminCondition failed.");
        return EdmReturnErrCode::REPLACE_ADMIN_FAILED;
    }
    if (FAILED(GetPermissionChecker()->GetAllPermissionsByAdmin(newAdmin.GetBundleName(), AdminType::ENT,
        DEFAULT_USER_ID, permissionList))) {
        EDMLOGW("ReplaceSuperAdmin: GetAllPermissionsByAdmin failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::HandleKeepPolicy(std::string &adminName, std::string &newAdminName,
    const Admin &edmAdmin, std::shared_ptr<Admin> adminPtr)
{
    if (FAILED(AdminManager::GetInstance()->ReplaceSuperAdminByPackageName(adminName, edmAdmin))) {
        EDMLOGE("ReplaceSuperAdmin update Admin Policies Failed");
        return EdmReturnErrCode::REPLACE_ADMIN_FAILED;
    }
    std::string adminPolicyValue;
    policyMgr_->GetPolicy(adminName, DISALLOWED_UNINSTALL_POLICY, adminPolicyValue);
    std::string combinedPolicyValue;
    policyMgr_->GetPolicy("", DISALLOWED_UNINSTALL_POLICY, combinedPolicyValue);

    if (FAILED(policyMgr_->ReplaceAllPolicy(DEFAULT_USER_ID, adminName, newAdminName))) {
        EDMLOGE("ReplaceSuperAdmin update device Policies Failed");
        AdminManager::GetInstance()->ReplaceSuperAdminByPackageName(newAdminName, *adminPtr);
        return EdmReturnErrCode::REPLACE_ADMIN_FAILED;
    }
    if (!adminPolicyValue.empty() && adminPolicyValue.find(adminName) != std::string::npos) {
        AppExecFwk::BundleInfo bundleInfo;
        GetBundleMgr()->GetBundleInfo(adminName, AppExecFwk::BundleFlag::GET_BUNDLE_WITH_ABILITIES,
            bundleInfo, DEFAULT_USER_ID);
        std::vector<std::string> data = {bundleInfo.appId};
        if (FAILED(GetBundleMgr()->DeleteAppInstallControlRule(
            AppExecFwk::AppInstallControlRuleType::DISALLOWED_UNINSTALL, data, DEFAULT_USER_ID))) {
            EDMLOGE("ReplaceSuperAdmin DeleteAppInstallControlRule failed");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        AppExecFwk::BundleInfo newBundleInfo;
        GetBundleMgr()->GetBundleInfo(newAdminName, AppExecFwk::BundleFlag::GET_BUNDLE_WITH_ABILITIES,
            newBundleInfo, DEFAULT_USER_ID);
        data = {newBundleInfo.appId};
        if (FAILED(GetBundleMgr()->AddAppInstallControlRule(data,
            AppExecFwk::AppInstallControlRuleType::DISALLOWED_UNINSTALL, DEFAULT_USER_ID))) {
            EDMLOGE("ReplaceSuperAdmin AddAppInstallControlRule failed");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        adminPolicyValue.replace(adminPolicyValue.find(adminName), adminName.length(), newAdminName);
        combinedPolicyValue.replace(combinedPolicyValue.find(adminName), adminName.length(), newAdminName);
        EDMLOGD("ReplaceSuperAdmin uninstall new admin policy value: %{public}s", adminPolicyValue.c_str());
        EDMLOGD("ReplaceSuperAdmin uninstall new combined policy value: %{public}s", combinedPolicyValue.c_str());
        if (FAILED(policyMgr_->SetPolicy(newAdminName, DISALLOWED_UNINSTALL_POLICY, adminPolicyValue,
            combinedPolicyValue))) {
            EDMLOGE("ReplaceSuperAdmin update uninstall policy failed");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::ReplaceSuperAdmin(AppExecFwk::ElementName &oldAdmin,
    AppExecFwk::ElementName &newAdmin, bool keepPolicy)
{
    std::vector<AppExecFwk::ExtensionAbilityInfo> abilityInfo;
    std::vector<std::string> permissionList;
    ErrCode ret = CheckReplaceAdmins(oldAdmin, newAdmin, abilityInfo, permissionList);
    if (FAILED(ret)) {
        EDMLOGE("ReplaceSuperAdmin: CheckReplaceAdmins failed");
        return ret;
    }
    std::string adminName = oldAdmin.GetBundleName();
    std::shared_ptr<Admin> adminPtr = AdminManager::GetInstance()->GetAdminByPkgName(adminName, DEFAULT_USER_ID);
    if (adminPtr == nullptr) {
        EDMLOGE("ReplaceSuperAdmin adminName is not admin");
        return EdmReturnErrCode::ADMIN_INACTIVE;
    }
    EntInfo entInfo = adminPtr->adminInfo_.entInfo_;
    Admin edmAdmin(abilityInfo.at(0), AdminType::ENT, entInfo, permissionList, false);
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    if (keepPolicy) {
        std::string newAdminName = newAdmin.GetBundleName();
        return HandleKeepPolicy(adminName, newAdminName, edmAdmin, adminPtr);
    } else {
        ErrCode res = DoDisableAdmin(adminName, DEFAULT_USER_ID, AdminType::ENT);
        if (res != ERR_OK) {
            EDMLOGE("ReplaceSuperAdmin: delete admin failed");
            return EdmReturnErrCode::REPLACE_ADMIN_FAILED;
        }
    }
    if (FAILED(AdminManager::GetInstance()->SetAdminValue(DEFAULT_USER_ID, edmAdmin))) {
        EDMLOGE("EnableAdmin: SetAdminValue failed.");
        return EdmReturnErrCode::ENABLE_ADMIN_FAILED;
    }
    system::SetParameter(PARAM_EDM_ENABLE, "true");
    NotifyAdminEnabled(true);
    OnAdminEnabled(newAdmin.GetBundleName(), newAdmin.GetAbilityName(), IEnterpriseAdmin::COMMAND_ON_ADMIN_ENABLED,
        DEFAULT_USER_ID, true);

    EDMLOGI("EnableAdmin: SetAdminEnabled success %{public}s", newAdmin.GetBundleName().c_str());
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::EnableAdmin(AppExecFwk::ElementName &admin, EntInfo &entInfo, AdminType type,
    int32_t userId)
{
    EDMLOGD("EnterpriseDeviceMgrAbility::EnableAdmin user id = %{public}d", userId);
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    bool isDebug = GetPermissionChecker()->CheckIsDebug();
    Security::AccessToken::AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    if (!isDebug && !GetPermissionChecker()->VerifyCallingPermission(tokenId,
        PERMISSION_MANAGE_ENTERPRISE_DEVICE_ADMIN)) {
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
        return EdmReturnErrCode::ENABLE_ADMIN_FAILED;
    }
    std::shared_ptr<Admin> existAdmin = AdminManager::GetInstance()->GetAdminByPkgName(admin.GetBundleName(), userId);
    if (!isDebug && type == AdminType::ENT && AdminManager::GetInstance()->IsSuperAdminExist()) {
        if ((existAdmin == nullptr) || existAdmin->adminInfo_.adminType_ != AdminType::ENT) {
            EDMLOGW("EnableAdmin: There is another super admin enabled.");
            return EdmReturnErrCode::ENABLE_ADMIN_FAILED;
        }
    }

    /* Get all request and registered permissions */
    std::vector<std::string> permissionList;
    if (FAILED(GetPermissionChecker()->GetAllPermissionsByAdmin(admin.GetBundleName(), type, userId,
        permissionList))) {
        EDMLOGW("EnableAdmin: GetAllPermissionsByAdmin failed");
        return EdmReturnErrCode::COMPONENT_INVALID;
    }
    Admin edmAdmin(abilityInfo.at(0), type, entInfo, permissionList, isDebug);
    if (FAILED(AdminManager::GetInstance()->SetAdminValue(userId, edmAdmin))) {
        EDMLOGE("EnableAdmin: SetAdminValue failed.");
        return EdmReturnErrCode::ENABLE_ADMIN_FAILED;
    }
    system::SetParameter(PARAM_EDM_ENABLE, "true");
    NotifyAdminEnabled(true);
    EDMLOGI("EnableAdmin suc.:%{public}s type:%{public}d", admin.GetBundleName().c_str(), static_cast<uint32_t>(type));
    OnAdminEnabled(admin.GetBundleName(), admin.GetAbilityName(), IEnterpriseAdmin::COMMAND_ON_ADMIN_ENABLED, userId,
        true);
    if (type == AdminType::BYOD) {
        EdmDataAbilityUtils::UpdateSettingsData(KEY_EDM_DISPLAY, "true");
    }
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::RemoveAdminItem(const std::string &adminName, const std::string &policyName,
    const std::string &policyValue, int32_t userId)
{
    InitAllPlugins();
    std::shared_ptr<IPlugin> plugin = pluginMgr_->GetPluginByPolicyName(policyName);
    if (plugin == nullptr) {
        EDMLOGW("RemoveAdminItem: Get plugin by policy failed: %{public}s\n", policyName.c_str());
        return ERR_EDM_GET_PLUGIN_MGR_FAILED;
    }
    ErrCode ret = plugin->OnAdminRemove(adminName, policyValue, userId);
    if (ret != ERR_OK) {
        EDMLOGW("RemoveAdminItem: OnAdminRemove failed, admin:%{public}s, value:%{public}s, res:%{public}d\n",
            adminName.c_str(), policyValue.c_str(), ret);
    }
    if (plugin->NeedSavePolicy()) {
        std::string mergedPolicyData;
        ret = plugin->MergePolicyData(adminName, mergedPolicyData);
        if (ret != ERR_OK) {
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
    auto ret = AdminManager::GetInstance()->DeleteAdmin(adminName, userId);
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
    AdminManager::GetInstance()->GetSubSuperAdminsByParentName(bundleName, subAdmins);
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
    return RemoveAdminAndAdminPolicy(bundleName, EdmConstants::DEFAULT_USER_ID);
}

bool EnterpriseDeviceMgrAbility::ShouldUnsubscribeAppState(const std::string &adminName, int32_t userId)
{
    std::shared_ptr<Admin> adminPtr = AdminManager::GetInstance()->GetAdminByPkgName(adminName, userId);
    if (adminPtr == nullptr) {
        EDMLOGE("ShouldUnsubscribeAppState adminPtr null");
        return false;
    }
    return std::any_of(adminPtr->adminInfo_.managedEvents_.begin(), adminPtr->adminInfo_.managedEvents_.end(),
        [](ManagedEvent event) { return event == ManagedEvent::APP_START || event == ManagedEvent::APP_STOP; });
}

ErrCode EnterpriseDeviceMgrAbility::DisableAdmin(AppExecFwk::ElementName &admin, int32_t userId)
{
    EDMLOGI("EnterpriseDeviceMgrAbility::DisableAdmin user id = %{public}d", userId);
    std::shared_ptr<Admin> deviceAdmin = AdminManager::GetInstance()->GetAdminByPkgName(admin.GetBundleName(), userId);
    if (deviceAdmin == nullptr) {
        EDMLOGE("DisableAdmin: %{public}s is not activated", admin.GetBundleName().c_str());
        return EdmReturnErrCode::DISABLE_ADMIN_FAILED;
    }
    AdminType adminType = deviceAdmin->GetAdminType();
    if (adminType == AdminType::ENT || adminType == AdminType::BYOD) {
        userId = DEFAULT_USER_ID;
    }
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    return DoDisableAdmin(admin.GetBundleName(), userId, adminType);
}

ErrCode EnterpriseDeviceMgrAbility::DisableSuperAdmin(const std::string &bundleName)
{
    EDMLOGI("EnterpriseDeviceMgrAbility::DisableSuperAdmin bundle name = %{public}s", bundleName.c_str());
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    return DoDisableAdmin(bundleName, DEFAULT_USER_ID, AdminType::ENT);
}

// non-thread-safe function
ErrCode EnterpriseDeviceMgrAbility::DoDisableAdmin(const std::string &bundleName, int32_t userId, AdminType adminType)
{
    bool isDebug = GetPermissionChecker()->CheckIsDebug();
    Security::AccessToken::AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    if (!isDebug && !GetPermissionChecker()->VerifyCallingPermission(tokenId,
        PERMISSION_MANAGE_ENTERPRISE_DEVICE_ADMIN)) {
        EDMLOGW("DoDisableAdmin::DisableSuperAdmin check permission failed.");
        return EdmReturnErrCode::PERMISSION_DENIED;
    }
    std::shared_ptr<Admin> admin = AdminManager::GetInstance()->GetAdminByPkgName(bundleName, userId);
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
    } else if ((adminType == AdminType::NORMAL || adminType == AdminType::BYOD) &&
        FAILED(RemoveAdminAndAdminPolicy(bundleName, userId))) {
        EDMLOGW("DoDisableAdmin: disable normal or byod admin failed.");
        return EdmReturnErrCode::DISABLE_ADMIN_FAILED;
    }
    if (!AdminManager::GetInstance()->IsAdminExist()) {
        system::SetParameter(PARAM_EDM_ENABLE, "false");
        NotifyAdminEnabled(false);
    }
    OnAdminEnabled(admin->adminInfo_.packageName_, admin->adminInfo_.className_,
        IEnterpriseAdmin::COMMAND_ON_ADMIN_DISABLED, userId, true);
    if (adminType == AdminType::BYOD) {
        EdmDataAbilityUtils::UpdateSettingsData(KEY_EDM_DISPLAY, "false");
    }
    return ERR_OK;
}

bool EnterpriseDeviceMgrAbility::IsSuperAdmin(const std::string &bundleName)
{
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    return AdminManager::GetInstance()->IsSuperAdmin(bundleName);
}

bool EnterpriseDeviceMgrAbility::IsAdminEnabled(AppExecFwk::ElementName &admin, int32_t userId)
{
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    std::shared_ptr<Admin> existAdmin = AdminManager::GetInstance()->GetAdminByPkgName(admin.GetBundleName(), userId);
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

ErrCode EnterpriseDeviceMgrAbility::UpdateDevicePolicy(uint32_t code, const std::string &bundleName,
    MessageParcel &data, MessageParcel &reply, int32_t userId)
{
    std::shared_ptr<IPlugin> plugin = pluginMgr_->GetPluginByFuncCode(code);
    if (plugin == nullptr) {
        EDMLOGW("UpdateDevicePolicy: get plugin failed, code:%{public}d", code);
        return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
    }

    std::string policyName = plugin->GetPolicyName();
    HandlePolicyData handlePolicyData{"", false};
    policyMgr_->GetPolicy(bundleName, policyName, handlePolicyData.policyData, userId);
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
        ret = plugin->MergePolicyData(bundleName, mergedPolicy);
        if (FAILED(ret)) {
            EDMLOGW("UpdateDevicePolicy: MergePolicyData failed error:%{public}d", ret);
            return ret;
        }
        policyMgr_->SetPolicy(bundleName, policyName, handlePolicyData.policyData, mergedPolicy, userId);
        isGlobalChanged = (oldCombinePolicy != mergedPolicy);
    }
    plugin->OnHandlePolicyDone(code, bundleName, isGlobalChanged, userId);
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::HandleDevicePolicy(uint32_t code, AppExecFwk::ElementName &admin,
    MessageParcel &data, MessageParcel &reply, int32_t userId)
{
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    InitAllPlugins();
    std::shared_ptr<IPlugin> plugin = pluginMgr_->GetPluginByFuncCode(code);
    if (plugin == nullptr) {
        EDMLOGW("HandleDevicePolicy: get plugin failed, code:%{public}d", code);
        return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
    }
#ifndef EDM_FUZZ_TEST
    bool isUserExist = false;
    GetOsAccountMgr()->IsOsAccountExists(userId, isUserExist);
    if (!isUserExist) {
        return EdmReturnErrCode::PARAM_ERROR;
    }
    ErrCode systemCalling = GetPermissionChecker()->CheckSystemCalling(plugin->GetApiType(FuncOperateType::SET), "");
    if (FAILED(systemCalling)) {
        return systemCalling;
    }
    EDMLOGI("HandleDevicePolicy: HandleDevicePolicy userId = %{public}d", userId);
    std::shared_ptr<Admin> deviceAdmin = AdminManager::GetInstance()->GetAdminByPkgName(admin.GetBundleName(),
        GetCurrentUserId());
    if (deviceAdmin == nullptr) {
        EDMLOGE("HandleDevicePolicy: %{public}s is not activated", admin.GetBundleName().c_str());
        return EdmReturnErrCode::ADMIN_INACTIVE;
    }
    std::string setPermission = plugin->GetPermission(FuncOperateType::SET,
        GetPermissionChecker()->AdminTypeToPermissionType(deviceAdmin->GetAdminType()), data.ReadString());
    EDMLOGD("HandleDevicePolicy: HandleDevicePolicy GetPermission = %{public}s", setPermission.c_str());
    ErrCode checkAdminPermission = GetPermissionChecker()->CheckHandlePolicyPermission(FuncOperateType::SET,
        admin.GetBundleName(), plugin->GetPolicyName(), setPermission, userId);
    if (FAILED(checkAdminPermission)) {
        return checkAdminPermission;
    }
#endif
    ErrCode ret = UpdateDevicePolicy(code, admin.GetBundleName(), data, reply, userId);
    CreateSecurityContent(admin.GetBundleName(), admin.GetAbilityName(), code, plugin->GetPolicyName(), ret);
    return ret;
}

void EnterpriseDeviceMgrAbility::CreateSecurityContent(const std::string &bundleName, const std::string &abilityName,
    uint32_t code, const std::string &policyName, ErrCode errorCode)
{
    ReportInfo reportInfo = ReportInfo(FuncCodeUtils::GetOperateType(code), policyName, std::to_string(errorCode));
    SecurityReport::ReportSecurityInfo(bundleName, abilityName, reportInfo);
}

ErrCode EnterpriseDeviceMgrAbility::GetDevicePolicy(uint32_t code, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    bool isUserExist = false;
    GetOsAccountMgr()->IsOsAccountExists(userId, isUserExist);
    if (!isUserExist) {
        EDMLOGW("GetDevicePolicy: IsOsAccountExists failed");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    ErrCode errCode = PluginPolicyReader::GetInstance()->GetPolicyByCode(policyMgr_, code, data, reply, userId);
    if (errCode == EdmReturnErrCode::INTERFACE_UNSUPPORTED) {
        EDMLOGW("GetDevicePolicy: GetPolicyByCode INTERFACE_UNSUPPORTED");
        return errCode;
    }
    if (errCode == ERR_CANNOT_FIND_QUERY_FAILED) {
        return GetDevicePolicyFromPlugin(code, data, reply, userId);
    }
    EDMLOGI("policy query get finished");
    return errCode;
}

ErrCode EnterpriseDeviceMgrAbility::GetDevicePolicyFromPlugin(uint32_t code, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    InitAllPlugins();
    std::shared_ptr<IPlugin> plugin = pluginMgr_->GetPluginByFuncCode(code);
    if (plugin == nullptr) {
        return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
    }
    std::string permissionTag = data.ReadString();
    ErrCode systemCallingCheck = GetPermissionChecker()->CheckSystemCalling(
        plugin->GetApiType(FuncOperateType::GET), permissionTag);
    if (FAILED(systemCallingCheck)) {
        return systemCallingCheck;
    }
    AppExecFwk::ElementName elementName;
    // has admin
    if (data.ReadInt32() == 0) {
        std::unique_ptr<AppExecFwk::ElementName> admin(data.ReadParcelable<AppExecFwk::ElementName>());
        if (!admin) {
            EDMLOGW("GetDevicePolicy: ReadParcelable failed");
            return EdmReturnErrCode::PARAM_ERROR;
        }
#ifndef EDM_FUZZ_TEST
        std::shared_ptr<Admin> deviceAdmin = AdminManager::GetInstance()->GetAdminByPkgName(admin->GetBundleName(),
            GetCurrentUserId());
        if (deviceAdmin == nullptr) {
            return EdmReturnErrCode::ADMIN_INACTIVE;
        }
        std::string getPermission = plugin->GetPermission(FuncOperateType::GET,
            GetPermissionChecker()->AdminTypeToPermissionType(deviceAdmin->GetAdminType()), permissionTag);
        ErrCode ret = GetPermissionChecker()->CheckHandlePolicyPermission(FuncOperateType::GET,
            admin->GetBundleName(), plugin->GetPolicyName(), getPermission, userId);
        if (FAILED(ret)) {
            return ret;
        }
#endif
        elementName.SetBundleName(admin->GetBundleName());
        elementName.SetAbilityName(admin->GetAbilityName());
    }
    std::string policyName = plugin->GetPolicyName();
    std::string policyValue;

    if (plugin->NeedSavePolicy()) {
        policyMgr_->GetPolicy(elementName.GetBundleName(), policyName, policyValue, userId);
    }
    ErrCode getRet = plugin->GetExecuteStrategy()->OnGetExecute(code, policyValue, data, reply, userId);
    CreateSecurityContent(elementName.GetBundleName(), elementName.GetAbilityName(), code, plugin->GetPolicyName(),
        getRet);
    return getRet;
}

ErrCode EnterpriseDeviceMgrAbility::CheckAndGetAdminProvisionInfo(uint32_t code, MessageParcel &data,
    MessageParcel &reply, int32_t userId)
{
    InitAllPlugins();
    std::shared_ptr<IPlugin> plugin = pluginMgr_->GetPluginByFuncCode(code);
    if (plugin == nullptr) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (AdminManager::GetInstance()->IsAdminExist()) {
        EDMLOGE("CheckAndGetAdminProvisionInfo::device exist admin.");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    Security::AccessToken::AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    if (!GetPermissionChecker()->VerifyCallingPermission(tokenId, PERMISSION_GET_ADMINPROVISION_INFO)) {
        EDMLOGE("CheckAndGetAdminProvisionInfo::VerifyCallingPermission check permission failed.");
        return EdmReturnErrCode::PERMISSION_DENIED;
    }
    std::string policyValue;
    AppExecFwk::ElementName elementName;
    ErrCode getRet = plugin->GetExecuteStrategy()->OnGetExecute(code, policyValue, data, reply, userId);
    CreateSecurityContent(elementName.GetBundleName(), elementName.GetAbilityName(), code, plugin->GetPolicyName(),
        getRet);
    return getRet;
}

ErrCode EnterpriseDeviceMgrAbility::GetEnabledAdmin(AdminType type, std::vector<std::string> &enabledAdminList)
{
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    std::vector<std::string> superList;
    std::vector<std::string> normalList;
    std::vector<std::string> byodList;
    switch (type) {
        case AdminType::NORMAL:
            AdminManager::GetInstance()->GetEnabledAdmin(AdminType::NORMAL, normalList, GetCurrentUserId());
            AdminManager::GetInstance()->GetEnabledAdmin(AdminType::ENT, superList, EdmConstants::DEFAULT_USER_ID);
            break;
        case AdminType::ENT:
            AdminManager::GetInstance()->GetEnabledAdmin(AdminType::ENT, superList, EdmConstants::DEFAULT_USER_ID);
            break;
        case AdminType::BYOD:
            AdminManager::GetInstance()->GetEnabledAdmin(AdminType::BYOD, byodList, EdmConstants::DEFAULT_USER_ID);
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
    if (!byodList.empty()) {
        enabledAdminList.insert(enabledAdminList.begin(), byodList.begin(), byodList.end());
    }
    for (const auto &enabledAdmin : enabledAdminList) {
        EDMLOGD("GetEnabledAdmin: %{public}s", enabledAdmin.c_str());
    }
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::GetEnterpriseInfo(AppExecFwk::ElementName &admin, MessageParcel &reply)
{
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    auto adminItem = AdminManager::GetInstance()->GetAdminByPkgName(admin.GetBundleName(),  GetCurrentUserId());
    if (adminItem != nullptr && (adminItem->GetAdminType() == AdminType::VIRTUAL_ADMIN ||
        adminItem->GetAdminType() == AdminType::BYOD)) {
        EDMLOGE("GetEnterpriseInfo delegated or byod admin does not have permission to get enterprise info.");
        reply.WriteInt32(EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED);
        return EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED;
    }
    EntInfo entInfo;
    int32_t userId = (adminItem != nullptr && (adminItem->GetAdminType() == AdminType::ENT ||
        adminItem->GetAdminType() == AdminType::SUB_SUPER_ADMIN)) ? EdmConstants::DEFAULT_USER_ID : GetCurrentUserId();
    ErrCode code = AdminManager::GetInstance()->GetEntInfo(admin.GetBundleName(), entInfo, userId);
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
    int32_t userId = GetCurrentUserId();
    std::shared_ptr<Admin> adminItem = AdminManager::GetInstance()->GetAdminByPkgName(admin.GetBundleName(), userId);
    if (adminItem == nullptr) {
        return EdmReturnErrCode::ADMIN_INACTIVE;
    }
    ErrCode ret = GetPermissionChecker()->CheckCallerPermission(adminItem, PERMISSION_SET_ENTERPRISE_INFO, false);
    if (FAILED(ret)) {
        return ret;
    }
    if (adminItem->GetAdminType() == AdminType::ENT || adminItem->GetAdminType() == AdminType::SUB_SUPER_ADMIN) {
        userId = EdmConstants::DEFAULT_USER_ID;
    }
    ErrCode code = AdminManager::GetInstance()->SetEntInfo(admin.GetBundleName(), entInfo, userId);
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
    int32_t userId = AdminManager::GetInstance()->IsSuperOrSubSuperAdmin(admin.GetBundleName()) ?
        EdmConstants::DEFAULT_USER_ID : GetCurrentUserId();
    AdminManager::GetInstance()->SaveSubscribeEvents(events, admin.GetBundleName(), userId);
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::UnsubscribeManagedEvent(const AppExecFwk::ElementName &admin,
    const std::vector<uint32_t> &events)
{
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    RETURN_IF_FAILED(VerifyManagedEvent(admin, events));
    int32_t userId = AdminManager::GetInstance()->IsSuperOrSubSuperAdmin(admin.GetBundleName()) ?
        EdmConstants::DEFAULT_USER_ID : GetCurrentUserId();
    AdminManager::GetInstance()->RemoveSubscribeEvents(events, admin.GetBundleName(), userId);
    return HandleApplicationEvent(events, false);
}

ErrCode EnterpriseDeviceMgrAbility::VerifyManagedEvent(const AppExecFwk::ElementName &admin,
    const std::vector<uint32_t> &events)
{
    std::shared_ptr<Admin> adminItem = AdminManager::GetInstance()->GetAdminByPkgName(admin.GetBundleName(),
        GetCurrentUserId());
    ErrCode ret = GetPermissionChecker()->CheckCallerPermission(adminItem,
        PERMISSION_ENTERPRISE_SUBSCRIBE_MANAGED_EVENT, false);
    if (FAILED(ret)) {
        return ret;
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
        case static_cast<uint32_t>(ManagedEvent::USER_ADDED):
        case static_cast<uint32_t>(ManagedEvent::USER_SWITCHED):
        case static_cast<uint32_t>(ManagedEvent::USER_REMOVED):
            break;
        default:
            return false;
    }
    return true;
}

ErrCode EnterpriseDeviceMgrAbility::AuthorizeAdmin(const AppExecFwk::ElementName &admin, const std::string &bundleName)
{
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    std::shared_ptr<Admin> adminItem = AdminManager::GetInstance()->GetAdminByPkgName(admin.GetBundleName(),
        GetCurrentUserId());
    ErrCode ret = GetPermissionChecker()->CheckCallerPermission(adminItem, PERMISSION_MANAGE_ENTERPRISE_DEVICE_ADMIN,
        true);
    if (FAILED(ret)) {
        return ret;
    }
    /* Get all request and registered permissions */
    std::vector<std::string> permissionList;
    if (FAILED(GetPermissionChecker()->GetAllPermissionsByAdmin(bundleName, AdminType::SUB_SUPER_ADMIN,
        EdmConstants::DEFAULT_USER_ID, permissionList))) {
        EDMLOGW("AuthorizeAdmin: GetAllPermissionsByAdmin failed.");
        return EdmReturnErrCode::AUTHORIZE_PERMISSION_FAILED;
    }
    EntInfo entInfo;
    AppExecFwk::ExtensionAbilityInfo abilityInfo;
    abilityInfo.bundleName = bundleName;
    Admin subAdmin(abilityInfo, AdminType::SUB_SUPER_ADMIN, entInfo, permissionList, adminItem->adminInfo_.isDebug_);
    subAdmin.SetParentAdminName(admin.GetBundleName());
    return AdminManager::GetInstance()->SetAdminValue(EdmConstants::DEFAULT_USER_ID, subAdmin);
}

ErrCode EnterpriseDeviceMgrAbility::GetSuperAdmin(MessageParcel &reply)
{
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    auto superAdmin = AdminManager::GetInstance()->GetSuperAdmin();
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

ErrCode EnterpriseDeviceMgrAbility::SetDelegatedPolicies(const std::string &parentAdminName,
    const std::string &bundleName, const std::vector<std::string> &policies)
{
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    std::shared_ptr<Admin> adminItem = AdminManager::GetInstance()->GetAdminByPkgName(parentAdminName,
        GetCurrentUserId());
    ErrCode ret = GetPermissionChecker()->CheckCallerPermission(adminItem, PERMISSION_SET_DELEGATED_POLICY, true);
    if (FAILED(ret)) {
        return ret;
    }
    if (parentAdminName == bundleName) {
        EDMLOGE("SetDelegatedPolicies does not delegated policies to self.");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    if (policies.empty()) {
        EDMLOGW("SetDelegatedPolicies remove delegated policies.");
        return RemoveSubSuperAdminAndAdminPolicy(bundleName);
    }
    ret = CheckDelegatedPolicies(adminItem, policies);
    if (FAILED(ret)) {
        return ret;
    }
    if (!GetBundleMgr()->IsBundleInstalled(bundleName, EdmConstants::DEFAULT_USER_ID)) {
        EDMLOGE("SetDelegatedPolicies the delegated application does not installed.");
        return EdmReturnErrCode::AUTHORIZE_PERMISSION_FAILED;
    }
    std::string appDistributionType = GetBundleMgr()->GetApplicationInfo(bundleName, EdmConstants::DEFAULT_USER_ID);
    if (appDistributionType != APP_TYPE_ENTERPRISE_MDM && appDistributionType != APP_TYPE_ENTERPRISE_NORMAL) {
        EDMLOGE("SetDelegatedPolicies get appDistributionType %{public}s.", appDistributionType.c_str());
        return EdmReturnErrCode::AUTHORIZE_PERMISSION_FAILED;
    }
    EntInfo entInfo;
    AppExecFwk::ExtensionAbilityInfo abilityInfo;
    abilityInfo.bundleName = bundleName;
    Admin virtualAdmin(abilityInfo, AdminType::VIRTUAL_ADMIN, entInfo, {}, adminItem->adminInfo_.isDebug_);
    virtualAdmin.SetParentAdminName(parentAdminName);
    virtualAdmin.SetAccessiblePolicies(policies);
    return AdminManager::GetInstance()->SetAdminValue(EdmConstants::DEFAULT_USER_ID, virtualAdmin);
}

ErrCode EnterpriseDeviceMgrAbility::GetDelegatedPolicies(const std::string &parentAdminName,
    const std::string &bundleName, std::vector<std::string> &policies)
{
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    std::shared_ptr<Admin> adminItem = AdminManager::GetInstance()->GetAdminByPkgName(parentAdminName,
        GetCurrentUserId());
    ErrCode ret = GetPermissionChecker()->CheckCallerPermission(adminItem, PERMISSION_SET_DELEGATED_POLICY, true);
    if (FAILED(ret)) {
        return ret;
    }
    return AdminManager::GetInstance()->GetPoliciesByVirtualAdmin(bundleName, parentAdminName, policies);
}

ErrCode EnterpriseDeviceMgrAbility::GetDelegatedBundleNames(const std::string &parentAdminName,
    const std::string &policyName, std::vector<std::string> &bundleNames)
{
    if (allowDelegatedPolicies_.find(policyName) == allowDelegatedPolicies_.end()) {
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::lock_guard<std::mutex> autoLock(mutexLock_);
    std::shared_ptr<Admin> adminItem = AdminManager::GetInstance()->GetAdminByPkgName(parentAdminName,
        GetCurrentUserId());
    ErrCode ret = GetPermissionChecker()->CheckCallerPermission(adminItem, PERMISSION_SET_DELEGATED_POLICY, true);
    if (FAILED(ret)) {
        return ret;
    }
    AdminManager::GetInstance()->GetVirtualAdminsByPolicy(policyName, parentAdminName, bundleNames);
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::CheckDelegatedPolicies(std::shared_ptr<Admin> admin,
    const std::vector<std::string> &policies)
{
    if (admin == nullptr) {
        return EdmReturnErrCode::ADMIN_INACTIVE;
    }
    for (const std::string &policy : policies) {
        if (allowDelegatedPolicies_.find(policy) == allowDelegatedPolicies_.end()) {
            return EdmReturnErrCode::PARAM_ERROR;
        }
        auto plugin = pluginMgr_->GetPluginByPolicyName(policy);
        if (plugin == nullptr) {
            EDMLOGE("CheckDelegatedPolicies get policyName is not exist.");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        auto permission = plugin->GetPermission(FuncOperateType::SET,
            GetPermissionChecker()->AdminTypeToPermissionType(admin->GetAdminType()));
        if (permission == NONE_PERMISSION_MATCH) {
            permission = plugin->GetPermission(FuncOperateType::SET,
                GetPermissionChecker()->AdminTypeToPermissionType(admin->GetAdminType()),
                EdmConstants::PERMISSION_TAG_VERSION_12);
        }
        if (permission.empty() || permission == NONE_PERMISSION_MATCH) {
            EDMLOGE("CheckDelegatedPolicies get plugin access permission failed.");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        auto ret = GetPermissionChecker()->CheckAndUpdatePermission(admin, IPCSkeleton::GetCallingTokenID(),
            permission, EdmConstants::DEFAULT_USER_ID);
        if (FAILED(ret)) {
            return ret;
        }
    }
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::GetAdmins(std::vector<std::shared_ptr<AAFwk::Want>> &wants)
{
    std::vector<std::shared_ptr<Admin>> admins;
    AdminManager::GetInstance()->GetAdmins(admins, GetCurrentUserId());
    for (auto admin : admins) {
        std::shared_ptr<AAFwk::Want> want = std::make_shared<AAFwk::Want>();
        want->SetParam("bundleName", admin->adminInfo_.packageName_);
        want->SetParam("abilityName", admin->adminInfo_.className_);
        want->SetParam("adminType", static_cast<int32_t>(admin->adminInfo_.adminType_));
        wants.push_back(want);
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS