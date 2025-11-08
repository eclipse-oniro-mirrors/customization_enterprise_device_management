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
#include "clipboard_policy.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "device_policies_storage_rdb.h"
#include "directory_ex.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "matching_skills.h"
#include "message_parcel.h"
#include "parameters.h"
#include "system_ability.h"
#include "system_ability_definition.h"
#include "application_instance.h"
#include "array_string_serializer.h"
#include "admin_action.h"
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
#include "hisysevent_adapter.h"
#include "plugin_policy_reader.h"
#include "policy_type.h"

#ifdef NET_MANAGER_BASE_EDM_ENABLE
#include "map_string_serializer.h"
#endif
#ifdef PASTEBOARD_EDM_ENABLE
#include "clipboard_policy_serializer.h"
#endif
#ifdef USERIAM_EDM_ENABLE
#include "fingerprint_policy.h"
#include "fingerprint_policy_serializer.h"
#include "password_policy_serializer.h"
#endif

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT =
    SystemAbility::MakeAndRegisterAbility(EnterpriseDeviceMgrAbility::GetInstance().GetRefPtr());

const std::string PERMISSION_UPDATE_SYSTEM = "ohos.permission.UPDATE_SYSTEM";
const std::string PARAM_EDM_ENABLE = "persist.edm.edm_enable";
const std::string PARAM_SECURITY_MODE = "ohos.boot.advsecmode.state";
const std::string SYSTEM_UPDATE_FOR_POLICY = "usual.event.DUE_SA_FIRMWARE_UPDATE_FOR_POLICY";
const std::string WANT_BUNDLE_NAME = "bundleName";
const std::string FIRMWARE_EVENT_INFO_NAME = "version";
const std::string FIRMWARE_EVENT_INFO_TYPE = "packageType";
const std::string FIRMWARE_EVENT_INFO_CHECK_TIME = "firstReceivedTime";
const std::string DEVELOP_MODE_STATE = "const.security.developermode.state";
const std::string EDM_ADMIN_ENABLED_EVENT = "com.ohos.edm.edmadminenabled";
const std::string EDM_ADMIN_DISABLED_EVENT = "com.ohos.edm.edmadmindisabled";
const std::string APP_TYPE_ENTERPRISE_MDM = "enterprise_mdm";
const std::string APP_TYPE_ENTERPRISE_NORMAL = "enterprise_normal";
const char* const KEY_EDM_DISPLAY = "com.enterprise.enterprise_device_manager_display";
const std::string POLICY_ALLOW_ALL = "allow_all";
const int32_t INVALID_SYSTEM_ABILITY_ID = -1;
const int32_t MAX_POLICY_TYPE = 3;
const int32_t UPDATE_APPS_STATE_ON_AG_CHANGE = 1;
const int32_t UPDATE_APPS_STATE_ON_BMS_CHANGE = 2;
const int32_t INIT_AG_TASK = 3;
const int32_t INSTALL_MARKET_APPS_PLUGIN_CODE = 3028;
const int32_t AG_COMMON_EVENT_SIZE = 2;
const int32_t WITHOUT_ADMIN = 1;
constexpr int32_t MAX_SDA_AND_DA_COUNT = 10;

std::shared_mutex EnterpriseDeviceMgrAbility::adminLock_;

sptr<EnterpriseDeviceMgrAbility> EnterpriseDeviceMgrAbility::instance_;

constexpr const char *WITHOUT_PERMISSION_TAG = "";
#ifndef EDM_FUZZ_TEST
const int EDM_UID = 3057;
#endif

const int EDC_UID = 7200;

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
            that->UpdateMarketAppsState(data, UPDATE_APPS_STATE_ON_BMS_CHANGE);
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
    commonEventFuncMap_[EventFwk::CommonEventSupport::COMMON_EVENT_BUNDLE_SCAN_FINISHED] =
        [](EnterpriseDeviceMgrAbility* that, const EventFwk::CommonEventData &data) {
            that->OnCommonEventBmsReady(data);
        };
    commonEventFuncMap_[EventFwk::CommonEventSupport::COMMON_EVENT_KIOSK_MODE_ON] =
        [](EnterpriseDeviceMgrAbility* that, const EventFwk::CommonEventData &data) {
            that->OnCommonEventKioskMode(data, true);
        };
    commonEventFuncMap_[EventFwk::CommonEventSupport::COMMON_EVENT_KIOSK_MODE_OFF] =
        [](EnterpriseDeviceMgrAbility* that, const EventFwk::CommonEventData &data) {
            that->OnCommonEventKioskMode(data, false);
        };
}

void EnterpriseDeviceMgrAbility::InitAgTask()
{
    auto superAdmin = AdminManager::GetInstance()->GetSuperAdmin();
    if (superAdmin == nullptr) {
        EDMLOGE("current super admin is nullptr");
        return;
    }
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::INSTALL_MARKET_APPS);
    MessageParcel reply;
    MessageParcel messageData;
    messageData.WriteString(WITHOUT_PERMISSION_TAG);
    std::vector<std::string> bundleNames = {};
    messageData.WriteStringVector(bundleNames);
    messageData.WriteInt32(INIT_AG_TASK);

    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(superAdmin->adminInfo_.packageName_);
    elementName.SetAbilityName(superAdmin->adminInfo_.className_);
    HandleDevicePolicy(funcCode, elementName, messageData, reply, EdmConstants::DEFAULT_USER_ID);
}

void EnterpriseDeviceMgrAbility::GetAgCommonEventName()
{
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::INSTALL_MARKET_APPS);
    MessageParcel reply;
    MessageParcel messageData;
    messageData.WriteString(WITHOUT_PERMISSION_TAG);
    messageData.WriteInt32(WITHOUT_ADMIN);

    GetDevicePolicyFromPlugin(funcCode, messageData, reply, EdmConstants::DEFAULT_USER_ID);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGE("failed to get ag common event");
        return;
    }
    std::vector<std::string> agCommonEventList = {};
    if (!reply.ReadStringVector(&agCommonEventList)) {
        EDMLOGE("failed to read ag common event");
        return;
    }

    if (agCommonEventList.size() != AG_COMMON_EVENT_SIZE) {
        EDMLOGE("ag common event size is abnormally");
        return;
    }
    commonEventFuncMap_[agCommonEventList[0]] =
        [](EnterpriseDeviceMgrAbility* that, const EventFwk::CommonEventData &data) {
            that->UpdateMarketAppsState(data, UPDATE_APPS_STATE_ON_AG_CHANGE);
        };
    commonEventFuncMap_[agCommonEventList[1]] =
        [](EnterpriseDeviceMgrAbility* that, const EventFwk::CommonEventData &data) {
            that->UpdateMarketAppsState(data, UPDATE_APPS_STATE_ON_AG_CHANGE);
        };
}

void EnterpriseDeviceMgrAbility::UpdateMarketAppsState(const EventFwk::CommonEventData &data, int32_t event)
{
    auto superAdmin = AdminManager::GetInstance()->GetSuperAdmin();
    if (superAdmin == nullptr) {
        EDMLOGE("current super admin is nullptr");
        return;
    }
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::INSTALL_MARKET_APPS);
    MessageParcel reply;
    MessageParcel messageData;
    messageData.WriteString(WITHOUT_PERMISSION_TAG);
    std::vector<std::string> bundleNames = {};
    messageData.WriteStringVector(bundleNames);
    // event用于区分BMS和AG的安装事件
    messageData.WriteInt32(event);
    // data.GetCode()用于状态机更新状态
    messageData.WriteInt32(data.GetCode());
    messageData.WriteString(data.GetWant().GetStringParam(WANT_BUNDLE_NAME));

    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(superAdmin->adminInfo_.packageName_);
    elementName.SetAbilityName(superAdmin->adminInfo_.className_);
    HandleDevicePolicy(funcCode, elementName, messageData, reply, EdmConstants::DEFAULT_USER_ID);
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
    std::shared_ptr<EnterpriseConnManager> manager = DelayedSingleton<EnterpriseConnManager>::GetInstance();
    if (manager == nullptr) {
        EDMLOGW("EnterpriseDeviceMgrAbility::ConnectAbilityOnSystemUpdate EnterpriseConnManager null");
        return;
    }
    for (const auto &subAdmin : subAdmins) {
        for (const auto &it : subAdmin.second) {
            want.SetElementName(it->adminInfo_.packageName_, it->adminInfo_.className_);
            bool ret = manager->CreateUpdateConnection(want, subAdmin.first, updateInfo);
            if (!ret) {
                EDMLOGW("EnterpriseDeviceMgrAbility::ConnectAbilityOnSystemUpdate CreateUpdateConnection failed.");
            }
        }
    }
}

void EnterpriseDeviceMgrAbility::AddOnAddSystemAbilityFuncMapSecond()
{
    addSystemAbilityFuncMap_[BUNDLE_MGR_SERVICE_SYS_ABILITY_ID] =
        [](EnterpriseDeviceMgrAbility* that, int32_t systemAbilityId, const std::string &deviceId) {
            that->CallOnOtherServiceStart(EdmInterfaceCode::ALLOWED_KIOSK_APPS, BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
        };
    addSystemAbilityFuncMap_[ABILITY_MGR_SERVICE_ID] =
        [](EnterpriseDeviceMgrAbility* that, int32_t systemAbilityId, const std::string &deviceId) {
            that->OnAbilityManagerServiceStart();
            that->CallOnOtherServiceStart(EdmInterfaceCode::ALLOWED_KIOSK_APPS, ABILITY_MGR_SERVICE_ID);
        };
    addSystemAbilityFuncMap_[WINDOW_MANAGER_SERVICE_ID] =
        [](EnterpriseDeviceMgrAbility* that, int32_t systemAbilityId, const std::string &deviceId) {
            that->CallOnOtherServiceStart(EdmInterfaceCode::SNAPSHOT_SKIP);
            that->CallOnOtherServiceStart(EdmInterfaceCode::ALLOWED_KIOSK_APPS, WINDOW_MANAGER_SERVICE_ID);
        };
    addSystemAbilityFuncMap_[RES_SCHED_SYS_ABILITY_ID] =
        [](EnterpriseDeviceMgrAbility* that, int32_t systemAbilityId, const std::string &deviceId) {
            that->CallOnOtherServiceStart(EdmInterfaceCode::MANAGE_FREEZE_EXEMPTED_APPS, RES_SCHED_SYS_ABILITY_ID);
        };
#ifdef MOBILE_DATA_ENABLE
    addSystemAbilityFuncMap_[TELEPHONY_CALL_MANAGER_SYS_ABILITY_ID] =
        [](EnterpriseDeviceMgrAbility* that, int32_t systemAbilityId, const std::string &deviceId) {
            that->CallOnOtherServiceStart(EdmInterfaceCode::TELEPHONY_CALL_POLICY);
        };
#endif
}

void EnterpriseDeviceMgrAbility::AddOnAddSystemAbilityFuncMap()
{
    AddOnAddSystemAbilityFuncMapSecond();
    addSystemAbilityFuncMap_[APP_MGR_SERVICE_ID] =
        [](EnterpriseDeviceMgrAbility* that, int32_t systemAbilityId, const std::string &deviceId) {
            that->OnAppManagerServiceStart();
        };
    addSystemAbilityFuncMap_[COMMON_EVENT_SERVICE_ID] =
        [](EnterpriseDeviceMgrAbility* that, int32_t systemAbilityId, const std::string &deviceId) {
            that->OnCommonEventServiceStart();
        };
#ifdef PASTEBOARD_EDM_ENABLE
    addSystemAbilityFuncMap_[PASTEBOARD_SERVICE_ID] =
        [](EnterpriseDeviceMgrAbility* that, int32_t systemAbilityId, const std::string &deviceId) {
            that->CallOnOtherServiceStart(EdmInterfaceCode::CLIPBOARD_POLICY);
        };
#endif
#ifdef NET_MANAGER_BASE_EDM_ENABLE
    addSystemAbilityFuncMap_[COMM_NET_POLICY_MANAGER_SYS_ABILITY_ID] =
        [](EnterpriseDeviceMgrAbility* that, int32_t systemAbilityId, const std::string &deviceId) {
            that->CallOnOtherServiceStart(EdmInterfaceCode::DISABLED_NETWORK_INTERFACE);
        };
#endif
#ifdef USB_SERVICE_EDM_ENABLE
    addSystemAbilityFuncMap_[USB_SYSTEM_ABILITY_ID] =
        [](EnterpriseDeviceMgrAbility* that, int32_t systemAbilityId, const std::string &deviceId) {
            that->CallOnOtherServiceStart(EdmInterfaceCode::DISABLE_USB);
            that->CallOnOtherServiceStart(EdmInterfaceCode::ALLOWED_USB_DEVICES);
            that->CallOnOtherServiceStart(EdmInterfaceCode::DISALLOWED_USB_DEVICES);
        };
#endif
#ifdef USERIAM_EDM_ENABLE
    addSystemAbilityFuncMap_[SUBSYS_USERIAM_SYS_ABILITY_USERAUTH] =
        [](EnterpriseDeviceMgrAbility* that, int32_t systemAbilityId, const std::string &deviceId) {
            that->CallOnOtherServiceStart(EdmInterfaceCode::PASSWORD_POLICY);
            that->CallOnOtherServiceStart(EdmInterfaceCode::FINGERPRINT_AUTH);
        };
#endif
    addSystemAbilityFuncMap_[RENDER_SERVICE] =
        [](EnterpriseDeviceMgrAbility* that, int32_t systemAbilityId, const std::string &deviceId) {
            that->CallOnOtherServiceStart(EdmInterfaceCode::WATERMARK_IMAGE);
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
    GetAgCommonEventName();
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

void EnterpriseDeviceMgrAbility::UpdateUserNonStopInfo(const std::string &bundleName, int32_t userId, int32_t appIndex)
{
    EDMLOGI("OnCommonEventPackageRemoved UpdateUserNonStopInfo");
    std::vector<std::shared_ptr<Admin>> admins;
    AdminManager::GetInstance()->GetAdmins(admins, EdmConstants::DEFAULT_USER_ID);
    for (const auto& admin : admins) {
        std::uint32_t funcCode =
            POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::MANAGE_USER_NON_STOP_APPS);
        std::vector<ApplicationInstance> userNonStopApps;
        ApplicationInstance applicationInstance = { bundleName, userId, appIndex};
        userNonStopApps.push_back(applicationInstance);
        MessageParcel reply;
        MessageParcel data;
        data.WriteString(WITHOUT_PERMISSION_TAG);
        if (!ApplicationInstanceHandle::WriteApplicationInstanceVector(data, userNonStopApps)) {
            EDMLOGE("OnCommonEventPackageRemoved WriteApplicationInstanceVector fail");
        }
        data.WriteBool(true);
        OHOS::AppExecFwk::ElementName elementName;
        elementName.SetBundleName(admin->adminInfo_.packageName_);
        elementName.SetAbilityName(admin->adminInfo_.className_);
        HandleDevicePolicy(funcCode, elementName, data, reply, EdmConstants::DEFAULT_USER_ID);
    }
}

void EnterpriseDeviceMgrAbility::OnCommonEventUserAdded(const EventFwk::CommonEventData &data)
{
    int userIdToAdd = data.GetCode();
    if (userIdToAdd < 0) {
        EDMLOGE("EnterpriseDeviceMgrAbility OnCommonEventUserAdded error");
        return;
    }
    EDMLOGI("EnterpriseDeviceMgrAbility OnCommonEventUserAdded");
    ConnectAbilityOnSystemAccountEvent(userIdToAdd, ManagedEvent::USER_ADDED);
}

void EnterpriseDeviceMgrAbility::OnCommonEventUserSwitched(const EventFwk::CommonEventData &data)
{
    int userIdToSwitch = data.GetCode();
    if (userIdToSwitch < 0) {
        EDMLOGE("EnterpriseDeviceMgrAbility OnCommonEventUserSwitched error");
        return;
    }
    EDMLOGI("EnterpriseDeviceMgrAbility OnCommonEventUserSwitched");
    std::vector<std::shared_ptr<Admin>> userAdmin;
    AdminManager::GetInstance()->GetAdminByUserId(GetCurrentUserId(), userAdmin);
    for (auto &admin : userAdmin) {
        if (admin->IsEnterpriseAdminKeepAlive()) {
            OnAdminEnabled(admin->adminInfo_.packageName_, admin->adminInfo_.className_,
                IEnterpriseAdmin::COMMAND_ON_ADMIN_ENABLED, GetCurrentUserId(), false);
        }
    }
    ConnectAbilityOnSystemAccountEvent(userIdToSwitch, ManagedEvent::USER_SWITCHED);
}

void EnterpriseDeviceMgrAbility::OnCommonEventUserRemoved(const EventFwk::CommonEventData &data)
{
    int userIdToRemove = data.GetCode();
    if (userIdToRemove < 0) {
        EDMLOGE("EnterpriseDeviceMgrAbility OnCommonEventUserRemoved error");
        return;
    }
    EDMLOGI("OnCommonEventUserRemoved");
    std::unique_lock<std::shared_mutex> autoLock(adminLock_);
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
        if (subAdmin->IsAllowedAcrossAccountSetPolicy() &&
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

void EnterpriseDeviceMgrAbility::UpdateFreezeExemptedApps(const std::string &bundleName,
    int32_t userId, int32_t appIndex)
{
    EDMLOGI("OnCommonEventPackageRemoved UpdateFreezeExemptedApps");
    std::vector<std::shared_ptr<Admin>> admins;
    AdminManager::GetInstance()->GetAdmins(admins, EdmConstants::DEFAULT_USER_ID);
    for (const auto& admin : admins) {
        std::uint32_t funcCode =
            POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::MANAGE_FREEZE_EXEMPTED_APPS);
        std::vector<ApplicationMsg> freezeExemptedApps;
        ApplicationMsg appMsg = { bundleName, userId, appIndex };
        freezeExemptedApps.push_back(appMsg);
        MessageParcel reply;
        MessageParcel data;
        std::u16string descriptor = u"ohos.edm.IEnterpriseDeviceMgr";
        data.WriteString(WITHOUT_PERMISSION_TAG);
        if (!ApplicationInstanceHandle::WriteApplicationMsgVector(data, freezeExemptedApps)) {
            EDMLOGE("UpdateFreezeExemptedApps WriteApplicationInstanceVector fail");
        }
        data.WriteBool(true);
        OHOS::AppExecFwk::ElementName elementName;
        elementName.SetBundleName(admin->adminInfo_.packageName_);
        elementName.SetAbilityName(admin->adminInfo_.className_);
        HandleDevicePolicy(funcCode, elementName, data, reply, EdmConstants::DEFAULT_USER_ID);
    }
}

void EnterpriseDeviceMgrAbility::UpdateClipboardInfo(const std::string &bundleName, int32_t userId)
{
    EDMLOGI("OnCommonEventPackageRemoved UpdateClipboardInfo");
    std::vector<std::shared_ptr<Admin>> admins;
    AdminManager::GetInstance()->GetAdmins(admins, EdmConstants::DEFAULT_USER_ID);
    for (const auto& admin : admins) {
        std::uint32_t funcCode =
            POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::CLIPBOARD_POLICY);
        MessageParcel reply;
        MessageParcel data;
        data.WriteString(WITHOUT_PERMISSION_TAG);
        data.WriteInt32(ClipboardFunctionType::SET_HAS_BUNDLE_NAME);
        data.WriteString(bundleName);
        data.WriteInt32(userId);
        data.WriteInt32(static_cast<int32_t>(ClipboardPolicy::DEFAULT));
        OHOS::AppExecFwk::ElementName elementName;
        elementName.SetBundleName(admin->adminInfo_.packageName_);
        elementName.SetAbilityName(admin->adminInfo_.className_);
        HandleDevicePolicy(funcCode, elementName, data, reply, EdmConstants::DEFAULT_USER_ID);
    }
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
    std::unique_lock<std::shared_mutex> autoLock(adminLock_);
    std::shared_ptr<Admin> admin = AdminManager::GetInstance()->GetAdminByPkgName(bundleName, userId);
    if (admin != nullptr) {
        if (!admin->IsAllowedAcrossAccountSetPolicy()) {
            RemoveAdminAndAdminPolicy(bundleName, userId);
        }
        if (!admin->IsSuperAdmin() && admin->IsAllowedAcrossAccountSetPolicy() &&
            userId == EdmConstants::DEFAULT_USER_ID) {
            // remove sub super admin and sub super admin policy
            RemoveSubSuperAdminAndAdminPolicy(bundleName);
        }
        if (admin->IsSuperAdmin() && userId == EdmConstants::DEFAULT_USER_ID) {
            // remove super admin and super admin policy
            RemoveSuperAdminAndAdminPolicy(bundleName);
        }
        if (!AdminManager::GetInstance()->IsAdminExist()) {
            system::SetParameter(PARAM_EDM_ENABLE, "false");
            NotifyAdminEnabled(false);
        }
    }
    ConnectAbilityOnSystemEvent(bundleName, ManagedEvent::BUNDLE_REMOVED, userId);
    autoLock.unlock();
    UpdateClipboardInfo(bundleName, userId);
    int32_t appIndex = data.GetWant().GetIntParam(AppExecFwk::Constants::APP_INDEX,
        AppExecFwk::Constants::DEFAULT_APP_INDEX);
    UpdateFreezeExemptedApps(bundleName, userId, appIndex);
    UpdateUserNonStopInfo(bundleName, userId, appIndex);
}

void EnterpriseDeviceMgrAbility::OnCommonEventPackageChanged(const EventFwk::CommonEventData &data)
{
    EDMLOGI("OnCommonEventPackageChanged");
    std::string bundleName = data.GetWant().GetElement().GetBundleName();
    int32_t userId = data.GetWant().GetIntParam(AppExecFwk::Constants::USER_ID, AppExecFwk::Constants::INVALID_USERID);
    std::shared_ptr<Admin> admin = AdminManager::GetInstance()->GetAdminByPkgName(bundleName, userId);
    if (admin != nullptr) {
        if (admin->IsEnterpriseAdminKeepAlive()) {
            OnAdminEnabled(admin->adminInfo_.packageName_, admin->adminInfo_.className_,
                IEnterpriseAdmin::COMMAND_ON_ADMIN_ENABLED, userId, false);
        }
        std::vector<std::string> permissionList;
        if (FAILED(GetPermissionChecker()->GetAllPermissionsByAdmin(bundleName, userId, permissionList))) {
            EDMLOGW("OnCommonEventPackageChanged: GetAllPermissionsByAdmin failed");
            return;
        }
        if (FAILED(AdminManager::GetInstance()->UpdateAdminPermission(bundleName, userId, permissionList))) {
            EDMLOGW("OnCommonEventPackageChanged: update admin permission failed.");
        }
    }
}

void EnterpriseDeviceMgrAbility::OnCommonEventBmsReady(const EventFwk::CommonEventData &data)
{
    EDMLOGI("OnCommonEventBmsReady");
    ConnectEnterpriseAbility();
}

void EnterpriseDeviceMgrAbility::OnCommonEventKioskMode(const EventFwk::CommonEventData &data, bool isModeOn)
{
    AAFwk::Want want = data.GetWant();
    int32_t paramUserId = want.GetIntParam(AppExecFwk::Constants::USER_ID, EdmConstants::DEFAULT_USER_ID);
    std::string bundleName = want.GetStringParam(WANT_BUNDLE_NAME);
    auto code = static_cast<uint32_t>(
        isModeOn ? IEnterpriseAdmin::COMMAND_ON_KIOSK_MODE_ENTERING : IEnterpriseAdmin::COMMAND_ON_KIOSK_MODE_EXITING);
    std::vector<std::shared_ptr<Admin>> admins;
    int32_t currentUserId = GetCurrentUserId();
    if (currentUserId < 0) {
        return;
    }
    AdminManager::GetInstance()->GetAdmins(admins, currentUserId);
    for (const auto& admin : admins) {
        EDMLOGI("OnCommonEventKioskMode packageName:%{public}s", admin->adminInfo_.packageName_.c_str());
        AAFwk::Want connectWant;
        connectWant.SetElementName(admin->adminInfo_.packageName_, admin->adminInfo_.className_);
        std::shared_ptr<EnterpriseConnManager> manager = DelayedSingleton<EnterpriseConnManager>::GetInstance();
        bool ret = manager->CreateKioskConnection(connectWant, code, currentUserId, bundleName, paramUserId);
        if (!ret) {
            EDMLOGW("EnterpriseDeviceMgrAbility::OnCommonEventKioskMode CreateKioskConnection failed.");
        }
    }
}

bool EnterpriseDeviceMgrAbility::OnAdminEnabled(const std::string &bundleName, const std::string &abilityName,
    uint32_t code, int32_t userId, bool isAdminEnabled)
{
    if (abilityName.empty()) {
        EDMLOGW("EnterpriseDeviceMgrAbility::OnAdminEnabled ignore bundlename is %{public}s", bundleName.c_str());
        return false;
    }
    AAFwk::Want connectWant;
    connectWant.SetElementName(bundleName, abilityName);
    std::shared_ptr<EnterpriseConnManager> manager = DelayedSingleton<EnterpriseConnManager>::GetInstance();
    return manager->CreateAdminConnection(connectWant, code, userId, isAdminEnabled);
}

bool EnterpriseDeviceMgrAbility::OnAdminEnabled(AdminInfo adminInfo, uint32_t code, int32_t userId,
    const std::string &enabledBundleName)
{
    if (adminInfo.className_.empty()) {
        EDMLOGW("EnterpriseDeviceMgrAbility::OnAdminEnabled ignore bundlename is %{public}s",
            adminInfo.packageName_.c_str());
        return false;
    }
    AAFwk::Want connectWant;
    connectWant.SetElementName(adminInfo.packageName_, adminInfo.className_);
    std::shared_ptr<EnterpriseConnManager> manager = DelayedSingleton<EnterpriseConnManager>::GetInstance();
    return manager->CreateAdminConnection(
        connectWant, code, userId, true, enabledBundleName);
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
            int32_t userId = subAdmin.first;
            int32_t currentUserId = GetCurrentUserId();
            if (currentUserId < 0) {
                return;
            }
            if (it->adminInfo_.runningMode_ == RunningMode::MULTI_USER) {
                userId = currentUserId;
            }
            bool ret = manager->CreateAccountConnection(want, static_cast<uint32_t>(event), userId, accountId);
            if (!ret) {
                EDMLOGW("EnterpriseDeviceMgrAbility CreateAccountConnection failed.");
            }
        }
    }
}

void EnterpriseDeviceMgrAbility::ConnectAbility(const int32_t accountId, std::shared_ptr<Admin> admin)
{
    AAFwk::Want want;
    want.SetElementName(admin->adminInfo_.packageName_, admin->adminInfo_.className_);
    std::shared_ptr<EnterpriseConnManager> manager = DelayedSingleton<EnterpriseConnManager>::GetInstance();
    bool ret = manager->CreateAdminConnection(want, IEnterpriseAdmin::COMMAND_ON_ADMIN_ENABLED, accountId, false);
    if (!ret) {
        EDMLOGW("EnterpriseDeviceMgrAbility::ConnectAbility CreateAdminConnection failed.");
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
            int32_t currentUserId = subAdmin.first;
            int32_t tmpUserId = GetCurrentUserId();
            if (it->adminInfo_.runningMode_ == RunningMode::MULTI_USER && tmpUserId >= 0) {
                currentUserId = tmpUserId;
            }
            bool ret = manager->CreateBundleConnection(
                want, static_cast<uint32_t>(event), currentUserId, bundleName, userId);
            if (!ret) {
                EDMLOGW("EnterpriseDeviceMgrAbility::ConnectAbilityOnSystemEvent CreateBundleConnection failed.");
            }
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
        std::unique_lock<std::shared_mutex> autoLock(adminLock_);
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

    if (PluginManager::GetInstance()) {
        PluginManager::GetInstance().reset();
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
    {
        std::unique_lock<std::shared_mutex> autoLock(adminLock_);
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
        WatermarkObserverManager::GetInstance();
        AddOnAddSystemAbilityFuncMap();
        AddSystemAbilityListeners();
        CheckAndUpdateByodSettingsData();
    }
    InitAgTask();
}

void EnterpriseDeviceMgrAbility::CheckAndUpdateByodSettingsData()
{
    if (AdminManager::GetInstance()->IsByodAdminExist()) {
        EDMLOGD("CheckAndUpdateByodSettingsData:byod exist.");
        std::string data = "false";
        EdmDataAbilityUtils::GetStringFromSettingsDataShare(KEY_EDM_DISPLAY, data);
        if (data == "false") {
            EdmDataAbilityUtils::UpdateSettingsData(KEY_EDM_DISPLAY, "true");
        }
    }
}

void EnterpriseDeviceMgrAbility::InitAllAdmins()
{
    AdminManager::GetInstance()->Init();
    EDMLOGD("create AdminManager::GetInstance() success");
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
    AddSystemAbilityListener(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    AddSystemAbilityListener(COMMON_EVENT_SERVICE_ID);
    AddSystemAbilityListener(APP_MGR_SERVICE_ID);
    AddSystemAbilityListener(ABILITY_MGR_SERVICE_ID);
    AddSystemAbilityListener(RES_SCHED_SYS_ABILITY_ID);
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
#ifdef MOBILE_DATA_ENABLE
    AddSystemAbilityListener(TELEPHONY_CALL_MANAGER_SYS_ABILITY_ID);
#endif
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
    ConnectEnterpriseAbility();
}

void EnterpriseDeviceMgrAbility::ConnectEnterpriseAbility()
{
    std::vector<std::shared_ptr<Admin>> userAdmin;
    int32_t userId = GetCurrentUserId();
    AdminManager::GetInstance()->GetAdminByUserId(userId, userAdmin);
    for (auto &admin : userAdmin) {
        std::string bundleName = admin->adminInfo_.packageName_;
        if (admin->IsEnterpriseAdminKeepAlive() && (adminConnectMap_.find(bundleName) == adminConnectMap_.end() ||
            !adminConnectMap_[bundleName])) {
            adminConnectMap_[bundleName] = OnAdminEnabled(admin->adminInfo_.packageName_,
                admin->adminInfo_.className_, IEnterpriseAdmin::COMMAND_ON_ADMIN_ENABLED, userId, false);
        }
    }
}

void EnterpriseDeviceMgrAbility::CallOnOtherServiceStart(uint32_t interfaceCode)
{
    CallOnOtherServiceStart(interfaceCode, INVALID_SYSTEM_ABILITY_ID);
}

void EnterpriseDeviceMgrAbility::CallOnOtherServiceStart(uint32_t interfaceCode, int32_t systemAbilityId)
{
    EDMLOGI("EnterpriseDeviceMgrAbility::CallOnOtherServiceStart %{public}d", interfaceCode);
    auto ret = PluginManager::GetInstance()->LoadPluginByCode(interfaceCode);
    if (ret != ERR_OK) {
        return;
    }
    auto plugin = PluginManager::GetInstance()->GetPluginByCode(interfaceCode);
    if (plugin == nullptr) {
        EDMLOGE("get Plugin fail %{public}d", interfaceCode);
        return;
    }
    plugin->OnOtherServiceStart(systemAbilityId);
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

void EnterpriseDeviceMgrAbility::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId) {}

void EnterpriseDeviceMgrAbility::OnStop()
{
    PluginManager::GetInstance()->NotifyUnloadAllPlugin();
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

ErrCode EnterpriseDeviceMgrAbility::VerifyEnableAdminCondition(const AppExecFwk::ElementName &admin, AdminType type,
    int32_t userId, bool isDebug)
{
    if ((type == AdminType::ENT || type == AdminType::NORMAL) && userId != DEFAULT_USER_ID) {
        EDMLOGW("EnableAdmin: super device admin or device admin can only be enabled in default user.");
        return ERR_EDM_ADD_ADMIN_FAILED;
    }

    if (type != AdminType::ENT && system::GetBoolParameter(PARAM_SECURITY_MODE, false)) {
        EDMLOGW("EnableAdmin: The current mode is not supported.");
        return ERR_EDM_ADD_ADMIN_FAILED;
    }

    if (AdminManager::GetInstance()->IsExistTargetAdmin(!isDebug)) {
        EDMLOGW("EnableAdmin: An official super admin exsit, cannot enable another debug admin");
        return ERR_EDM_ADD_ADMIN_FAILED;
    }

    if (VerifyEnableAdminConditionCheckExistAdmin(admin, type, userId, isDebug) != ERR_OK) {
        return ERR_EDM_ADD_ADMIN_FAILED;
    }
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::VerifyEnableAdminConditionCheckExistAdmin(const AppExecFwk::ElementName &admin,
    AdminType type, int32_t userId, bool isDebug)
{
    std::shared_ptr<Admin> existAdmin = AdminManager::GetInstance()->GetAdminByPkgName(admin.GetBundleName(), userId);
    if (existAdmin != nullptr) {
        if (existAdmin->GetAdminType() != type) {
            EDMLOGW("EnableAdmin: a byod admin can't be enabled when alreadly enabled other admin.");
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
        return ERR_OK;
    }
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::CheckReplaceAdmins(const AppExecFwk::ElementName &oldAdmin,
    const AppExecFwk::ElementName &newAdmin, std::vector<AppExecFwk::ExtensionAbilityInfo> &abilityInfo,
    std::vector<std::string> &permissionList)
{
    Security::AccessToken::AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    if (!GetPermissionChecker()->VerifyCallingPermission(tokenId,
        EdmPermission::PERMISSION_MANAGE_ENTERPRISE_DEVICE_ADMIN)) {
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
        AppExecFwk::ExtensionAbilityInfoFlag::GET_EXTENSION_INFO_WITH_PERMISSION, EdmConstants::DEFAULT_USER_ID,
        abilityInfo) || abilityInfo.empty()) {
        EDMLOGW("ReplaceSuperAdmin: QueryExtensionAbilityInfos_newAdmin failed");
        return EdmReturnErrCode::COMPONENT_INVALID;
    }

    if (FAILED(VerifyEnableAdminCondition(newAdmin, AdminType::ENT, EdmConstants::DEFAULT_USER_ID, false))) {
        EDMLOGW("ReplaceSuperAdmin: VerifyEnableAdminCondition failed.");
        return EdmReturnErrCode::REPLACE_ADMIN_FAILED;
    }
    if (FAILED(GetPermissionChecker()->GetAllPermissionsByAdmin(newAdmin.GetBundleName(), DEFAULT_USER_ID,
        permissionList))) {
        EDMLOGW("ReplaceSuperAdmin: GetAllPermissionsByAdmin failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::AddDisallowUninstallApp(const std::string &bundleName)
{
    if (!GetBundleMgr()->SetDisallowedUninstall(bundleName, true)) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::DelDisallowUninstallApp(const std::string &bundleName)
{
    if (!GetBundleMgr()->SetDisallowedUninstall(bundleName, false)) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::AddDisallowUninstallAppForAccount(const std::string &bundleName, int32_t userId)
{
    AppExecFwk::BundleInfo bundleInfo;
    GetBundleMgr()->GetBundleInfo(bundleName, AppExecFwk::BundleFlag::GET_BUNDLE_WITH_ABILITIES,
        bundleInfo, userId);
    std::vector<std::string> data = {bundleInfo.appId};
    if (FAILED(GetBundleMgr()->AddAppInstallControlRule(data,
        AppExecFwk::AppInstallControlRuleType::DISALLOWED_UNINSTALL, userId))) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::DelDisallowUninstallAppForAccount(const std::string &bundleName, int32_t userId)
{
    AppExecFwk::BundleInfo bundleInfo;
    GetBundleMgr()->GetBundleInfo(bundleName, AppExecFwk::BundleFlag::GET_BUNDLE_WITH_ABILITIES,
        bundleInfo, userId);
    std::vector<std::string> data = {bundleInfo.appId};
    if (FAILED(GetBundleMgr()->DeleteAppInstallControlRule(
        AppExecFwk::AppInstallControlRuleType::DISALLOWED_UNINSTALL, data, userId))) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::HandleKeepPolicy(std::string &adminName, std::string &newAdminName,
    const AdminInfo &edmAdminInfo, const AdminInfo &oldAdminInfo)
{
    if (FAILED(AdminManager::GetInstance()->ReplaceSuperAdminByPackageName(adminName, edmAdminInfo))) {
        EDMLOGE("ReplaceSuperAdmin update Admin Policies Failed");
        return EdmReturnErrCode::REPLACE_ADMIN_FAILED;
    }
    std::string adminPolicyValue;
    policyMgr_->GetPolicy(adminName, PolicyName::POLICY_DISALLOWED_UNINSTALL_BUNDLES, adminPolicyValue);
    std::string combinedPolicyValue;
    policyMgr_->GetPolicy("", PolicyName::POLICY_DISALLOWED_UNINSTALL_BUNDLES, combinedPolicyValue);

    if (FAILED(policyMgr_->ReplaceAllPolicy(EdmConstants::DEFAULT_USER_ID, adminName, newAdminName))) {
        EDMLOGE("ReplaceSuperAdmin update device Policies Failed");
        AdminManager::GetInstance()->ReplaceSuperAdminByPackageName(newAdminName, oldAdminInfo);
        return EdmReturnErrCode::REPLACE_ADMIN_FAILED;
    }
    if (!adminPolicyValue.empty() && adminPolicyValue.find(adminName) != std::string::npos) {
        if (FAILED(DelDisallowUninstallApp(adminName))) {
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        if (FAILED(AddDisallowUninstallApp(newAdminName))) {
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        adminPolicyValue.replace(adminPolicyValue.find(adminName), adminName.length(), newAdminName);
        combinedPolicyValue.replace(combinedPolicyValue.find(adminName), adminName.length(), newAdminName);
        EDMLOGD("ReplaceSuperAdmin uninstall new admin policy value: %{public}s", adminPolicyValue.c_str());
        EDMLOGD("ReplaceSuperAdmin uninstall new combined policy value: %{public}s", combinedPolicyValue.c_str());
        if (FAILED(policyMgr_->SetPolicy(newAdminName, PolicyName::POLICY_DISALLOWED_UNINSTALL_BUNDLES,
            adminPolicyValue, combinedPolicyValue))) {
            EDMLOGE("ReplaceSuperAdmin update uninstall policy failed");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    EDMLOGD("ReportEdmEventManagerAdmin HandleKeepPolicy");
    HiSysEventAdapter::ReportEdmEventManagerAdmin(newAdminName.c_str(),
        static_cast<int32_t>(AdminAction::REPLACE),
        static_cast<int32_t>(AdminType::ENT), adminName.c_str());
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::ReplaceSuperAdmin(const AppExecFwk::ElementName &oldAdmin,
    const AppExecFwk::ElementName &newAdmin, bool keepPolicy)
{
    EDMLOGD("ReplaceSuperAdmin: oldAdmin.bundlename %{public}s,  oldAdmin.abilityname:%{public}s  "
        "ReplaceSuperAdmin: newAdmin.bundlename %{public}s,  newAdmin.abilityname:%{public}s",
        oldAdmin.GetBundleName().c_str(), oldAdmin.GetAbilityName().c_str(), newAdmin.GetBundleName().c_str(),
        newAdmin.GetAbilityName().c_str());
    std::vector<AppExecFwk::ExtensionAbilityInfo> abilityInfo;
    std::vector<std::string> permissionList;
    ErrCode ret = CheckReplaceAdmins(oldAdmin, newAdmin, abilityInfo, permissionList);
    if (FAILED(ret)) {
        EDMLOGE("ReplaceSuperAdmin: CheckReplaceAdmins failed");
        return ret;
    }
    auto superAdmin = AdminManager::GetInstance()->GetSuperAdmin();
    if (superAdmin->adminInfo_.runningMode_ == RunningMode::MULTI_USER) {
        EDMLOGE("multi user not support replace admin");
        return EdmReturnErrCode::REPLACE_ADMIN_FAILED;
    }
    std::string adminName = oldAdmin.GetBundleName();
    std::shared_ptr<Admin> adminPtr = AdminManager::GetInstance()->GetAdminByPkgName(adminName, DEFAULT_USER_ID);
    if (adminPtr == nullptr) {
        EDMLOGE("ReplaceSuperAdmin adminName is not admin");
        return EdmReturnErrCode::ADMIN_INACTIVE;
    }
    EntInfo entInfo = adminPtr->adminInfo_.entInfo_;
    AdminInfo adminInfo = {.packageName_ = abilityInfo.at(0).bundleName, .className_ = abilityInfo.at(0).name,
        .entInfo_ = entInfo, .permission_ = permissionList, .adminType_ = AdminType::ENT, .isDebug_ = false};
    std::unique_lock<std::shared_mutex> autoLock(adminLock_);
    if (keepPolicy) {
        std::string newAdminName = newAdmin.GetBundleName();
        HandleKeepPolicy(adminName, newAdminName, adminInfo, adminPtr->adminInfo_);
    } else {
        ErrCode res = DoDisableAdmin(adminPtr, DEFAULT_USER_ID, AdminType::ENT);
        if (res != ERR_OK) {
            EDMLOGE("ReplaceSuperAdmin: delete admin failed");
            return EdmReturnErrCode::REPLACE_ADMIN_FAILED;
        }
        if (FAILED(AdminManager::GetInstance()->SetAdminValue(DEFAULT_USER_ID, adminInfo))) {
            EDMLOGE("ReplaceSuperAdmin: SetAdminValue failed.");
            return EdmReturnErrCode::REPLACE_ADMIN_FAILED;
        }
    }
    system::SetParameter(PARAM_EDM_ENABLE, "true");
    NotifyAdminEnabled(true);
    OnAdminEnabled(newAdmin.GetBundleName(), newAdmin.GetAbilityName(), IEnterpriseAdmin::COMMAND_ON_ADMIN_ENABLED,
        DEFAULT_USER_ID, true);
    EDMLOGI("EnableAdmin: SetAdminEnabled success %{public}s", newAdmin.GetBundleName().c_str());
    AfterEnableAdminReportEdmEvent(newAdmin, oldAdmin);
    return ERR_OK;
}

void EnterpriseDeviceMgrAbility::AfterEnableAdminReportEdmEvent(const AppExecFwk::ElementName &newAdmin,
    const AppExecFwk::ElementName &oldAdmin)
{
    DelDisallowUninstallApp(oldAdmin.GetBundleName());
    AddDisallowUninstallApp(newAdmin.GetBundleName());
    EdmDataAbilityUtils::UpdateSettingsData(KEY_EDM_DISPLAY, "true");
    HiSysEventAdapter::ReportEdmEventManagerAdmin(newAdmin.GetBundleName().c_str(),
        static_cast<int32_t>(AdminAction::REPLACE),
        static_cast<int32_t>(AdminType::ENT), oldAdmin.GetBundleName().c_str());
}

ErrCode EnterpriseDeviceMgrAbility::EnableAdmin(
    const AppExecFwk::ElementName &admin, const EntInfo &entInfo, AdminType type, int32_t userId)
{
    EDMLOGD("EnterpriseDeviceMgrAbility::EnableAdmin");
    if (type != AdminType::NORMAL && type != AdminType::ENT && type != AdminType::BYOD) {
        EDMLOGE("EnterpriseDeviceMgrAbility::EnableAdmin admin type is invalid.");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::unique_lock<std::shared_mutex> autoLock(adminLock_);
    if (AdminManager::GetInstance()->GetSuperDeviceAdminAndDeviceAdminCount() >= MAX_SDA_AND_DA_COUNT) {
        EDMLOGE("EnterpriseDeviceMgrAbility::super device admin and device admin has reach max count %{public}d.",
            MAX_SDA_AND_DA_COUNT);
        return EdmReturnErrCode::ENABLE_ADMIN_FAILED;
    }
    bool isDebug = GetPermissionChecker()->CheckIsDebug();
    Security::AccessToken::AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    if (!isDebug && !GetPermissionChecker()->VerifyCallingPermission(tokenId,
        EdmPermission::PERMISSION_MANAGE_ENTERPRISE_DEVICE_ADMIN)) {
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
    if (!isDebug && type == AdminType::ENT && AdminManager::GetInstance()->IsSuperAdminExist() &&
        existAdmin == nullptr) {
        EDMLOGW("EnableAdmin: There is another super admin enabled.");
        return EdmReturnErrCode::ENABLE_ADMIN_FAILED;
    }
    /* Get all request and registered permissions */
    std::vector<std::string> permissionList;
    if (FAILED(GetPermissionChecker()->GetAllPermissionsByAdmin(admin.GetBundleName(), userId, permissionList))) {
        EDMLOGW("EnableAdmin: GetAllPermissionsByAdmin failed");
        return EdmReturnErrCode::COMPONENT_INVALID;
    }
    AdminInfo adminInfo = {.packageName_ = abilityInfo.at(0).bundleName, .className_ = abilityInfo.at(0).name,
        .entInfo_ = entInfo, .permission_ = permissionList, .adminType_ = type, .isDebug_ = isDebug};
    if (FAILED(AdminManager::GetInstance()->SetAdminValue(userId, adminInfo))) {
        return EdmReturnErrCode::ENABLE_ADMIN_FAILED;
    }
    AfterEnableAdmin(admin, type, userId);
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::CheckEnableDeviceAdmin(const AppExecFwk::ElementName &admin)
{
    int32_t adminCount = AdminManager::GetInstance()->GetSuperDeviceAdminAndDeviceAdminCount();
    if (adminCount >= MAX_SDA_AND_DA_COUNT) {
        EDMLOGE("EnterpriseDeviceMgrAbility::EnableDeviceAdmin Exceeded maximum admin count");
        return EdmReturnErrCode::ENABLE_ADMIN_FAILED;
    }

    Security::AccessToken::AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    if (!GetPermissionChecker()->VerifyCallingPermission(tokenId,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_DEVICE_ADMIN)) {
        EDMLOGW("EnterpriseDeviceMgrAbility::EnableDeviceAdmin check permission failed");
        return EdmReturnErrCode::PERMISSION_DENIED;
    }

    std::vector<AppExecFwk::ExtensionAbilityInfo> abilityInfo;
    AAFwk::Want want;
    want.SetElement(admin);
    if (!GetBundleMgr()->QueryExtensionAbilityInfos(want, AppExecFwk::ExtensionAbilityType::ENTERPRISE_ADMIN,
        AppExecFwk::ExtensionAbilityInfoFlag::GET_EXTENSION_INFO_WITH_PERMISSION,
        EdmConstants::DEFAULT_USER_ID, abilityInfo) || abilityInfo.empty()) {
        EDMLOGW("EnableDeviceAdmin: QueryExtensionAbilityInfos failed");
        return EdmReturnErrCode::COMPONENT_INVALID;
    }
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::EnableDeviceAdmin(const AppExecFwk::ElementName &admin)
{
    EDMLOGD("EnterpriseDeviceMgrAbility::EnableDeviceAdmin");
    Security::AccessToken::AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    std::string callingBundleName = GetPermissionChecker()->GetHapTokenBundleName(tokenId);
    std::unique_lock<std::shared_mutex> autoLock(adminLock_);
    std::shared_ptr<Admin> superAdmin = AdminManager::GetInstance()->GetAdminByPkgName(callingBundleName,
        EdmConstants::DEFAULT_USER_ID);
    if (superAdmin == nullptr) {
        EDMLOGE("EnableDeviceAdmin: the admin is not a super admin.");
        return EdmReturnErrCode::ADMIN_INACTIVE;
    }
    if (!superAdmin->HasPermissionToCallServiceCode(EdmInterfaceCode::ENABLE_DEVICE_ADMIN)) {
        EDMLOGE("EnableDeviceAdmin the admin has no permission.");
        return EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED;
    }
    ErrCode ret = CheckEnableDeviceAdmin(admin);
    if (FAILED(ret)) {
        return ret;
    }
    std::shared_ptr<Admin> existAdmin = AdminManager::GetInstance()->GetAdminByPkgName(admin.GetBundleName(),
        EdmConstants::DEFAULT_USER_ID);
    if (existAdmin != nullptr) {
        if (existAdmin->adminInfo_.adminType_ == AdminType::NORMAL) {
            EDMLOGI("EnableDeviceAdmin the device admin has exist.");
            return ERR_OK;
        } else {
            EDMLOGE("EnableDeviceAdmin the admin has exist but is not a device admin.");
            return EdmReturnErrCode::ENABLE_ADMIN_FAILED;
        }
    }

    /* Get all request and registered permissions */
    std::vector<std::string> permissionList;
    GetPermissionChecker()->GetAllPermissionsByAdmin(admin.GetBundleName(),
        EdmConstants::DEFAULT_USER_ID, permissionList);
    AdminInfo adminInfo = {.packageName_ = admin.GetBundleName(), .className_ = admin.GetAbilityName(),
        .permission_ = permissionList, .adminType_ = AdminType::NORMAL, .isDebug_ = superAdmin->adminInfo_.isDebug_};
    if (FAILED(AdminManager::GetInstance()->SetAdminValue(EdmConstants::DEFAULT_USER_ID, adminInfo))) {
        return EdmReturnErrCode::ENABLE_ADMIN_FAILED;
    }
    int32_t userId = GetCurrentUserId();
    AfterEnableAdmin(admin, AdminType::NORMAL, userId);
    return ERR_OK;
}

void EnterpriseDeviceMgrAbility::AfterEnableAdmin(const AppExecFwk::ElementName &admin, AdminType type, int32_t userId)
{
    system::SetParameter(PARAM_EDM_ENABLE, "true");
    NotifyAdminEnabled(true);
    EDMLOGI("EnableAdmin suc.:%{public}s type:%{public}d", admin.GetBundleName().c_str(), static_cast<uint32_t>(type));
    OnAdminEnabled(admin.GetBundleName(), admin.GetAbilityName(), IEnterpriseAdmin::COMMAND_ON_ADMIN_ENABLED, userId,
        true);
    // 如果是激活DA需要上报给SDA
    std::shared_ptr<Admin> superAdmin = AdminManager::GetInstance()->GetSuperAdmin();
    if (superAdmin != nullptr && type == AdminType::NORMAL) {
        OnAdminEnabled(superAdmin->adminInfo_, IEnterpriseAdmin::COMMAND_ON_DEVICE_ADMIN_ENABLED, userId,
            admin.GetBundleName());
    }
    EdmDataAbilityUtils::UpdateSettingsData(KEY_EDM_DISPLAY, "true");
    std::shared_ptr<Admin> deviceAdmin = AdminManager::GetInstance()->GetAdminByPkgName(admin.GetBundleName(), userId);
    if (deviceAdmin && deviceAdmin->IsDisallowedUninstall()) {
        if (deviceAdmin->IsAllowedAcrossAccountSetPolicy()) {
            AddDisallowUninstallApp(admin.GetBundleName());
        } else {
            AddDisallowUninstallAppForAccount(admin.GetBundleName(), userId);
        }
    }
    EDMLOGD("ReportEdmEventManagerAdmin EnableAdmin");
    HiSysEventAdapter::ReportEdmEventManagerAdmin(admin.GetBundleName().c_str(),
        static_cast<int32_t>(AdminAction::ENABLE), static_cast<int32_t>(type));
}

ErrCode EnterpriseDeviceMgrAbility::RemoveAdminItem(const std::string &adminName, const std::string &policyName,
    const std::string &policyValue, int32_t userId)
{
    PluginManager::GetInstance()->LoadAllPlugin();
    std::shared_ptr<IPlugin> plugin = PluginManager::GetInstance()->GetPluginByPolicyName(policyName);
    if (plugin == nullptr) {
        EDMLOGW("RemoveAdminItem: Get plugin by policy failed: %{public}s\n", policyName.c_str());
        return ERR_EDM_GET_PLUGIN_MGR_FAILED;
    }
    std::string mergedPolicyData;
    plugin->GetOthersMergePolicyData(adminName, userId, mergedPolicyData);
    ErrCode ret = plugin->OnAdminRemove(adminName, policyValue, mergedPolicyData, userId);
    if (ret != ERR_OK) {
        EDMLOGW("RemoveAdminItem: OnAdminRemove failed, admin:%{public}s, value:%{public}s, res:%{public}d\n",
            adminName.c_str(), policyValue.c_str(), ret);
    }
    if (plugin->NeedSavePolicy()) {
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
    EDMLOGD("RemoveAdminAndAdminPolicy:admin: %{public}s.", adminName.c_str());
    ErrCode removeAdminPolicyRet = RemoveAdminPolicy(adminName, userId);
    if (FAILED(removeAdminPolicyRet)) {
        EDMLOGE("Remove admin %{public}s policy fail.", adminName.c_str());
        return removeAdminPolicyRet;
    }

    ErrCode removeAdminRet = RemoveAdmin(adminName, userId);
    if (FAILED(removeAdminRet)) {
        EDMLOGE("Remove admin %{public}s fail.", adminName.c_str());
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

ErrCode EnterpriseDeviceMgrAbility::DisableAdmin(const AppExecFwk::ElementName &admin, int32_t userId)
{
    EDMLOGI("EnterpriseDeviceMgrAbility::DisableAdmin");
    std::unique_lock<std::shared_mutex> autoLock(adminLock_);
    std::shared_ptr<Admin> deviceAdmin = AdminManager::GetInstance()->GetAdminByPkgName(admin.GetBundleName(), userId);
    if (deviceAdmin == nullptr) {
        EDMLOGE("DisableAdmin: %{public}s is not activated", admin.GetBundleName().c_str());
        return EdmReturnErrCode::DISABLE_ADMIN_FAILED;
    }
    auto ret = CheckDisableAdmin(deviceAdmin, deviceAdmin->GetAdminType());
    if (FAILED(ret)) {
        return ret;
    }
    if (deviceAdmin->IsAllowedAcrossAccountSetPolicy()) {
        userId = DEFAULT_USER_ID;
    }
    return DoDisableAdmin(deviceAdmin, userId, deviceAdmin->GetAdminType());
}

ErrCode EnterpriseDeviceMgrAbility::DisableSuperAdmin(const std::string &bundleName)
{
    EDMLOGI("EnterpriseDeviceMgrAbility::DisableSuperAdmin bundle name = %{public}s", bundleName.c_str());
    std::unique_lock<std::shared_mutex> autoLock(adminLock_);
    return DoDisableAdmin(bundleName, EdmConstants::DEFAULT_USER_ID, AdminType::ENT);
}

ErrCode EnterpriseDeviceMgrAbility::CheckDisableAdmin(std::shared_ptr<Admin> admin, AdminType adminType)
{
    bool isDebug = GetPermissionChecker()->CheckIsDebug();
    if (isDebug) {
        if (!admin->adminInfo_.isDebug_) {
            EDMLOGE("CheckDisableAdmin shell command can only remove debug super admin.");
            return EdmReturnErrCode::DISABLE_ADMIN_FAILED;
        }
        return ERR_OK;
    }
    if (admin->adminInfo_.adminType_ != adminType) {
        EDMLOGW("DoDisableAdmin: only remove the certain admin.");
        return EdmReturnErrCode::DISABLE_ADMIN_FAILED;
    }
    Security::AccessToken::AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    std::string requiredPermission = EdmPermission::PERMISSION_MANAGE_ENTERPRISE_DEVICE_ADMIN;
    if (GetPermissionChecker()->VerifyCallingPermission(tokenId, requiredPermission)) {
        return ERR_OK;
    }
    if (GetPermissionChecker()->GetHapTokenBundleName(tokenId) != admin->adminInfo_.packageName_) {
        EDMLOGW("CheckDisableAdmin can only disable self.");
        return EdmReturnErrCode::PERMISSION_DENIED;
    }
    requiredPermission = admin->GetDisableSelfPermission();
    if (requiredPermission == EdmPermission::PERMISSION_DENIED) {
        EDMLOGE("CheckDisableAdmin this admin does not disable self.");
        return EdmReturnErrCode::PERMISSION_DENIED;
    }
    if (!GetPermissionChecker()->VerifyCallingPermission(tokenId, requiredPermission)) {
        EDMLOGE("CheckDisableAdmin VerifyCallingPermission failed.");
        return EdmReturnErrCode::PERMISSION_DENIED;
    }
    return ERR_OK;
}

// non-thread-safe function
ErrCode EnterpriseDeviceMgrAbility::DoDisableAdmin(const std::string &bundleName, int32_t userId, AdminType adminType)
{
    std::shared_ptr<Admin> deviceAdmin = AdminManager::GetInstance()->GetAdminByPkgName(bundleName, userId);
    if (deviceAdmin == nullptr) {
        EDMLOGE("DisableAdmin: %{public}s is not activated", bundleName.c_str());
        return EdmReturnErrCode::DISABLE_ADMIN_FAILED;
    }
    auto ret = CheckDisableAdmin(deviceAdmin, adminType);
    if (FAILED(ret)) {
        return ret;
    }
    if (deviceAdmin->IsAllowedAcrossAccountSetPolicy()) {
        return DoDisableAdmin(deviceAdmin, DEFAULT_USER_ID, adminType);
    }
    return DoDisableAdmin(deviceAdmin, userId, adminType);
}

ErrCode EnterpriseDeviceMgrAbility::DoDisableAdmin(std::shared_ptr<Admin> admin, int32_t userId, AdminType adminType)
{
    if (admin->IsSuperAdmin() && FAILED(RemoveSuperAdminAndAdminPolicy(admin->adminInfo_.packageName_))) {
        EDMLOGW("DoDisableAdmin: remove admin failed.");
        return EdmReturnErrCode::DISABLE_ADMIN_FAILED;
    }
    if (!admin->IsSuperAdmin() && admin->IsAllowedAcrossAccountSetPolicy() &&
        FAILED(RemoveSubSuperAdminAndAdminPolicy(admin->adminInfo_.packageName_))) {
        EDMLOGW("DoDisableAdmin: remove admin failed.");
        return EdmReturnErrCode::DISABLE_ADMIN_FAILED;
    }
    if (!admin->IsAllowedAcrossAccountSetPolicy() &&
        FAILED(RemoveAdminAndAdminPolicy(admin->adminInfo_.packageName_, userId))) {
        EDMLOGW("DoDisableAdmin: disable normal or byod admin failed.");
        return EdmReturnErrCode::DISABLE_ADMIN_FAILED;
    }
    if (!AdminManager::GetInstance()->IsAdminExist()) {
        system::SetParameter(PARAM_EDM_ENABLE, "false");
        NotifyAdminEnabled(false);
        EdmDataAbilityUtils::UpdateSettingsData(KEY_EDM_DISPLAY, "false");
    }
    OnAdminEnabled(admin->adminInfo_.packageName_, admin->adminInfo_.className_,
        IEnterpriseAdmin::COMMAND_ON_ADMIN_DISABLED, userId, true);
    auto superAdmin = AdminManager::GetInstance()->GetSuperAdmin();
    if (superAdmin != nullptr && adminType == AdminType::NORMAL) {
        OnAdminEnabled(superAdmin->adminInfo_, IEnterpriseAdmin::COMMAND_ON_DEVICE_ADMIN_DISABLED,
            userId, admin->adminInfo_.packageName_);
    }
    if (admin->IsDisallowedUninstall()) {
        if (admin->IsAllowedAcrossAccountSetPolicy()) {
            DelDisallowUninstallApp(admin->adminInfo_.packageName_);
        } else {
            DelDisallowUninstallAppForAccount(admin->adminInfo_.packageName_, userId);
        }
    }
    EDMLOGD("ReportEdmEventManagerAdmin DisableAdmin");
    HiSysEventAdapter::ReportEdmEventManagerAdmin(admin->adminInfo_.packageName_.c_str(),
        static_cast<int32_t>(AdminAction::DISABLE), static_cast<int32_t>(adminType));
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::IsSuperAdmin(const std::string &bundleName, bool &isSuper)
{
    isSuper = AdminManager::GetInstance()->IsSuperAdmin(bundleName);
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::DisableDeviceAdmin(const AppExecFwk::ElementName &admin)
{
    EDMLOGI("EnterpriseDeviceMgrAbility::DisableDeviceAdmin");
    std::shared_ptr<Admin> deviceAdmin = AdminManager::GetInstance()->GetAdminByPkgName(admin.GetBundleName(),
        EdmConstants::DEFAULT_USER_ID);
    if (deviceAdmin == nullptr) {
        EDMLOGE("DisableDeviceAdmin: %{public}s is not activated", admin.GetBundleName().c_str());
        return EdmReturnErrCode::DISABLE_ADMIN_FAILED;
    }
    ErrCode ret = CheckDisableDeviceAdmin(deviceAdmin);
    if (FAILED(ret)) {
        return ret;
    }
    std::unique_lock<std::shared_mutex> autoLock(adminLock_);
    return DoDisableAdmin(deviceAdmin, EdmConstants::DEFAULT_USER_ID, AdminType::NORMAL);
}

ErrCode EnterpriseDeviceMgrAbility::CheckDisableDeviceAdmin(std::shared_ptr<Admin> deviceAdmin)
{
    Security::AccessToken::AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    std::string callingBundleName = GetPermissionChecker()->GetHapTokenBundleName(tokenId);
    std::shared_ptr<Admin> superAdmin = AdminManager::GetInstance()->GetAdminByPkgName(callingBundleName,
        EdmConstants::DEFAULT_USER_ID);
    if (superAdmin == nullptr) {
        EDMLOGE("DisableDeviceAdmin the admin is not a super admin");
        return EdmReturnErrCode::ADMIN_INACTIVE;
    }
    if (!superAdmin->HasPermissionToCallServiceCode(EdmInterfaceCode::DISABLE_DEVICE_ADMIN)) {
        EDMLOGE("DisableDeviceAdmin: the admin has no permission");
        return EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED;
    }
    if (!GetPermissionChecker()->VerifyCallingPermission(tokenId,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_DEVICE_ADMIN)) {
        EDMLOGE("CheckDisableDeviceAdmin: check permission failed");
        return EdmReturnErrCode::PERMISSION_DENIED;
    }
    AdminType adminType = deviceAdmin->GetAdminType();
    if (adminType != AdminType::NORMAL) {
        EDMLOGE("CheckDisableDeviceAdmin: this admin is not device admin");
        return EdmReturnErrCode::DISABLE_ADMIN_FAILED;
    }
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::IsByodAdmin(const AppExecFwk::ElementName &admin, bool &isByod)
{
    EDMLOGI("EnterpriseDeviceMgrAbility::IsByodAdmin calling.");
    isByod = false;
    Security::AccessToken::AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    if (!GetPermissionChecker()->VerifyCallingPermission(tokenId, EdmPermission::PERMISSION_GET_ADMINPROVISION_INFO)) {
        EDMLOGE("IsByodAdmin::VerifyCallingPermission check permission failed.");
        return EdmReturnErrCode::PERMISSION_DENIED;
    }
    Security::AccessToken::HapTokenInfo hapTokenInfo;
    std::string bundleName = admin.GetBundleName();
    if (FAILED(Security::AccessToken::AccessTokenKit::GetHapTokenInfo(tokenId, hapTokenInfo)) ||
        hapTokenInfo.bundleName != bundleName) {
        EDMLOGE("IsByodAdmin::calling bundleName is not input bundleName.");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    isByod = AdminManager::GetInstance()->IsByodAdmin(bundleName, GetCurrentUserId());
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::IsAdminEnabled(
    const AppExecFwk::ElementName &admin, int32_t userId, bool &isEnabled)
{
    std::shared_ptr<Admin> existAdmin = AdminManager::GetInstance()->GetAdminByPkgName(admin.GetBundleName(), userId);
    if (existAdmin != nullptr) {
        EDMLOGD("IsAdminEnabled: get admin successed");
        isEnabled = true;
    } else {
        isEnabled = false;
    }
    return ERR_OK;
}

int32_t EnterpriseDeviceMgrAbility::GetCurrentUserId()
{
    std::vector<int32_t> ids;
    ErrCode ret = GetOsAccountMgr()->QueryActiveOsAccountIds(ids);
    if (FAILED(ret) || ids.empty()) {
        EDMLOGE("EnterpriseDeviceMgrAbility GetCurrentUserId failed");
        return -1;
    }
    EDMLOGD("EnterpriseDeviceMgrAbility GetCurrentUserId");
    return (ids.at(0));
}

ErrCode EnterpriseDeviceMgrAbility::UpdateDevicePolicy(uint32_t code, const std::string &bundleName,
    MessageParcel &data, MessageParcel &reply, int32_t userId)
{
    std::shared_ptr<IPlugin> plugin = PluginManager::GetInstance()->GetPluginByFuncCode(code);
    if (plugin == nullptr) {
        EDMLOGW("UpdateDevicePolicy: get plugin failed, code:%{public}d", code);
        return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
    }

    std::string policyName = plugin->GetPolicyName();
    std::string oldCombinePolicy;
    policyMgr_->GetPolicy("", policyName, oldCombinePolicy, userId);
    HandlePolicyData handlePolicyData{"", "", false};
    policyMgr_->GetPolicy(bundleName, policyName, handlePolicyData.policyData, userId);
    plugin->GetOthersMergePolicyData(bundleName, userId, handlePolicyData.mergePolicyData);
    ErrCode ret = plugin->GetExecuteStrategy()->OnSetExecute(code, data, reply, handlePolicyData, userId);
    if (FAILED(ret)) {
        EDMLOGW("UpdateDevicePolicy: OnHandlePolicy failed");
        return ret;
    }
    EDMLOGD("UpdateDevicePolicy: isChanged:%{public}d, needSave:%{public}d", handlePolicyData.isChanged,
        plugin->NeedSavePolicy());
    bool isGlobalChanged = false;
    if (plugin->NeedSavePolicy() && handlePolicyData.isChanged) {
        policyMgr_->SetPolicy(bundleName, policyName, handlePolicyData.policyData, handlePolicyData.mergePolicyData,
            userId);
        isGlobalChanged = (oldCombinePolicy != handlePolicyData.mergePolicyData);
    }
    plugin->OnHandlePolicyDone(code, bundleName, isGlobalChanged, userId);
    EDMLOGI("UpdateDevicePolicy: handle policy success.");
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::HandleDevicePolicy(uint32_t code, AppExecFwk::ElementName &admin,
    MessageParcel &data, MessageParcel &reply, int32_t userId)
{
    auto loadRet = PluginManager::GetInstance()->LoadPluginByFuncCode(code);
    if (loadRet != ERR_OK) {
        return loadRet;
    }
    std::shared_ptr<IPlugin> plugin = PluginManager::GetInstance()->GetPluginByFuncCode(code);
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
    EDMLOGI("HandleDevicePolicy: HandleDevicePolicy");
    std::unique_lock<std::shared_mutex> autoLock(adminLock_);
    std::shared_ptr<Admin> deviceAdmin = AdminManager::GetInstance()->GetAdminByPkgName(admin.GetBundleName(),
        GetCurrentUserId());
    if (deviceAdmin == nullptr) {
        EDMLOGE("HandleDevicePolicy: %{public}s is not activated", admin.GetBundleName().c_str());
        return EdmReturnErrCode::ADMIN_INACTIVE;
    }
    int uid = IPCSkeleton::GetCallingUid();
    std::string permissionTag = data.ReadString();
    if (uid != EDM_UID) {
        std::string setPermission = plugin->GetPermission(FuncOperateType::SET,
            GetPermissionChecker()->AdminTypeToPermissionType(deviceAdmin->GetAdminType()), permissionTag);
        EDMLOGD("HandleDevicePolicy: HandleDevicePolicy GetPermission = %{public}s", setPermission.c_str());
        ErrCode checkAdminPermission = GetPermissionChecker()->CheckHandlePolicyPermission(FuncOperateType::SET,
            deviceAdmin, plugin->GetPolicyName(), setPermission, userId);
        if (FAILED(checkAdminPermission)) {
            return checkAdminPermission;
        }
    }
#endif
    ReportFuncEvent(code);
    ErrCode ret = UpdateDevicePolicy(code, admin.GetBundleName(), data, reply, userId);
    ReportInfo info = ReportInfo(FuncCodeUtils::GetOperateType(code), plugin->GetPolicyName(), std::to_string(ret));
    SecurityReport::ReportSecurityInfo(admin.GetBundleName(), admin.GetAbilityName(), info, false);
    return ret;
}

void EnterpriseDeviceMgrAbility::ReportFuncEvent(uint32_t code)
{
    std::uint32_t ipcCode = FuncCodeUtils::GetPolicyCode(code);
    std::string apiNameParam = std::to_string(ipcCode);
    HiSysEventAdapter::ReportEdmEvent(ReportType::EDM_FUNC_EVENT, apiNameParam);
}

ErrCode EnterpriseDeviceMgrAbility::GetDevicePolicy(uint32_t code, MessageParcel &data, MessageParcel &reply,
    int32_t userId, int32_t hasUserId)
{
    if (hasUserId != 0) {
        bool isUserExist = false;
        GetOsAccountMgr()->IsOsAccountExists(userId, isUserExist);
        if (!isUserExist) {
            EDMLOGW("GetDevicePolicy: IsOsAccountExists failed");
            return EdmReturnErrCode::PARAM_ERROR;
        }
    }

    std::shared_lock<std::shared_mutex> autoLock(adminLock_);
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
    auto loadRet = PluginManager::GetInstance()->LoadPluginByFuncCode(code);
    if (loadRet != ERR_OK) {
        return loadRet;
    }
    std::shared_ptr<IPlugin> plugin = PluginManager::GetInstance()->GetPluginByFuncCode(code);
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
        ErrCode errCode = CheckGetPolicyParam(data, plugin, elementName, permissionTag, userId);
        if (errCode != ERR_OK) {
            return errCode;
        }
    } else {
        std::string getPermission = plugin->GetPermission(FuncOperateType::GET,
            IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag);
        if (!PermissionChecker::GetInstance()->CheckElementNullPermission(code, getPermission)) {
            EDMLOGE("GetDevicePolicy: permission check failed");
            return EdmReturnErrCode::PERMISSION_DENIED;
        }
    }
    std::string policyName = plugin->GetPolicyName();
    std::string policyValue;

    if (plugin->NeedSavePolicy()) {
        policyMgr_->GetPolicy(elementName.GetBundleName(), policyName, policyValue, userId);
    }
    ErrCode getRet = plugin->GetExecuteStrategy()->OnGetExecute(code, policyValue, data, reply, userId);
    ReportInfo info = ReportInfo(FuncCodeUtils::GetOperateType(code), plugin->GetPolicyName(), std::to_string(getRet));
    SecurityReport::ReportSecurityInfo(elementName.GetBundleName(), elementName.GetAbilityName(), info, true);
    return getRet;
}

ErrCode EnterpriseDeviceMgrAbility::CheckGetPolicyParam(MessageParcel &data, std::shared_ptr<IPlugin> &plugin,
    AppExecFwk::ElementName &elementName, const std::string &permissionTag, int32_t userId)
{
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
        deviceAdmin, plugin->GetPolicyName(), getPermission, userId);
    if (FAILED(ret)) {
        return ret;
    }
#endif
    elementName.SetBundleName(admin->GetBundleName());
    elementName.SetAbilityName(admin->GetAbilityName());
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::CheckAndGetAdminProvisionInfo(uint32_t code, MessageParcel &data,
    MessageParcel &reply, int32_t userId)
{
    std::unique_ptr<AppExecFwk::ElementName> admin(data.ReadParcelable<AppExecFwk::ElementName>());
    if (!admin) {
        EDMLOGW("CheckAndGetAdminProvisionInfo: ReadParcelable failed");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    EDMLOGD("CheckAndGetAdminProvisionInfo bundleName: %{public}s, abilityName : %{public}s ",
        admin->GetBundleName().c_str(), admin->GetAbilityName().c_str());

    Security::AccessToken::AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    if (!GetPermissionChecker()->VerifyCallingPermission(tokenId, EdmPermission::PERMISSION_GET_ADMINPROVISION_INFO)) {
        EDMLOGE("CheckAndGetAdminProvisionInfo::VerifyCallingPermission check permission failed.");
        return EdmReturnErrCode::PERMISSION_DENIED;
    }
    Security::AccessToken::HapTokenInfo hapTokenInfo;
    if (FAILED(Security::AccessToken::AccessTokenKit::GetHapTokenInfo(tokenId, hapTokenInfo)) ||
        hapTokenInfo.bundleName != admin->GetBundleName()) {
        EDMLOGE("CheckAndGetAdminProvisionInfo::calling bundleName is not input bundleName.");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::vector<AppExecFwk::ExtensionAbilityInfo> abilityInfo;
    AAFwk::Want want;
    want.SetElement(*admin);
    if (!GetBundleMgr()->QueryExtensionAbilityInfos(want, AppExecFwk::ExtensionAbilityType::ENTERPRISE_ADMIN,
        AppExecFwk::ExtensionAbilityInfoFlag::GET_EXTENSION_INFO_WITH_PERMISSION, userId, abilityInfo) ||
        abilityInfo.empty()) {
        EDMLOGW("CheckAndGetAdminProvisionInfo: QueryExtensionAbilityInfos failed");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    auto loadRet = PluginManager::GetInstance()->LoadPluginByFuncCode(code);
    if (loadRet != ERR_OK) {
        return loadRet;
    }
    std::shared_ptr<IPlugin> plugin = PluginManager::GetInstance()->GetPluginByFuncCode(code);
    if (plugin == nullptr) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (AdminManager::GetInstance()->IsAdminExist()) {
        EDMLOGE("CheckAndGetAdminProvisionInfo::device exist admin.");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::string policyValue;
    AppExecFwk::ElementName elementName;
    ErrCode getRet = plugin->GetExecuteStrategy()->OnGetExecute(code, policyValue, data, reply, userId);
    ReportInfo info = ReportInfo(FuncCodeUtils::GetOperateType(code), plugin->GetPolicyName(), std::to_string(getRet));
    SecurityReport::ReportSecurityInfo(elementName.GetBundleName(), elementName.GetAbilityName(), info, false);
    return getRet;
}

ErrCode EnterpriseDeviceMgrAbility::ReportAgInstallStatus(const std::string &bundleName,
    const std::string &mediaBundleName, int32_t status)
{
    EDMLOGI("EnterpriseMgrAbility::ReportAgInstallStatus start, bundleName %{public}s status %{public}d",
        bundleName.c_str(), status);
#ifndef EDM_FUZZ_TEST
    if (IPCSkeleton::GetCallingUid() != EDM_UID) {
        EDMLOGE("ReportAgInstallStatus::VerifyCallingPermission check permission failed.");
        return EdmReturnErrCode::PERMISSION_DENIED;
    }
#endif
    std::vector<std::shared_ptr<Admin>> admins;
    int32_t currentUserId = GetCurrentUserId();
    if (currentUserId < 0) {
        return ERR_OK;
    }
    AdminManager::GetInstance()->GetAdmins(admins, currentUserId);
    for (const auto& admin : admins) {
        if (admin->adminInfo_.packageName_ != mediaBundleName) {
            continue;
        }
        EDMLOGI("ReportAgInstallStatus packageName:%{public}s", admin->adminInfo_.packageName_.c_str());
        AAFwk::Want connectWant;
        connectWant.SetElementName(admin->adminInfo_.packageName_, admin->adminInfo_.className_);
        std::shared_ptr<EnterpriseConnManager> manager = DelayedSingleton<EnterpriseConnManager>::GetInstance();
        bool ret = manager->CreateMarketConnection(connectWant,
            static_cast<uint32_t>(IEnterpriseAdmin::COMMAND_ON_MARKET_INSTALL_STATUS_CHANGED),
            currentUserId, bundleName, status);
        if (!ret) {
            EDMLOGW("EnterpriseDeviceMgrAbility::ReportAgInstallStatus CreateMarketConnection failed.");
        }
    }
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::GetEnabledAdmin(AdminType adminType, std::vector<std::string> &enabledAdminList)
{
    std::shared_lock<std::shared_mutex> autoLock(adminLock_);
    std::vector<std::string> superList;
    std::vector<std::string> normalList;
    std::vector<std::string> byodList;
    switch (adminType) {
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

ErrCode EnterpriseDeviceMgrAbility::GetEnterpriseInfo(const AppExecFwk::ElementName &admin, EntInfo &entInfo)
{
    std::shared_lock<std::shared_mutex> autoLock(adminLock_);
    auto adminItem = AdminManager::GetInstance()->GetAdminByPkgName(admin.GetBundleName(),  GetCurrentUserId());
    if (adminItem == nullptr) {
        return EdmReturnErrCode::ADMIN_INACTIVE;
    }
    entInfo = adminItem->adminInfo_.entInfo_;
    EDMLOGD(
        "EnterpriseDeviceMgrAbility::GetEnterpriseInfo: entInfo->enterpriseName %{public}s, "
        "entInfo->description:%{public}s",
        entInfo.enterpriseName.c_str(), entInfo.description.c_str());
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::SetEnterpriseInfo(const AppExecFwk::ElementName &admin, const EntInfo &entInfo)
{
    std::unique_lock<std::shared_mutex> autoLock(adminLock_);
    int32_t userId = GetCurrentUserId();
    std::shared_ptr<Admin> adminItem = AdminManager::GetInstance()->GetAdminByPkgName(admin.GetBundleName(), userId);
    if (adminItem == nullptr) {
        return EdmReturnErrCode::ADMIN_INACTIVE;
    }
    if (!GetPermissionChecker()->CheckCallerPermission(adminItem->adminInfo_.packageName_,
        EdmPermission::PERMISSION_SET_ENTERPRISE_INFO)) {
        return EdmReturnErrCode::PERMISSION_DENIED;
    }
    if (adminItem->IsAllowedAcrossAccountSetPolicy()) {
        userId = EdmConstants::DEFAULT_USER_ID;
    }
    ErrCode code = AdminManager::GetInstance()->SetEntInfo(adminItem, entInfo, userId);
    return (code != ERR_OK) ? EdmReturnErrCode::ADMIN_INACTIVE : ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::SetAdminRunningMode(const AppExecFwk::ElementName &admin, uint32_t runningMode)
{
    std::unique_lock<std::shared_mutex> autoLock(adminLock_);
    int32_t userId = GetCurrentUserId();
    std::shared_ptr<Admin> adminItem = AdminManager::GetInstance()->GetAdminByPkgName(admin.GetBundleName(), userId);
    if (adminItem == nullptr) {
        return EdmReturnErrCode::ADMIN_INACTIVE;
    }
    Security::AccessToken::AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    if (!GetPermissionChecker()->VerifyCallingPermission(tokenId,
        EdmPermission::PERMISSION_MANAGE_ENTERPRISE_DEVICE_ADMIN)) {
        EDMLOGW("EnterpriseDeviceMgrAbility::SetAdminRunningMode check permission failed");
        return EdmReturnErrCode::PERMISSION_DENIED;
    }
    if (!CheckRunningMode(runningMode)) {
        return EdmReturnErrCode::PARAM_ERROR;
    }
    adminItem->adminInfo_.runningMode_ = static_cast<RunningMode>(runningMode);
    return AdminManager::GetInstance()->SetAdminValue(EdmConstants::DEFAULT_USER_ID, adminItem->adminInfo_);
}

bool EnterpriseDeviceMgrAbility::CheckRunningMode(uint32_t runningMode)
{
    if (runningMode >= static_cast<uint32_t>(RunningMode::DEFAULT) &&
        runningMode <= static_cast<uint32_t>(RunningMode::MULTI_USER)) {
        return true;
    }
    return false;
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
    std::unique_lock<std::shared_mutex> autoLock(adminLock_);
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
    std::unique_lock<std::shared_mutex> autoLock(adminLock_);
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
    if (adminItem == nullptr) {
        return EdmReturnErrCode::ADMIN_INACTIVE;
    }
    if (!adminItem->HasPermissionToCallServiceCode(EdmInterfaceCode::SUBSCRIBE_MANAGED_EVENT)) {
        return EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED;
    }
    if (!GetPermissionChecker()->CheckCallerPermission(adminItem->adminInfo_.packageName_,
        EdmPermission::PERMISSION_ENTERPRISE_SUBSCRIBE_MANAGED_EVENT)) {
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
    if (event >= static_cast<uint32_t>(ManagedEvent::BUNDLE_ADDED) &&
        event <= static_cast<uint32_t>(ManagedEvent::USER_REMOVED)) {
        return true;
    }
    return false;
}

ErrCode EnterpriseDeviceMgrAbility::AuthorizeAdmin(const AppExecFwk::ElementName &admin, const std::string &bundleName)
{
    std::unique_lock<std::shared_mutex> autoLock(adminLock_);
    std::shared_ptr<Admin> adminItem = AdminManager::GetInstance()->GetAdminByPkgName(admin.GetBundleName(),
        GetCurrentUserId());
    if (adminItem == nullptr) {
        return EdmReturnErrCode::ADMIN_INACTIVE;
    }
    if (!adminItem->HasPermissionToCallServiceCode(EdmInterfaceCode::AUTHORIZE_ADMIN)) {
        return EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED;
    }
    if (!GetPermissionChecker()->VerifyCallingPermission(IPCSkeleton::GetCallingTokenID(),
        EdmPermission::PERMISSION_MANAGE_ENTERPRISE_DEVICE_ADMIN)) {
        return EdmReturnErrCode::PERMISSION_DENIED;
    }
    /* Get all request and registered permissions */
    std::vector<std::string> permissionList;
    if (FAILED(GetPermissionChecker()->GetAllPermissionsByAdmin(bundleName, EdmConstants::DEFAULT_USER_ID,
        permissionList))) {
        EDMLOGW("AuthorizeAdmin: GetAllPermissionsByAdmin failed.");
        return EdmReturnErrCode::AUTHORIZE_PERMISSION_FAILED;
    }
    std::string abilityName = GetExtensionEnterpriseAdminName(bundleName, EdmConstants::DEFAULT_USER_ID);
    AdminInfo subAdminInfo = {.packageName_ = bundleName, .className_ = abilityName,
        .permission_ = permissionList, .parentAdminName_ = admin.GetBundleName(),
        .adminType_ = AdminType::SUB_SUPER_ADMIN, .isDebug_ = adminItem->adminInfo_.isDebug_};
    ErrCode ret = AdminManager::GetInstance()->SetAdminValue(EdmConstants::DEFAULT_USER_ID, subAdminInfo);
    if (ret != ERR_OK) {
        return ret;
    }
    OnAdminEnabled(bundleName, abilityName, IEnterpriseAdmin::COMMAND_ON_ADMIN_ENABLED,
        EdmConstants::DEFAULT_USER_ID, true);
    EDMLOGD("ReportEdmEventManagerAdmin AuthorizeAdmin");
    HiSysEventAdapter::ReportEdmEventManagerAdmin(bundleName, static_cast<int32_t>(AdminAction::ENABLE),
        static_cast<int32_t>(AdminType::SUB_SUPER_ADMIN), admin.GetBundleName().c_str());
    return ret;
}

std::string EnterpriseDeviceMgrAbility::GetExtensionEnterpriseAdminName(const std::string &bundleName, int32_t userId)
{
    AppExecFwk::BundleInfo bundleInfo;
    bool ret = GetBundleMgr()->GetBundleInfoV9(bundleName,
        static_cast<uint32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) |
        static_cast<uint32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_EXTENSION_ABILITY),
        bundleInfo, userId);
    if (!ret) {
        return "";
    }
    for (const auto &hapModuleInfo : bundleInfo.hapModuleInfos) {
        for (const auto &extensionInfo : hapModuleInfo.extensionInfos) {
            if (extensionInfo.type == AppExecFwk::ExtensionAbilityType::ENTERPRISE_ADMIN) {
                return extensionInfo.name;
            }
        }
    }
    return "";
}

ErrCode EnterpriseDeviceMgrAbility::GetSuperAdmin(std::string &bundleName, std::string &abilityName)
{
    std::shared_lock<std::shared_mutex> autoLock(adminLock_);
    auto superAdmin = AdminManager::GetInstance()->GetSuperAdmin();
    if (superAdmin == nullptr) {
        bundleName = "";
        abilityName = "";
    } else {
        bundleName = superAdmin->adminInfo_.packageName_;
        abilityName = superAdmin->adminInfo_.className_;
    }
    return ERR_OK;
}

bool EnterpriseDeviceMgrAbility::CheckDelegatedBundle(const std::string &bundleName, int32_t userId)
{
    if (!GetBundleMgr()->IsBundleInstalled(bundleName, userId)) {
        EDMLOGE("SetDelegatedPolicies the delegated application does not installed.");
        return false;
    }
    std::string appDistributionType = GetBundleMgr()->GetApplicationInfo(bundleName, userId);
    if (appDistributionType != APP_TYPE_ENTERPRISE_MDM && appDistributionType != APP_TYPE_ENTERPRISE_NORMAL) {
        EDMLOGE("SetDelegatedPolicies get appDistributionType %{public}s.", appDistributionType.c_str());
        return false;
    }
    return true;
}

ErrCode EnterpriseDeviceMgrAbility::DisableVirtualAdmin(const std::string &bundleName, const std::string &parentName)
{
    EDMLOGW("SetDelegatedPolicies remove delegated policies.");
    ErrCode res = RemoveSubSuperAdminAndAdminPolicy(bundleName);
    if (res == ERR_OK) {
        HiSysEventAdapter::ReportEdmEventManagerAdmin(bundleName, static_cast<int32_t>(AdminAction::DISABLE),
            static_cast<int32_t>(AdminType::VIRTUAL_ADMIN), parentName);
    }
    return res;
}

ErrCode EnterpriseDeviceMgrAbility::SetDelegatedPolicies(const std::string &bundleName,
    const std::vector<std::string> &policies, int32_t userId)
{
    std::unique_lock<std::shared_mutex> autoLock(adminLock_);
    Security::AccessToken::AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    if (!GetPermissionChecker()->VerifyCallingPermission(tokenId,
        EdmPermission::PERMISSION_MANAGE_ENTERPRISE_DEVICE_ADMIN)) {
        EDMLOGW("EnterpriseDeviceMgrAbility::SetDelegatedPolicies check permission failed");
        return EdmReturnErrCode::PERMISSION_DENIED;
    }
    std::vector<std::string> setPolicies = policies;
    if (setPolicies.size() > EdmConstants::POLICIES_MAX_SIZE) {
            return EdmReturnErrCode::PARAM_ERROR;
    }
    for (const std::string &policy : setPolicies) {
        if (!GetPermissionChecker()->IsAllowDelegatedPolicy(policy)) {
            return EdmReturnErrCode::PARAM_ERROR;
        }
    }
    std::shared_ptr<Admin> adminItem = AdminManager::GetInstance()->GetAdminByPkgName(bundleName, userId);
    if (adminItem != nullptr) {
        return ERR_EDM_ADD_ADMIN_FAILED;
    }
    if (!CheckDelegatedBundle(bundleName, userId)) {
        return EdmReturnErrCode::AUTHORIZE_PERMISSION_FAILED;
    }
    if (std::find(setPolicies.begin(), setPolicies.end(), POLICY_ALLOW_ALL) != setPolicies.end()) {
        setPolicies = { POLICY_ALLOW_ALL };
    }
    int uid = IPCSkeleton::GetCallingUid();
    std::string callingBundleName;
    if (GetExternalManagerFactory()->CreateBundleManager()->GetNameForUid(uid, callingBundleName) != ERR_OK) {
        EDMLOGW("SetDelegatedPolicies CheckCallingUid failed: get bundleName for uid %{public}d fail.", uid);
        return ERR_EDM_PERMISSION_ERROR;
    }
    /* Get all request and registered permissions */
    std::vector<std::string> permissionList;
    if (FAILED(GetPermissionChecker()->GetAllPermissionsByAdmin(bundleName, userId, permissionList))) {
        return EdmReturnErrCode::AUTHORIZE_PERMISSION_FAILED;
    }
    AdminInfo virtualAdminInfo = {.packageName_ = bundleName,
        .permission_ = permissionList, .parentAdminName_ = callingBundleName, .accessiblePolicies_ = setPolicies,
        .adminType_ = AdminType::VIRTUAL_ADMIN, .isDebug_ = false};
    system::SetParameter(PARAM_EDM_ENABLE, "true");
    NotifyAdminEnabled(true);
    return AdminManager::GetInstance()->SetAdminValue(userId, virtualAdminInfo);
}

ErrCode EnterpriseDeviceMgrAbility::SetDelegatedPolicies(const AppExecFwk::ElementName &parentAdmin,
    const std::string &bundleName, const std::vector<std::string> &policies)
{
    if (policies.size() > EdmConstants::POLICIES_MAX_SIZE) {
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::unique_lock<std::shared_mutex> autoLock(adminLock_);
    std::string parentAdminName = parentAdmin.GetBundleName();
    std::shared_ptr<Admin> adminItem = AdminManager::GetInstance()->GetAdminByPkgName(parentAdminName,
        GetCurrentUserId());
    if (adminItem == nullptr) {
        return EdmReturnErrCode::ADMIN_INACTIVE;
    }
    if (!adminItem->HasPermissionToCallServiceCode(EdmInterfaceCode::SET_DELEGATED_POLICIES)) {
        return EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED;
    }
    if (!GetPermissionChecker()->CheckCallerPermission(parentAdminName,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_DELEGATED_POLICY)) {
        return EdmReturnErrCode::PERMISSION_DENIED;
    }
    if (parentAdminName == bundleName) {
        EDMLOGE("SetDelegatedPolicies does not delegated policies to self.");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    if (policies.empty()) {
        return DisableVirtualAdmin(bundleName, parentAdminName);
    }
    ErrCode ret = CheckDelegatedPolicies(adminItem->GetAdminType(), policies);
    if (FAILED(ret)) {
        return ret;
    }
    if (!CheckDelegatedBundle(bundleName, GetCurrentUserId())) {
        return EdmReturnErrCode::AUTHORIZE_PERMISSION_FAILED;
    }
    /* Get all request and registered permissions */
    std::vector<std::string> permissionList;
    if (FAILED(GetPermissionChecker()->GetAllPermissionsByAdmin(bundleName, GetCurrentUserId(), permissionList))) {
        return EdmReturnErrCode::AUTHORIZE_PERMISSION_FAILED;
    }
    AdminInfo virtualAdminInfo = {.packageName_ = bundleName, .permission_ = permissionList,
        .parentAdminName_ = parentAdminName, .accessiblePolicies_ = policies, .adminType_ = AdminType::VIRTUAL_ADMIN,
        .isDebug_ = adminItem->adminInfo_.isDebug_};
    ret = AdminManager::GetInstance()->SetAdminValue(GetCurrentUserId(), virtualAdminInfo);
    if (ret == ERR_OK) {
        HiSysEventAdapter::ReportEdmEventManagerAdmin(bundleName, static_cast<int32_t>(AdminAction::ENABLE),
            static_cast<int32_t>(AdminType::VIRTUAL_ADMIN), parentAdminName);
    }
    return ret;
}

ErrCode EnterpriseDeviceMgrAbility::GetDelegatedPolicies(const AppExecFwk::ElementName &parentAdmin,
    const std::string &bundleName, std::vector<std::string> &policies)
{
    std::shared_lock<std::shared_mutex> autoLock(adminLock_);
    std::string parentAdminName = parentAdmin.GetBundleName();
    std::shared_ptr<Admin> adminItem = AdminManager::GetInstance()->GetAdminByPkgName(parentAdminName,
        GetCurrentUserId());
    if (adminItem == nullptr) {
        return EdmReturnErrCode::ADMIN_INACTIVE;
    }
    if (!adminItem->HasPermissionToCallServiceCode(EdmInterfaceCode::GET_DELEGATED_POLICIES)) {
        return EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED;
    }
    if (!GetPermissionChecker()->CheckCallerPermission(parentAdminName,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_DELEGATED_POLICY)) {
        return EdmReturnErrCode::PERMISSION_DENIED;
    }
    return AdminManager::GetInstance()->GetPoliciesByVirtualAdmin(bundleName, parentAdminName, policies);
}

ErrCode EnterpriseDeviceMgrAbility::GetDelegatedBundleNames(const AppExecFwk::ElementName &parentAdmin,
    const std::string &policyName, std::vector<std::string> &bundleNames)
{
    if (!GetPermissionChecker()->IsAllowDelegatedPolicy(policyName)) {
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::string parentAdminName = parentAdmin.GetBundleName();
    std::shared_lock<std::shared_mutex> autoLock(adminLock_);
    std::shared_ptr<Admin> adminItem = AdminManager::GetInstance()->GetAdminByPkgName(parentAdminName,
        GetCurrentUserId());
    if (adminItem == nullptr) {
        return EdmReturnErrCode::ADMIN_INACTIVE;
    }
    if (!adminItem->HasPermissionToCallServiceCode(EdmInterfaceCode::GET_DELEGATED_BUNDLE_NAMES)) {
        return EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED;
    }
    if (!GetPermissionChecker()->CheckCallerPermission(parentAdminName,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_DELEGATED_POLICY)) {
        return EdmReturnErrCode::PERMISSION_DENIED;
    }
    AdminManager::GetInstance()->GetVirtualAdminsByPolicy(policyName, parentAdminName, bundleNames);
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::CheckDelegatedPolicies(AdminType adminType,
    const std::vector<std::string> &policies)
{
    PluginManager::GetInstance()->LoadAllPlugin();
    for (const std::string &policy : policies) {
        if (!GetPermissionChecker()->IsAllowDelegatedPolicy(policy)) {
            return EdmReturnErrCode::PARAM_ERROR;
        }
        auto plugin = PluginManager::GetInstance()->GetPluginByPolicyName(policy);
        if (plugin == nullptr) {
            EDMLOGE("CheckDelegatedPolicies get policyName is not exist.");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        auto permission = plugin->GetPermission(FuncOperateType::SET,
            GetPermissionChecker()->AdminTypeToPermissionType(adminType));
        if (permission == NONE_PERMISSION_MATCH) {
            permission = plugin->GetPermission(FuncOperateType::SET,
                GetPermissionChecker()->AdminTypeToPermissionType(adminType),
                EdmConstants::PERMISSION_TAG_VERSION_12);
        }
        if (permission.empty() || permission == NONE_PERMISSION_MATCH) {
            EDMLOGE("CheckDelegatedPolicies get plugin access permission failed.");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        if (!GetPermissionChecker()->VerifyCallingPermission(IPCSkeleton::GetCallingTokenID(), permission)) {
            return EdmReturnErrCode::PERMISSION_DENIED;
        }
    }
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrAbility::UnloadInstallMarketAppsPlugin()
{
    EDMLOGI("EnterpriseDeviceMgrAbility::UnloadInstallMarketAppsPlugin on start.");
#ifndef EDM_FUZZ_TEST
    if (IPCSkeleton::GetCallingUid() != EDM_UID) {
        EDMLOGW("EnterpriseDeviceMgrAbility::UnloadInstallMarketAppsPlugin check permission failed");
        return EdmReturnErrCode::PERMISSION_DENIED;
    }
#endif
    auto plugin = PluginManager::GetInstance()->GetPluginByCode(INSTALL_MARKET_APPS_PLUGIN_CODE);
    if (plugin == nullptr) {
        EDMLOGE("get Plugin fail %{public}d", INSTALL_MARKET_APPS_PLUGIN_CODE);
        return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
    }
    plugin->SetPluginUnloadFlag(true);
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

ErrCode EnterpriseDeviceMgrAbility::SetBundleInstallPolicies(const std::vector<std::string> &bundles, int32_t userId,
    int32_t policyType)
{
    std::unique_lock<std::shared_mutex> autoLock(adminLock_);
    if (policyType < 0 || policyType > MAX_POLICY_TYPE) {
        EDMLOGE("SetBundleInstallPolicies policy type is abnormal, value : %{public}d.", policyType);
        return EdmReturnErrCode::PARAM_ERROR;
    }
    Security::AccessToken::AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    if (GetPermissionChecker()->VerifyCallingPermission(tokenId,
        EdmPermission::PERMISSION_MANAGE_ENTERPRISE_DEVICE_ADMIN) && IPCSkeleton::GetCallingUid() == EDC_UID) {
        auto ruleMap = std::vector<AppExecFwk::AppInstallControlRuleType> {
            AppExecFwk::AppInstallControlRuleType::UNSPECIFIED,
            AppExecFwk::AppInstallControlRuleType::DISALLOWED_UNINSTALL,
            AppExecFwk::AppInstallControlRuleType::ALLOWED_INSTALL,
            AppExecFwk::AppInstallControlRuleType::DISALLOWED_INSTALL,
        };
        AppExecFwk::AppInstallControlRuleType rule = ruleMap[policyType];
        std::vector<std::string> data = bundles;
        return GetBundleMgr()->AddAppInstallControlRule(data, rule, userId);
    }
    return EdmReturnErrCode::PERMISSION_DENIED;
}

} // namespace EDM
} // namespace OHOS