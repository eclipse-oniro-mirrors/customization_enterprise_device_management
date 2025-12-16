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

#ifndef SERVICES_EDM_INCLUDE_EDM_ENTERPRISE_DEVICE_MGR_ABILITY_H
#define SERVICES_EDM_INCLUDE_EDM_ENTERPRISE_DEVICE_MGR_ABILITY_H

#include <chrono>
#include <condition_variable>
#include <memory>
#include <string>

#include "admin_manager.h"
#include "app_control_interface.h"
#include "common_event_subscriber.h"
#include "enterprise_admin_proxy.h"
#include "enterprise_device_mgr_stub.h"
#include "extra_policy_notification.h"
#include "hilog/log.h"
#include "plugin_manager.h"
#include "policy_manager.h"
#include "policy_struct.h"
#include "security_report.h"
#include "system_ability.h"
#include "watermark_observer_manager.h"

namespace OHOS {
namespace EDM {
class EnterpriseDeviceMgrAbility : public SystemAbility, public EnterpriseDeviceMgrStub {
    DECLARE_SYSTEM_ABILITY(EnterpriseDeviceMgrAbility);

public:
    EnterpriseDeviceMgrAbility();
    DISALLOW_COPY_AND_MOVE(EnterpriseDeviceMgrAbility);
    ~EnterpriseDeviceMgrAbility() override;
    static sptr<EnterpriseDeviceMgrAbility> GetInstance();
    ErrCode EnableAdmin(
        const AppExecFwk::ElementName &admin, const EntInfo &entInfo, AdminType adminType, int32_t userId) override;
    ErrCode DisableAdmin(const AppExecFwk::ElementName &admin, int32_t userId) override;
    ErrCode DisableSuperAdmin(const std::string &bundleName) override;
    ErrCode GetEnabledAdmin(AdminType adminType, std::vector<std::string> &enabledAdminList) override;
    ErrCode GetEnterpriseInfo(const AppExecFwk::ElementName &admin, EntInfo &entInfo) override;
    ErrCode SetEnterpriseInfo(const AppExecFwk::ElementName &admin, const EntInfo &entInfo) override;
    ErrCode IsSuperAdmin(const std::string &bundleName, bool &isSuper) override;
    ErrCode IsByodAdmin(const AppExecFwk::ElementName &admin, bool &isByod) override;
    ErrCode IsAdminEnabled(const AppExecFwk::ElementName &admin, int32_t userId, bool &isEnabled) override;
    ErrCode SubscribeManagedEvent(const AppExecFwk::ElementName &admin, const std::vector<uint32_t> &events) override;
    ErrCode UnsubscribeManagedEvent(const AppExecFwk::ElementName &admin, const std::vector<uint32_t> &events) override;
    ErrCode AuthorizeAdmin(const AppExecFwk::ElementName &admin, const std::string &bundleName) override;
    ErrCode GetSuperAdmin(std::string &bundleName, std::string &abilityName) override;
    ErrCode SetDelegatedPolicies(const AppExecFwk::ElementName &parentAdmin, const std::string &bundleName,
        const std::vector<std::string> &policies) override;
    ErrCode GetDelegatedPolicies(const AppExecFwk::ElementName &parentAdmin, const std::string &bundleName,
        std::vector<std::string> &policies) override;
    ErrCode GetDelegatedBundleNames(const AppExecFwk::ElementName &parentAdmin, const std::string &policyName,
        std::vector<std::string> &bundleNames) override;
    ErrCode ReplaceSuperAdmin(const AppExecFwk::ElementName &oldAdmin, const AppExecFwk::ElementName &newAdmin,
        bool keepPolicy) override;
    ErrCode GetAdmins(std::vector<std::shared_ptr<AAFwk::Want>> &wants) override;
    ErrCode SetAdminRunningMode(const AppExecFwk::ElementName &admin, uint32_t runningMode) override;
    ErrCode SetDelegatedPolicies(const std::string &bundleName,
        const std::vector<std::string> &policies, int32_t userId) override;
    ErrCode SetBundleInstallPolicies(const std::vector<std::string> &bundles, int32_t userId,
        int32_t policyType) override;
    ErrCode UnloadInstallMarketAppsPlugin() override;
    ErrCode EnableDeviceAdmin(const AppExecFwk::ElementName &admin) override;
    ErrCode DisableDeviceAdmin(const AppExecFwk::ElementName &admin) override;
    ErrCode GetEnterpriseManagedTips(std::string &tips) override;

    ErrCode HandleDevicePolicy(uint32_t code, AppExecFwk::ElementName &admin, MessageParcel &data, MessageParcel &reply,
        int32_t userId) override;
    ErrCode GetDevicePolicy(uint32_t code, MessageParcel &data, MessageParcel &reply, int32_t userId,
        int32_t hasUserId = 1) override;
    ErrCode CheckAndGetAdminProvisionInfo(uint32_t code, MessageParcel &data, MessageParcel &reply, int32_t userId)
        override;
    ErrCode ReportAgInstallStatus(const std::string &bundleName,
        const std::string &mediaBundleName, int32_t status) override;
    ErrCode StartAbilityByAdmin(const AppExecFwk::ElementName &admin, const AAFwk::Want &want,
        const sptr<IRemoteObject> &callerToken) override;
    void ConnectAbilityOnSystemEvent(const std::string &bundleName, ManagedEvent event, int32_t userId = 100);
    void ConnectAbility(const int32_t accountId, std::shared_ptr<Admin> admin);
    std::unordered_map<std::string,
        std::function<void(EnterpriseDeviceMgrAbility *that, const EventFwk::CommonEventData &data)>>
        commonEventFuncMap_;
    std::unordered_map<int32_t,
        std::function<void(EnterpriseDeviceMgrAbility *that, int32_t systemAbilityId, const std::string &deviceId)>>
        addSystemAbilityFuncMap_;

    virtual std::shared_ptr<PermissionChecker> GetPermissionChecker();
protected:
    void OnStart() override;
    void OnStop() override;
    int32_t Dump(int32_t fd, const std::vector<std::u16string> &args) override;
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;
    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;

private:
    void AddCommonEventFuncMap();
    void AddOnAddSystemAbilityFuncMap();
    void AddOnAddSystemAbilityFuncMapSecond();
    bool SubscribeAppState();
    bool UnsubscribeAppState();
    void NotifyAdminEnabled(bool isEnabled);
    void CheckAndUpdateByodSettingsData();
    void UpdateClipboardInfo(const std::string &bundleName, int32_t userId);
    ErrCode RemoveAdminItem(const std::string &adminName, const std::string &policyName, const std::string &policyValue,
        int32_t userId);
    ErrCode RemoveAdminAndAdminPolicy(const std::string &adminName, int32_t userId);
    ErrCode RemoveAdmin(const std::string &adminName, int32_t userId);
    ErrCode RemoveAdminPolicy(const std::string &adminName, int32_t userId);
    ErrCode RemoveSubSuperAdminAndAdminPolicy(const std::string &bundleName);
    ErrCode RemoveSuperAdminAndAdminPolicy(const std::string &bundleName);
    ErrCode RemoveSubOrSuperAdminAndAdminPolicy(const std::string &bundleName,
        const std::vector<int32_t> &nonDefaultUserIds);
    ErrCode GetDevicePolicyFromPlugin(uint32_t code, MessageParcel &data, MessageParcel &reply, int32_t userId);
    ErrCode CheckGetPolicyParam(MessageParcel &data, std::shared_ptr<IPlugin> &plugin,
        AppExecFwk::ElementName &elementName, const std::string &permissionTag, int32_t userId);
    int32_t GetCurrentUserId();
    ErrCode HandleApplicationEvent(const std::vector<uint32_t> &events, bool subscribe);
    ErrCode VerifyEnableAdminCondition(const AppExecFwk::ElementName &admin, AdminType type, int32_t userId,
        bool isDebug);
    ErrCode VerifyEnableAdminConditionCheckExistAdmin(const AppExecFwk::ElementName &admin, AdminType type,
        int32_t userId, bool isDebug);
    ErrCode VerifyManagedEvent(const AppExecFwk::ElementName &admin, const std::vector<uint32_t> &events);
    ErrCode UpdateDevicePolicy(uint32_t code, const std::string &bundleName, MessageParcel &data, MessageParcel &reply,
        int32_t userId);
    ErrCode CheckDelegatedPolicies(AdminType adminType, const std::vector<std::string> &policies);
    ErrCode CheckReplaceAdmins(const AppExecFwk::ElementName &oldAdmin, const AppExecFwk::ElementName &newAdmin,
        std::vector<AppExecFwk::ExtensionAbilityInfo> &abilityInfo, std::vector<std::string> &permissionList);
    ErrCode HandleKeepPolicy(std::string &adminName, std::string &newAdminName, const AdminInfo &edmAdminInfo,
        const AdminInfo &oldAdminInfo);
    ErrCode AddDisallowUninstallApp(const std::string &bundleName);
    ErrCode DelDisallowUninstallApp(const std::string &bundleName);
    void UpdateFreezeExemptedApps(const std::string &bundleName, int32_t userId, int32_t appIndex);
    void UpdateAbilityEnabled(const std::string &bundleName, int32_t userId, int32_t appIndex);
    ErrCode AddDisallowUninstallAppForAccount(const std::string &bundleName, int32_t userId);
    ErrCode DelDisallowUninstallAppForAccount(const std::string &bundleName, int32_t userId);
    void AfterEnableAdmin(const AppExecFwk::ElementName &admin, AdminType type, int32_t userId);
    void AfterEnableAdminReportEdmEvent(const AppExecFwk::ElementName &newAdmin,
        const AppExecFwk::ElementName &oldAdmin);
    void ReportFuncEvent(uint32_t code);
    void UpdateMarketAppsState(const EventFwk::CommonEventData &data, int32_t event);
    void InitAgTask();
    void UpdateUserNonStopInfo(const std::string &bundleName, int32_t userId, int32_t appIndex);
    ErrCode CheckStartAbility(int32_t currentUserId, const AppExecFwk::ElementName &admin, const AAFwk::Want &want);
#ifdef COMMON_EVENT_SERVICE_EDM_ENABLE
    std::shared_ptr<EventFwk::CommonEventSubscriber> CreateEnterpriseDeviceEventSubscriber(
        EnterpriseDeviceMgrAbility &listener);
    std::shared_ptr<EventFwk::CommonEventSubscriber> CreateAGEventSubscriber(
        EnterpriseDeviceMgrAbility &listener);
    std::vector<std::string> GetAgCommonEventName();
#endif
    void OnCommonEventUserAdded(const EventFwk::CommonEventData &data);
    void OnCommonEventUserSwitched(const EventFwk::CommonEventData &data);
    void OnCommonEventUserRemoved(const EventFwk::CommonEventData &data);
    void OnCommonEventPackageAdded(const EventFwk::CommonEventData &data);
    void OnCommonEventPackageRemoved(const EventFwk::CommonEventData &data);
    void OnCommonEventPackageChanged(const EventFwk::CommonEventData &data);
    void OnCommonEventBmsReady(const EventFwk::CommonEventData &data);
    void OnCommonEventKioskMode(const EventFwk::CommonEventData &data, bool isModeOn);
    bool ShouldUnsubscribeAppState(const std::string &adminName, int32_t userId);
    bool CheckManagedEvent(uint32_t event);
    void OnAppManagerServiceStart();
    void OnAbilityManagerServiceStart();
    void OnCommonEventServiceStart();
    void OnDistributedKvDataServiceStart();
    void ConnectAbilityOnSystemAccountEvent(const int32_t accountId, ManagedEvent event);
    bool CheckRunningMode(uint32_t runningMode);
    void ConnectEnterpriseAbility();
    void CallOnOtherServiceStart(uint32_t interfaceCode);
    void CallOnOtherServiceStart(uint32_t interfaceCode, int32_t systemAbilityId);
    bool OnAdminEnabled(const std::string &bundleName, const std::string &abilityName, uint32_t code, int32_t userId,
        bool isAdminEnabled);
    bool OnAdminEnabled(AdminInfo adminInfo, uint32_t code, int32_t userId, const std::string &enabledBundleName);
    ErrCode CheckDisableAdmin(std::shared_ptr<Admin> admin, AdminType adminType);
    bool CheckDelegatedBundle(const std::string &bundleName, int32_t userId);
    ErrCode DisableVirtualAdmin(const std::string &bundleName, const std::string &parentName);
    void InitAllAdmins();
    void InitAllPolices();
    void RemoveAllDebugAdmin();
    void AddSystemAbilityListeners();
    void ConnectAbilityOnSystemUpdate(const UpdateInfo &updateInfo);
    void OnCommonEventSystemUpdate(const EventFwk::CommonEventData &data);
    std::shared_ptr<IEdmBundleManager> GetBundleMgr();
    std::shared_ptr<IEdmAppManager> GetAppMgr();
    std::shared_ptr<IEdmOsAccountManager> GetOsAccountMgr();
    // non-thread-safe function
    ErrCode DoDisableAdmin(const std::string &bundleName, int32_t userId, AdminType adminType);
    ErrCode DoDisableAdmin(std::shared_ptr<Admin> admin, int32_t userId, AdminType adminType);
    std::string GetExtensionEnterpriseAdminName(const std::string &bundleName, int32_t userId);
    ErrCode CheckEnableDeviceAdmin(const AppExecFwk::ElementName &admin);
    ErrCode CheckDisableDeviceAdmin(std::shared_ptr<Admin> deviceAdmin);
    void OnHandleInitExecute(uint32_t interfaceCode);
#if defined(FEATURE_PC_ONLY) && defined(LOG_SERVICE_PLUGIN_EDM_ENABLE)
    void CreateLogDirIfNeed(const std::string path);
    void DeleteLogDirIfNeed(const std::string path);
#endif
    static std::shared_mutex adminLock_;
    static sptr<EnterpriseDeviceMgrAbility> instance_;
    std::shared_ptr<PolicyManager> policyMgr_;
    std::shared_ptr<ExtraPolicyNotification> policyNotification_;
    bool registerToService_ = false;
    std::shared_ptr<EventFwk::CommonEventSubscriber> commonEventSubscriber = nullptr;
    sptr<AppExecFwk::IApplicationStateObserver> appStateObserver_;
    std::unordered_map<std::string, bool> adminConnectMap_;
    bool isNeedRemoveSettigsMenu_ = false;
};
#ifdef COMMON_EVENT_SERVICE_EDM_ENABLE
class EnterpriseDeviceEventSubscriber : public EventFwk::CommonEventSubscriber {
public:
    EnterpriseDeviceEventSubscriber(const EventFwk::CommonEventSubscribeInfo &subscribeInfo,
        EnterpriseDeviceMgrAbility &listener);
    ~EnterpriseDeviceEventSubscriber() override = default;

    void OnReceiveEvent(const EventFwk::CommonEventData &data) override;

private:
    EnterpriseDeviceMgrAbility &listener_;
};
#endif
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_INCLUDE_EDM_ENTERPRISE_DEVICE_MGR_ABILITY_H
