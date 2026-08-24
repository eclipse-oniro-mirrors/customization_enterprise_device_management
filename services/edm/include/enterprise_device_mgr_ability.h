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
#include "enable_source.h"
#include "event_subscription_manager.h"
#include "extra_policy_notification.h"
#include "hilog/log.h"
#include "installed_bundle_info_util.h"
#include "plugin_manager.h"
#include "policy_manager.h"
#include "security_report.h"
#include "subscription_handle.h"
#include "system_ability.h"
#include "mdm_event_relayer.h"

namespace OHOS {
namespace EDM {
class EnterpriseDeviceMgrAbility : public SystemAbility, public EnterpriseDeviceMgrStub,
    public std::enable_shared_from_this<EnterpriseDeviceMgrAbility> {
    DECLARE_SYSTEM_ABILITY(EnterpriseDeviceMgrAbility);

public:
    EnterpriseDeviceMgrAbility();
    DISALLOW_COPY_AND_MOVE(EnterpriseDeviceMgrAbility);
    ~EnterpriseDeviceMgrAbility() override;
    static sptr<EnterpriseDeviceMgrAbility> GetInstance();
    ErrCode EnableAdmin(
        const AppExecFwk::ElementName &admin, const EntInfo &entInfo, AdminType adminType, int32_t userId,
        EnableSource enableSource = EnableSource::DEPLOY) override;
    ErrCode DisableAdmin(const AppExecFwk::ElementName &admin, int32_t userId) override;
    ErrCode DisableSuperAdmin(const std::string &bundleName) override;
    ErrCode GetEnabledAdmin(AdminType adminType, std::vector<std::string> &enabledAdminList) override;
    ErrCode GetEnterpriseInfo(const AppExecFwk::ElementName &admin, EntInfo &entInfo) override;
    ErrCode SetEnterpriseInfo(const AppExecFwk::ElementName &admin, const EntInfo &entInfo) override;
    ErrCode IsSuperAdmin(const std::string &bundleName, bool &isSuper) override;
    ErrCode IsSuperAdminByWant(const AppExecFwk::ElementName &admin, bool &isSuper) override;
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
    ErrCode GetAdminInfos(const AppExecFwk::ElementName &admin,
        std::vector<std::shared_ptr<AAFwk::Want>> &wants) override;
    ErrCode SetAdminRunningMode(const AppExecFwk::ElementName &admin, uint32_t runningMode) override;
    ErrCode SetDelegatedPolicies(const std::string &bundleName,
        const std::vector<std::string> &policies, int32_t userId) override;
    ErrCode SetBundleInstallPolicies(const std::vector<std::string> &bundles, int32_t userId,
        int32_t policyType) override;
    ErrCode UnloadInstallMarketAppsPlugin() override;
    ErrCode EnableDeviceAdmin(const AppExecFwk::ElementName &admin) override;
    ErrCode DisableDeviceAdmin(const AppExecFwk::ElementName &admin) override;
    ErrCode GetEnterpriseManagedTips(std::string &tips) override;
    ErrCode EnableSelfDeviceAdmin(const AppExecFwk::ElementName &admin, const std::string &credential) override;
    ErrCode EnableAdmin(const AppExecFwk::ElementName &admin, const EntInfo &entInfo, AdminType adminType,
        int32_t userId, bool enableSelf, EnableSource enableSource = EnableSource::DEPLOY) override;

    ErrCode HandleDevicePolicy(uint32_t code, AppExecFwk::ElementName &admin, MessageParcel &data, MessageParcel &reply,
        int32_t userId) override;
    ErrCode GetDevicePolicy(uint32_t code, MessageParcel &data, MessageParcel &reply, int32_t userId,
        int32_t hasUserId = 1) override;
    ErrCode CheckAndGetAdminProvisionInfo(uint32_t code, MessageParcel &data, MessageParcel &reply, int32_t userId)
        override;
    ErrCode ReportAgInstallStatus(const std::string &bundleName,
        const std::string &mediaBundleName, int32_t status) override;
    ErrCode StartAbilityByAdmin(const AppExecFwk::ElementName &admin, const AAFwk::Want &want) override;
    bool ConnectAbility(const int32_t accountId, std::shared_ptr<Admin> admin);
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
    void AddOnAddSystemAbilityFuncMap();
    void AddOnAddSystemAbilityFuncMapSecond();
    void NotifyAdminEnabled(bool isEnabled);
    void CheckAndUpdateByodSettingsData();
    ErrCode RemoveAdminAndAdminPolicy(const std::string &adminName, int32_t userId, AdminType adminType);
    ErrCode RemoveAdmin(const std::string &adminName, int32_t userId, AdminType adminType);
    ErrCode RemoveAdminPolicy(const std::string &adminName, int32_t userId);
#ifndef FEATURE_PC_ONLY
    bool IsSystemTimerFuncCode(uint32_t code);
    ErrCode HandleSystemTimerPolicy(uint32_t code, AppExecFwk::ElementName &admin,
        MessageParcel &data, MessageParcel &reply, int32_t userId);
#endif
    ErrCode RemoveSubSuperAdminAndAdminPolicy(const std::string &bundleName, AdminType adminType);
    ErrCode RemoveSuperAdminAndAdminPolicy(const std::string &bundleName);
    ErrCode RemoveSubOrSuperAdminAndAdminPolicy(const std::string &bundleName,
        const std::vector<int32_t> &nonDefaultUserIds, AdminType adminType);
    ErrCode GetDevicePolicyFromPlugin(uint32_t code, MessageParcel &data, MessageParcel &reply, int32_t userId,
        const std::string &permissionTag);
    ErrCode EnableAdminWithPermission(const AppExecFwk::ElementName &admin, const EntInfo &entInfo,
        AdminType adminType, int32_t userId, const std::string &permission,
        EnableSource enableSource = EnableSource::DEPLOY);
    int32_t GetCurrentUserId();
    ErrCode VerifyEnableAdminCondition(const AppExecFwk::ElementName &admin, AdminType type, int32_t userId,
        bool isDebug);
    ErrCode VerifyEnableAdminConditionCheckExistAdmin(const AppExecFwk::ElementName &admin, AdminType type,
        int32_t userId, bool isDebug);
    ErrCode VerifyManagedEvent(const AppExecFwk::ElementName &admin, const std::vector<uint32_t> &events);
    ErrCode CheckDelegatedPolicies(AdminType adminType, const std::vector<std::string> &policies);
    ErrCode CheckReplaceAdmins(const AppExecFwk::ElementName &oldAdmin, const AppExecFwk::ElementName &newAdmin,
        std::vector<AppExecFwk::ExtensionAbilityInfo> &abilityInfo, std::vector<std::string> &permissionList);
    ErrCode HandleKeepPolicy(std::string &adminName, std::string &newAdminName, const AdminInfo &edmAdminInfo,
        const AdminInfo &oldAdminInfo);
    ErrCode AddDisallowUninstallApp(const std::string &bundleName);
    ErrCode DelDisallowUninstallApp(const std::string &bundleName);
    ErrCode AddDisallowUninstallAppForAccount(const std::string &bundleName, int32_t userId);
    ErrCode DelDisallowUninstallAppForAccount(const std::string &bundleName, int32_t userId);
    void AfterEnableAdmin(const AppExecFwk::ElementName &admin, AdminType type, int32_t userId,
        EnableSource enableSource);
    void AfterEnableAdminReportEdmEvent(const AppExecFwk::ElementName &newAdmin,
        const AppExecFwk::ElementName &oldAdmin);
    void CheckAndReportInstalledBundleInfoOnStart();

public:
    ErrCode CheckStartAbility(int32_t currentUserId, const AppExecFwk::ElementName &admin,
        const std::string &bundleName);
    void OnCommonEventUserSwitched(const EventFwk::CommonEventData &data);
    void OnCommonEventUserRemoved(const EventFwk::CommonEventData &data);
    void OnCommonEventPackageRemoved(const EventFwk::CommonEventData &data);
    void OnCommonEventPackageChanged(const EventFwk::CommonEventData &data);
    void OnCommonEventBmsReady(const EventFwk::CommonEventData &data);
    void OnCommonEventKioskMode(const EventFwk::CommonEventData &data, bool isModeOn);
    void OnCommonEventSimStateChanged(const EventFwk::CommonEventData &data);
    void UpdateMarketAppsState(const EventFwk::CommonEventData &data, int32_t event);
    void InitAgTask();
    bool CheckManagedEvent(uint32_t event);
    void OnAppManagerServiceStart();
    void OnAbilityManagerServiceStart();
    void OnCommonEventServiceStart();
    void OnDistributedKvDataServiceStart();
    bool CheckRunningMode(uint32_t runningMode);
    void ConnectEnterpriseAbility();
    void CallOnOtherServiceStart(uint32_t interfaceCode);
    void CallOnOtherServiceStart(uint32_t interfaceCode, int32_t systemAbilityId);
    void CallOnOtherServiceStartForWatermark(uint32_t interfaceCode);
    bool OnAdminEnabled(const std::string &bundleName, const std::string &abilityName, uint32_t code, int32_t userId);
    bool OnAdminEnabled(AdminInfo adminInfo, uint32_t code, int32_t userId, const std::string &enabledBundleName);
    ErrCode CheckDisableAdmin(std::shared_ptr<Admin> admin, AdminType adminType);
    bool CheckDelegatedBundle(const std::string &bundleName, int32_t userId);
    ErrCode DisableVirtualAdmin(const std::string &bundleName, const std::string &parentName);
    void InitAllAdmins();
    void InitAllPolices();
    void RemoveAllDebugAdmin();
    void CleanHapTempDirectory();
    void AddSystemAbilityListeners();
    std::shared_ptr<IEdmBundleManager> GetBundleMgr();
    std::shared_ptr<IEdmAppManager> GetAppMgr();
    std::shared_ptr<IEdmOsAccountManager> GetOsAccountMgr();
    void UpdateNetworkAccessPolicy(int oldId, int newId);
    // non-thread-safe function
    ErrCode DoDisableAdmin(const std::string &bundleName, int32_t userId, AdminType adminType);
    ErrCode DoDisableAdmin(std::shared_ptr<Admin> admin, int32_t userId, AdminType adminType);
    std::string GetExtensionEnterpriseAdminName(const std::string &bundleName, int32_t userId);
    ErrCode CheckEnableDeviceAdmin(const AppExecFwk::ElementName &admin);
    ErrCode CheckDisableDeviceAdmin(std::shared_ptr<Admin> deviceAdmin);
    void OnHandleInitExecute(uint32_t interfaceCode);
    bool IsInMaintenanceMode();
    ErrCode EnableAdminPreCheck(AdminType type, EnableSource enableSource);
#if defined(FEATURE_PC_ONLY) && defined(LOG_SERVICE_PLUGIN_EDM_ENABLE)
    void CreateLogDirIfNeed(const std::string &path);
    void DeleteLogDirIfNeed(const std::string &adminName);
    void DeleteSubUserLogDirIfNeed(int32_t userId);
#endif
    static std::shared_mutex adminLock_;
    static sptr<EnterpriseDeviceMgrAbility> instance_;
    std::shared_ptr<PolicyManager> policyMgr_;
    std::shared_ptr<ExtraPolicyNotification> policyNotification_;
    bool registerToService_ = false;
    std::unordered_map<std::string, bool> adminConnectMap_;
    bool isNeedRemoveSettigsMenu_ = false;
    std::vector<std::shared_ptr<SubscriptionHandle>> saCoreHandles_;
};
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_INCLUDE_EDM_ENTERPRISE_DEVICE_MGR_ABILITY_H
