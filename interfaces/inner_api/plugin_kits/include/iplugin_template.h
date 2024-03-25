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

#ifndef SERVICES_EDM_INCLUDE_EDM_IPLUGIN_TEMPLATE_H
#define SERVICES_EDM_INCLUDE_EDM_IPLUGIN_TEMPLATE_H

#include <functional>
#include <memory>
#include <unordered_map>
#include "edm_log.h"
#include "func_code_utils.h"
#include "iplugin.h"
#include "ipolicy_manager.h"
#include "ipolicy_serializer.h"
#include "plugin_singleton.h"

namespace OHOS {
namespace EDM {
/*
 * Policy processing template.Implements the IPlugin interface and
 * provides the event registration method for policy processing.
 *
 * @tparam CT Policy processing logic class, which is the code to be implemented.
 * @tparam DT Policy data type, for example:string,vector<string>,map<string,string>...
 */
template<class CT, class DT>
class IPluginTemplate : public IPlugin {
public:
    ErrCode OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
        HandlePolicyData &policyData, int32_t userId) override;

    ErrCode MergePolicyData(const std::string &adminName, std::string &policyData) override;

    void OnHandlePolicyDone(std::uint32_t funcCode, const std::string &adminName,
        bool isGlobalChanged, int32_t userId) override;

    ErrCode OnAdminRemove(const std::string &adminName, const std::string &currentJsonData, int32_t userId) override;

    void OnAdminRemoveDone(const std::string &adminName, const std::string &removedJsonData, int32_t userId) override;

    ErrCode WritePolicyToParcel(const std::string &policyData, MessageParcel &reply) override;

    ErrCode OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId) override;

    /*
     * Sets the handle of the policy processing object.
     *
     * @param instance std::shared_ptr<CT>
     */
    void SetInstance(std::shared_ptr<CT> instance);

    /*
     * Define CT as the friend class of IPluginTemplate.
     */
    friend CT;

    IPluginTemplate();

    ~IPluginTemplate();

protected:
    /*
     * Represents a function that invoked during handling policy.
     *
     * @param one MessageParcel
     * @param two MessageParcel
     * @param three Current policy data
     * @param four Whether the policy data is changed
     * @param five Handle type
     * @see OnHandlePolicy
     * @see HandlePolicyFunc
     */
    typedef std::function<ErrCode(MessageParcel &, MessageParcel &, std::string &, bool &, FuncOperateType,
        int32_t userId)> HandlePolicy;

    /*
     * Represents a function that invoked during handling policy.
     *
     * @param one Admin name
     * @param two Whether the policy data is changed
     * @param three Handle type
     * @see OnHandlePolicyDone
     * @see HandlePolicyDoneFunc
     */
    typedef std::function<ErrCode(const std::string &, bool, FuncOperateType, int32_t userId)> HandlePolicyDone;

    /*
     * Represents a function that invoked during the removal of admin.
     *
     * @see OnAdminRemove
     * @see AdminRemoveFunc
     */
    typedef std::function<ErrCode(const std::string &, const std::string &, int32_t userId)> AdminRemove;

    /*
     * Represents a function that invoked after the admin is removed.
     *
     * @see OnAdminRemoveDone
     * @see AdminRemoveDoneFunc
     */
    typedef std::function<ErrCode(const std::string &, const std::string &, int32_t userId)> AdminRemoveDone;

    /*
     * This is a member function pointer type of CT class.
     * Represents a supplier of results. There is no requirement that a ErrCode result be returned each time the
     * supplier is invoked.
     * It is generally used in scenarios where only return values need to be processed and parameters are not concerned.
     *
     * @return Whether the policy is handled successfully.
     * @see SetOnHandlePolicyListener
     * @see SetOnAdminRemoveListener
     */
    typedef ErrCode (CT::*Supplier)();

    /*
     * This is a member function pointer type of CT class.
     * Represents a function that accepts one DT argument and produces a ErrCode result.
     * It is generally used in the scenario where only one DT parameter and return value need to be processed.
     *
     * @param data In: Input policy data parameter,Out: Used to update the admin data.
     * @return Whether the policy is handled successfully.
     * @see SetOnHandlePolicyListener
     */
    typedef ErrCode (CT::*Function)(DT &data);

    /*
     * This is a member function pointer type of CT class.
     * Represents a function that accepts one DT argument and produces a ErrCode result.
     * It is generally used in the scenario where only one DT parameter and return value need to be processed.
     *
     * @param data In: Input policy data parameter,Out: Used to update the admin data.
     * @param reply In: return message parcel for ipc,Out: parcel with return value or message.
     * @return Whether the policy is handled successfully.
     * @see SetOnHandlePolicyListener
     */
    typedef ErrCode (CT::*ReplyFunction)(DT &data, MessageParcel &reply);

    /*
     * This is a member function pointer type of CT class.
     * Represents a function that accepts two DT arguments and produces a ErrCode result.
     *
     * @param data Input policy data parameter
     * @param currentData In: data of the current admin,Out: Used to update the admin data.
     * @return Whether the policy is handled successfully.
     * @see SetOnHandlePolicyListener
     */
    typedef ErrCode (CT::*BiFunction)(DT &data, DT &currentData, int32_t userId);

    /*
     * This is a member function pointer type of CT class.
     * Represents a function that accepts an string-valued and a DT-valued argument, and produces a ErrCode result.
     *
     * @param adminName Admin name
     * @param data Admin policy data
     * @see SetOnAdminRemoveListener
     */
    typedef ErrCode (CT::*BiAdminFunction)(const std::string &adminName, DT &data, int32_t userId);

    /*
     * This is a member function pointer type of CT class.
     * Represents an operation that accepts a single bool input argument and returns no result.
     *
     * @param isGlobalChanged Whether the policy data is changed
     * @see SetOnHandlePolicyDoneListener
     */
    typedef void (CT::*BoolConsumer)(bool isGlobalChanged);

    /*
     * This is a member function pointer type of CT class.
     * Represents an operation that accepts an DT-valued and a bool-valued argument, and returns no result.
     *
     * @param data Admin policy data
     * @param isGlobalChanged Whether the policy data is changed
     * @see SetOnHandlePolicyDoneListener
     */
    typedef void (CT::*BiBoolConsumer)(DT &data, bool isGlobalChanged, int32_t userId);

    /*
     * This is a member function pointer type of CT class.
     * Represents an operation that accepts no arguments and returns no result.
     *
     * @param data Admin policy data
     * @param isGlobalChanged Whether the policy data is changed
     * @see SetOnAdminRemoveDoneListener
     */
    typedef void (CT::*Runner)();

    /*
     * This is a member function pointer type of CT class.
     * Represents an operation that accepts an string-valued and a DT-valued argument, and returns no result.
     *
     * @param adminName Admin name
     * @param data Admin policy data
     * @see SetOnAdminRemoveDoneListener
     */
    typedef void (CT::*BiAdminConsumer)(const std::string &adminName, DT &data, int32_t userId);

    virtual bool GetMergePolicyData(DT &policyData);

    void SetSerializer(std::shared_ptr<IPolicySerializer<DT>> serializer);

    void InitAttribute(uint32_t policyCode, const std::string &policyName, PolicyPermissionConfig config,
        bool needSave = true, bool global = true);

    void InitAttribute(uint32_t policyCode, const std::string &policyName, const std::string &permission,
        IPlugin::PermissionType permissionType, bool needSave = true, bool global = true);

    void InitAttribute(uint32_t policyCode, const std::string &policyName, bool needSave = true, bool global = true);

    void InitPermission(FuncOperateType operateType, PolicyPermissionConfig config);

    void InitPermission(FuncOperateType operateType, const std::string &permission,
        IPlugin::PermissionType permissionType);

    /*
     * Registering Listening for HandlePolicy Events.
     *
     * @param listener Listening member function pointer of CT Class
     * @param type Policy Data Processing Mode
     * @see FuncOperateType
     */
    void SetOnHandlePolicyListener(Supplier &&listener, FuncOperateType type);

    /*
     * Registering Listening for HandlePolicy Events.
     *
     * @param listener Listening member function pointer of CT Class
     * @param type Policy Data Processing Mode,default FuncOperateType::REMOVE
     * @see FuncOperateType
     */
    void SetOnHandlePolicyListener(Function &&listener, FuncOperateType type);

    /*
     * Registering Listening for HandlePolicy Events.
     *
     * @param listener Listening member function pointer of CT Class
     * @param type Policy Data Processing Mode,default FuncOperateType::SET
     * @see FuncOperateType
     */
    void SetOnHandlePolicyListener(BiFunction &&listener, FuncOperateType type);

    /*
     * Registering Listening for HandlePolicy Events.
     *
     * @param listener Listening member function pointer of CT Class
     * @param type Policy Data Processing Mode,default FuncOperateType::SET
     * @see FuncOperateType
     */
    void SetOnHandlePolicyListener(ReplyFunction &&listener, FuncOperateType type);

    /*
     * Registering listening for HandlePolicyDone events.
     *
     * @param listener Listening member function pointer of CT Class
     * @param type Policy Data Processing Mode
     */
    void SetOnHandlePolicyDoneListener(BoolConsumer &&listener, FuncOperateType type);

    /*
     * Registering listening for HandlePolicyDone events.
     *
     * @param listener Listening member function pointer of CT Class
     * @param type Policy Data Processing Mode
     */
    void SetOnHandlePolicyDoneListener(BiBoolConsumer &&listener, FuncOperateType type);

    /*
     * Registering listening for AdminRemove events.
     *
     * @param listener Listening member function pointer of CT Class
     */
    void SetOnAdminRemoveListener(Supplier &&listener);

    /*
     * Registering listening for AdminRemove events.
     *
     * @param listener Listening member function pointer of CT Class
     */
    void SetOnAdminRemoveListener(BiAdminFunction &&listener);

    /*
     * Registering listening for AdminRemoveDone events.
     *
     * @param listener Listening member function pointer of CT Class
     */
    void SetOnAdminRemoveDoneListener(Runner &&listener);

    /*
     * Registering listening for AdminRemoveDone events.
     *
     * @param listener Listening member function pointer of CT Class
     */
    void SetOnAdminRemoveDoneListener(BiAdminConsumer &&listener);

    /*
     * Mapping between HandlePolicy and member function types that support overloading.
     */
    struct HandlePolicyFunc {
        HandlePolicy handlePolicy_ = nullptr;
        Supplier supplier_ = nullptr;
        Function function_ = nullptr;
        ReplyFunction replyfunction_ = nullptr;
        BiFunction biFunction_ = nullptr;

        HandlePolicyFunc() {}

        HandlePolicyFunc(HandlePolicy handlePolicy, Supplier supplier)
            : handlePolicy_(std::move(handlePolicy)), supplier_(supplier) {}

        HandlePolicyFunc(HandlePolicy handlePolicy, Function function)
            : handlePolicy_(std::move(handlePolicy)), function_(function) {}

        HandlePolicyFunc(HandlePolicy handlePolicy, ReplyFunction replyfunction)
            : handlePolicy_(std::move(handlePolicy)), replyfunction_(replyfunction) {}

        HandlePolicyFunc(HandlePolicy handlePolicy, BiFunction biFunction)
            : handlePolicy_(std::move(handlePolicy)), biFunction_(biFunction) {}
    };

    // Member function callback object of the HandlePolicy event.
    std::map<FuncOperateType, HandlePolicyFunc> handlePolicyFuncMap_;

    /*
     * Mapping between HandlePolicyDone and member function types that support overloading.
     */
    struct HandlePolicyDoneFunc {
        HandlePolicyDone handlePolicyDone_ = nullptr;
        BoolConsumer boolConsumer_ = nullptr;
        BiBoolConsumer biBoolConsumer_ = nullptr;

        HandlePolicyDoneFunc() {}

        HandlePolicyDoneFunc(HandlePolicyDone handlePolicyDone, BoolConsumer boolConsumer)
            : handlePolicyDone_(std::move(handlePolicyDone)), boolConsumer_(boolConsumer) {}

        HandlePolicyDoneFunc(HandlePolicyDone handlePolicyDone, BiBoolConsumer biBoolConsumer)
            : handlePolicyDone_(std::move(handlePolicyDone)), biBoolConsumer_(biBoolConsumer) {}
    };

    // Member function callback object of the HandlePolicyDone event.
    std::map<FuncOperateType, HandlePolicyDoneFunc> handlePolicyDoneFuncMap_;

    /*
     * Mapping between AdminRemove and member function types that support overloading.
     */
    struct AdminRemoveFunc {
        AdminRemove adminRemove_ = nullptr;
        Supplier supplier_ = nullptr;
        BiAdminFunction biAdminFunction_ = nullptr;

        AdminRemoveFunc() {}

        AdminRemoveFunc(AdminRemove adminRemove, Supplier supplier)
            : adminRemove_(std::move(adminRemove)), supplier_(supplier) {}

        AdminRemoveFunc(AdminRemove adminRemove, BiAdminFunction biAdminFunction)
            : adminRemove_(std::move(adminRemove)), biAdminFunction_(biAdminFunction) {}
    };

    // Member function callback object of the AdminRemove event.
    AdminRemoveFunc adminRemoveFunc_;

    /*
     * Mapping between AdminRemoveDone and member function types that support overloading.
     */
    struct AdminRemoveDoneFunc {
        AdminRemoveDone adminRemoveDone_ = nullptr;
        Runner runner_ = nullptr;
        BiAdminConsumer biAdminConsumer_ = nullptr;

        AdminRemoveDoneFunc() {}

        AdminRemoveDoneFunc(AdminRemoveDone adminRemoveDone, Runner runner)
            : adminRemoveDone_(std::move(adminRemoveDone)), runner_(runner) {}

        AdminRemoveDoneFunc(AdminRemoveDone adminRemoveDone, BiAdminConsumer biAdminConsumer)
            : adminRemoveDone_(std::move(adminRemoveDone)), biAdminConsumer_(biAdminConsumer) {}
    };

    // Member function callback object of the AdminRemoveDone event.
    AdminRemoveDoneFunc adminRemoveDoneFunc_;
    // Pointer to the callback member function.
    std::shared_ptr<CT> instance_;
    // Data serializer for policy data
    std::shared_ptr<IPolicySerializer<DT>> serializer_;
};

#include "iplugin_template.tpp"

} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_INCLUDE_EDM_IPLUGIN_TEMPLATE_H
