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

#ifndef SERVICES_EDM_INCLUDE_EDM_IPLUGIN_TEMPLATE_H
#define SERVICES_EDM_INCLUDE_EDM_IPLUGIN_TEMPLATE_H

#include <functional>
#include "edm_log.h"
#include "iplugin.h"
#include "ipolicy_serializer.h"
#include "policy_manager.h"

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
    ErrCode OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, std::string &policyData,
        bool &isChanged) override;

    ErrCode MergePolicyData(const std::string &adminName, std::string &policyData) override;

    void OnHandlePolicyDone(std::uint32_t funcCode, const std::string &adminName,
        bool isGlobalChanged) override;

    ErrCode OnAdminRemove(const std::string &adminName, const std::string &currentJsonData) override;

    void OnAdminRemoveDone(const std::string &adminName, const std::string &removedJsonData) override;

    ErrCode WritePolicyToParcel(const std::string &policyData, MessageParcel &reply) override;

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
     * @param two Current policy data
     * @param three Whether the policy data is changed
     * @param four Handle type
     * @see OnHandlePolicy
     * @see HandlePolicyFunc
     */
    typedef std::function<ErrCode(MessageParcel &, std::string &, bool &, FuncOperateType)> HandlePolicy;

    /*
     * Represents a function that invoked during handling policy.
     *
     * @param one Admin name
     * @param two Whether the policy data is changed
     * @param three Handle type
     * @see OnHandlePolicyDone
     * @see HandlePolicyDoneFunc
     */
    typedef std::function<ErrCode(const std::string &, bool, FuncOperateType)> HandlePolicyDone;

    /*
     * Represents a function that invoked during the removal of admin.
     *
     * @see OnAdminRemove
     * @see AdminRemoveFunc
     */
    typedef std::function<ErrCode(const std::string &, const std::string &)> AdminRemove;

    /*
     * Represents a function that invoked after the admin is removed.
     *
     * @see OnAdminRemoveDone
     * @see AdminRemoveDoneFunc
     */
    typedef std::function<ErrCode(const std::string &, const std::string &)> AdminRemoveDone;

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
     * Represents a function that accepts two DT arguments and produces a ErrCode result.
     *
     * @param data Input policy data parameter
     * @param currentData In: data of the current admin,Out: Used to update the admin data.
     * @return Whether the policy is handled successfully.
     * @see SetOnHandlePolicyListener
     */
    typedef ErrCode (CT::*BiFunction)(DT &data, DT &currentData);

    /*
     * This is a member function pointer type of CT class.
     * Represents a function that accepts an string-valued and a DT-valued argument, and produces a ErrCode result.
     *
     * @param adminName Admin name
     * @param data Admin policy data
     * @see SetOnAdminRemoveListener
     */
    typedef ErrCode (CT::*BiAdminFunction)(const std::string &adminName, DT &data);

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
    typedef void (CT::*BiBoolConsumer)(DT &data, bool isGlobalChanged);

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
    typedef void (CT::*BiAdminConsumer)(const std::string &adminName, DT &data);

    virtual bool GetMergePolicyData(DT &policyData);

    void SetSerializer(std::shared_ptr<IPolicySerializer<DT>> serializer);

    void InitAttribute(uint32_t policyCode, const std::string &policyName, const std::string &permission,
        bool needSave = true, bool global = true);

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
        BiFunction biFunction_ = nullptr;

        HandlePolicyFunc() {}

        HandlePolicyFunc(HandlePolicy handlePolicy, Supplier supplier)
            : handlePolicy_(std::move(handlePolicy)), supplier_(supplier) {}

        HandlePolicyFunc(HandlePolicy handlePolicy, Function function)
            : handlePolicy_(std::move(handlePolicy)), function_(function) {}

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

template<class CT, class DT>
IPluginTemplate<CT, DT>::IPluginTemplate() {}

template<class CT, class DT>
ErrCode IPluginTemplate<CT, DT>::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, std::string &policyData,
    bool &isChanged)
{
    uint32_t typeCode = FUNC_TO_OPERATE(funcCode);
    FuncOperateType type = FuncCodeUtils::ConvertOperateType(typeCode);
    auto entry = handlePolicyFuncMap_.find(type);
    if (entry == handlePolicyFuncMap_.end() || entry->second.handlePolicy_ == nullptr) {
        return ERR_OK;
    }
    ErrCode res = entry->second.handlePolicy_(data, policyData, isChanged, type);
    EDMLOGI("IPluginTemplate::OnHandlePolicy operate: %{public}d, res: %{public}d", type, res);
    return res;
}

template<class CT, class DT>
void IPluginTemplate<CT, DT>::SetOnHandlePolicyListener(Supplier &&listener, FuncOperateType type)
{
    if (instance_ == nullptr) {
        return;
    }
    auto handle = [this](MessageParcel &data, std::string &policyData, bool &isChanged,
        FuncOperateType funcOperate) -> ErrCode {
        auto entry = handlePolicyFuncMap_.find(funcOperate);
        if (entry == handlePolicyFuncMap_.end() || entry->second.supplier_ == nullptr) {
            return ERR_EDM_NOT_EXIST_FUNC;
        }
        return (instance_.get()->*(entry->second.supplier_))();
    };
    handlePolicyFuncMap_.insert(std::make_pair(type, HandlePolicyFunc(handle, listener)));
}

template<class CT, class DT>
void IPluginTemplate<CT, DT>::SetOnHandlePolicyListener(Function &&listener, FuncOperateType type)
{
    if (instance_ == nullptr) {
        return;
    }
    auto handle = [this](MessageParcel &data, std::string &policyData, bool &isChanged,
        FuncOperateType funcOperate) -> ErrCode {
        DT handleData;
        if (!serializer_->GetPolicy(data, handleData)) {
            return ERR_EDM_OPERATE_PARCEL;
        }
        auto entry = handlePolicyFuncMap_.find(funcOperate);
        if (entry == handlePolicyFuncMap_.end() || entry->second.function_ == nullptr) {
            return ERR_EDM_NOT_EXIST_FUNC;
        }
        ErrCode result = (instance_.get()->*(entry->second.function_))(handleData);
        if (result != ERR_OK) {
            return result;
        }
        std::string afterHandle;
        if (!serializer_->Serialize(handleData, afterHandle)) {
            return ERR_EDM_OPERATE_JSON;
        }
        isChanged = (policyData != afterHandle);
        if (isChanged) {
            policyData = afterHandle;
        }
        return ERR_OK;
    };
    handlePolicyFuncMap_.insert(std::make_pair(type, HandlePolicyFunc(handle, listener)));
}

template<class CT, class DT>
void IPluginTemplate<CT, DT>::SetOnHandlePolicyListener(BiFunction &&listener, FuncOperateType type)
{
    if (instance_ == nullptr || instance_.get() == nullptr) {
        return;
    }
    auto handle = [this](MessageParcel &data, std::string &policyData, bool &isChanged,
        FuncOperateType funcOperate) -> ErrCode {
        DT handleData;
        if (!serializer_->GetPolicy(data, handleData)) {
            return ERR_EDM_OPERATE_PARCEL;
        }
        DT currentData;
        if (!policyData.empty() && !serializer_->Deserialize(policyData, currentData)) {
            return ERR_EDM_OPERATE_JSON;
        }
        auto entry = handlePolicyFuncMap_.find(funcOperate);
        if (entry == handlePolicyFuncMap_.end() || entry->second.biFunction_ == nullptr) {
            return ERR_EDM_NOT_EXIST_FUNC;
        }
        std::string beforeHandle;
        if (!serializer_->Serialize(currentData, beforeHandle)) {
            return ERR_EDM_OPERATE_JSON;
        }
        ErrCode result = (instance_.get()->*(entry->second.biFunction_))(handleData, currentData);
        if (result != ERR_OK) {
            return result;
        }
        std::string afterHandle;
        if (!serializer_->Serialize(currentData, afterHandle)) {
            return ERR_EDM_OPERATE_JSON;
        }
        policyData = afterHandle;
        isChanged = (beforeHandle != afterHandle);
        return ERR_OK;
    };
    handlePolicyFuncMap_.insert(std::make_pair(type, HandlePolicyFunc(handle, listener)));
}

template<class CT, class DT>
ErrCode IPluginTemplate<CT, DT>::MergePolicyData(const std::string &adminName, std::string &policyData)
{
    AdminValueItemsMap adminValues;
    PolicyManager::GetInstance()->GetAdminByPolicyName(GetPolicyName(), adminValues);
    EDMLOGD("IPluginTemplate::MergePolicyData %{public}s value size %{public}d.",
        GetPolicyName().c_str(), (uint32_t)adminValues.size());
    if (adminValues.empty()) {
        return ERR_OK;
    }
    // Update or remove policy value from the cache map.
    auto entry = adminValues.find(adminName);
    // Remove policy value from the cache map.
    if (entry != adminValues.end()) {
        adminValues.erase(entry);
    }
    if (adminValues.empty() && policyData.empty()) {
        return ERR_OK;
    }
    std::vector<DT> data;
    for (const auto &item : adminValues) {
        DT dataItem;
        if (!item.second.empty()) {
            if (!serializer_->Deserialize(item.second, dataItem)) {
                return ERR_EDM_OPERATE_JSON;
            }
            data.push_back(dataItem);
        }
    }
    // Add current policy to last, some policy must ensure the order, Deserialize can not parse empty String
    DT last;
    if (!policyData.empty()) {
        if (!serializer_->Deserialize(policyData, last)) {
            return ERR_EDM_OPERATE_JSON;
        }
        data.push_back(last);
    }
    DT result;
    if (!serializer_->MergePolicy(data, result)) {
        return ERR_EDM_OPERATE_JSON;
    }
    if (!serializer_->Serialize(result, policyData)) {
        return ERR_EDM_OPERATE_JSON;
    }
    return ERR_OK;
}

template<class CT, class DT>
void IPluginTemplate<CT, DT>::OnHandlePolicyDone(std::uint32_t funcCode, const std::string &adminName,
    const bool isGlobalChanged)
{
    uint32_t typeCode = FUNC_TO_OPERATE(funcCode);
    FuncOperateType type = FuncCodeUtils::ConvertOperateType(typeCode);
    auto entry = handlePolicyDoneFuncMap_.find(type);
    if (entry == handlePolicyDoneFuncMap_.end() || entry->second.handlePolicyDone_ == nullptr) {
        return;
    }
    ErrCode res = entry->second.handlePolicyDone_(adminName, isGlobalChanged, type);
    EDMLOGI("IPluginTemplate::OnHandlePolicyDone operate: %{public}d, isGlobalChanged: %{public}d, res: %{public}d",
        type, isGlobalChanged, res);
}

template<class CT, class DT>
void IPluginTemplate<CT, DT>::SetOnHandlePolicyDoneListener(BoolConsumer &&listener, FuncOperateType type)
{
    if (instance_ == nullptr) {
        return;
    }
    auto handle = [this](const std::string &adminName, bool isGlobalChanged, FuncOperateType funcOperate) -> ErrCode {
        auto entry = handlePolicyDoneFuncMap_.find(funcOperate);
        if (entry == handlePolicyDoneFuncMap_.end() || entry->second.boolConsumer_ == nullptr) {
            return ERR_EDM_NOT_EXIST_FUNC;
        }
        (instance_.get()->*(entry->second.boolConsumer_))(isGlobalChanged);
        return ERR_OK;
    };
    handlePolicyDoneFuncMap_.insert(std::make_pair(type, HandlePolicyDoneFunc(handle, listener)));
}

template<class CT, class DT>
void IPluginTemplate<CT, DT>::SetOnHandlePolicyDoneListener(BiBoolConsumer &&listener, FuncOperateType type)
{
    if (instance_ == nullptr) {
        return;
    }
    auto handle = [this](const std::string &adminName, bool isGlobalChanged, FuncOperateType funcOperate) -> ErrCode {
        auto entry = handlePolicyDoneFuncMap_.find(funcOperate);
        if (entry == handlePolicyDoneFuncMap_.end() || entry->second.biBoolConsumer_ == nullptr) {
            return ERR_EDM_NOT_EXIST_FUNC;
        }
        DT currentData;
        if (NeedSavePolicy() && !this->GetMergePolicyData(currentData)) {
            return ERR_EDM_OPERATE_JSON;
        }
        (instance_.get()->*(entry->second.biBoolConsumer_))(currentData, isGlobalChanged);
        return ERR_OK;
    };
    handlePolicyDoneFuncMap_.insert(std::make_pair(type, HandlePolicyDoneFunc(handle, listener)));
}

template<class CT, class DT>
ErrCode IPluginTemplate<CT, DT>::OnAdminRemove(const std::string &adminName, const std::string &currentJsonData)
{
    if (adminRemoveFunc_.adminRemove_ == nullptr) {
        return ERR_OK;
    }
    ErrCode res = (adminRemoveFunc_.adminRemove_)(adminName, currentJsonData);
    EDMLOGI("IPluginTemplate::OnAdminRemove admin:%{public}s, res: %{public}d", adminName.c_str(), res);
    return res;
}

template<class CT, class DT>
void IPluginTemplate<CT, DT>::SetOnAdminRemoveListener(Supplier &&listener)
{
    if (instance_ == nullptr) {
        return;
    }
    auto adminRemove = [this](const std::string &adminName, const std::string &currentJsonData) -> ErrCode {
        if (adminRemoveFunc_.supplier_ == nullptr) {
            return ERR_EDM_NOT_EXIST_FUNC;
        }
        return (instance_.get()->*(adminRemoveFunc_.supplier_))();
    };
    adminRemoveFunc_ = AdminRemoveFunc(adminRemove, listener);
}

template<class CT, class DT>
void IPluginTemplate<CT, DT>::SetOnAdminRemoveListener(BiAdminFunction &&listener)
{
    if (instance_ == nullptr) {
        return;
    }
    auto adminRemove = [this](const std::string &adminName, const std::string &currentJsonData) -> ErrCode {
        DT currentData;
        if (!serializer_->Deserialize(currentJsonData, currentData)) {
            return ERR_EDM_OPERATE_JSON;
        }
        if (adminRemoveFunc_.biAdminFunction_ == nullptr) {
            return ERR_EDM_NOT_EXIST_FUNC;
        }
        return (instance_.get()->*(adminRemoveFunc_.biAdminFunction_))(adminName, currentData);
    };
    adminRemoveFunc_ = AdminRemoveFunc(adminRemove, listener);
}

template<class CT, class DT>
void IPluginTemplate<CT, DT>::OnAdminRemoveDone(const std::string &adminName, const std::string &currentJsonData)
{
    if (instance_ == nullptr) {
        return;
    }
    if (adminRemoveDoneFunc_.adminRemoveDone_ == nullptr) {
        return;
    }
    (adminRemoveDoneFunc_.adminRemoveDone_)(adminName, currentJsonData);
}

template<class CT, class DT>
void IPluginTemplate<CT, DT>::SetOnAdminRemoveDoneListener(Runner &&listener)
{
    if (instance_ == nullptr) {
        return;
    }
    auto adminRemoveDone = [this](const std::string &adminName, const std::string &currentJsonData) -> ErrCode {
        if (adminRemoveDoneFunc_.runner_ == nullptr) {
            return ERR_EDM_NOT_EXIST_FUNC;
        }
        (instance_.get()->*(adminRemoveDoneFunc_.runner_))();
        return ERR_OK;
    };
    adminRemoveDoneFunc_ = AdminRemoveDoneFunc(adminRemoveDone, listener);
}

template<class CT, class DT>
void IPluginTemplate<CT, DT>::SetOnAdminRemoveDoneListener(BiAdminConsumer &&listener)
{
    if (instance_ == nullptr) {
        return;
    }
    auto adminRemoveDone = [this](const std::string &adminName, const std::string &currentJsonData) -> ErrCode {
        if (adminRemoveDoneFunc_.biAdminConsumer_ == nullptr) {
            return ERR_EDM_NOT_EXIST_FUNC;
        }
        DT currentData;
        if (!serializer_->Deserialize(currentJsonData, currentData)) {
            return ERR_EDM_OPERATE_JSON;
        }
        (instance_.get()->*(adminRemoveDoneFunc_.biAdminConsumer_))(adminName, currentData);
        return ERR_OK;
    };
    adminRemoveDoneFunc_ = AdminRemoveDoneFunc(adminRemoveDone, listener);
}

template<class CT, class DT>
ErrCode IPluginTemplate<CT, DT>::WritePolicyToParcel(const std::string &policyData, MessageParcel &reply)
{
    DT currentData;
    if (!serializer_->Deserialize(policyData, currentData)) {
        return ERR_EDM_OPERATE_JSON;
    }
    if (!serializer_->WritePolicy(reply, currentData)) {
        return ERR_EDM_OPERATE_PARCEL;
    }
    return ERR_OK;
}

template<class CT, class DT>
bool IPluginTemplate<CT, DT>::GetMergePolicyData(DT &policyData)
{
    AdminValueItemsMap adminValues;
    PolicyManager::GetInstance()->GetAdminByPolicyName(GetPolicyName(), adminValues);
    if (adminValues.empty()) {
        return true;
    }
    if (adminValues.size() == 1) {
        for (const auto &item : adminValues) {
            if (!serializer_->Deserialize(item.second, policyData)) {
                return false;
            } else {
                return true;
            }
        }
    } else {
        std::vector<DT> adminValueArray;
        for (const auto &item : adminValues) {
            DT dataItem;
            if (!serializer_->Deserialize(item.second, dataItem)) {
                return false;
            }
            adminValueArray.push_back(dataItem);
        }
        if (!serializer_->MergePolicy(adminValueArray, policyData)) {
            return false;
        }
    }
    return true;
}

template<class CT, class DT>
void IPluginTemplate<CT, DT>::SetInstance(std::shared_ptr<CT> instance)
{
    instance_ = instance;
}

template<class CT, class DT>
void IPluginTemplate<CT, DT>::SetSerializer(std::shared_ptr<IPolicySerializer<DT>> serializer)
{
    serializer_ = serializer;
}

template<class CT, class DT>
void IPluginTemplate<CT, DT>::InitAttribute(
    uint32_t policyCode, const std::string &policyName, const std::string &permission, bool needSave, bool global)
{
    policyCode_ = policyCode;
    policyName_ = policyName;
    permission_ = permission;
    needSave_ = needSave;
    isGlobal_ = global;
}

template<class CT, class DT>
IPluginTemplate<CT, DT>::~IPluginTemplate()
{
    if (instance_ != nullptr) {
        instance_.reset();
        instance_ = nullptr;
    }
    if (serializer_ != nullptr) {
        serializer_.reset();
        serializer_ = nullptr;
    }
}

/*
 * Policy processing plugin singleton mode template,which needs to inherit the template.
 *
 * @tparam CT Policy processing logic class, which is the code to be implemented.
 * @tparam DT Policy data type, for example:string,vector<string>,map<string,string>...
 */
template<typename CT, typename DT>
class PluginSingleton : public NoCopyable {
public:
    /*
     * Initialize the plugin. The subclass needs to implement the pure virtual
     * function, define the code,name and permission of the plugin, and listen
     * to policy events.
     *
     * @param ptr std::shared_ptr<IPluginTemplate<CT, DT>>
     */
    virtual void InitPlugin(std::shared_ptr<IPluginTemplate<CT, DT>> ptr) = 0;

    /*
     * Obtains the singleton of the plugin interface.
     *
     * @return std::shared_ptr<IPlugin>
     */
    static std::shared_ptr<IPlugin> GetPlugin();

    static void DestroyPlugin();

private:
    static std::shared_ptr<IPluginTemplate<CT, DT>> pluginInstance_;
    static std::mutex mutexLock_;
};

template<typename CT, typename DT>
std::shared_ptr<IPluginTemplate<CT, DT>> PluginSingleton<CT, DT>::pluginInstance_ = nullptr;

template<typename CT, typename DT>
std::mutex PluginSingleton<CT, DT>::mutexLock_;

template<typename CT, typename DT>
std::shared_ptr<IPlugin> PluginSingleton<CT, DT>::GetPlugin()
{
    if (pluginInstance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutexLock_);
        if (pluginInstance_ == nullptr) {
            std::shared_ptr<CT> ptr = std::make_shared<CT>();
            pluginInstance_ = std::make_shared<IPluginTemplate<CT, DT>>();
            pluginInstance_->SetInstance(ptr);
            ptr->InitPlugin(pluginInstance_);
        }
    }
    return pluginInstance_;
}

template<typename CT, typename DT>
void PluginSingleton<CT, DT>::DestroyPlugin()
{
    std::lock_guard<std::mutex> lock(mutexLock_);
    if (pluginInstance_ != nullptr) {
        pluginInstance_.reset();
        pluginInstance_ = nullptr;
    }
}
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_INCLUDE_EDM_IPLUGIN_TEMPLATE_H
