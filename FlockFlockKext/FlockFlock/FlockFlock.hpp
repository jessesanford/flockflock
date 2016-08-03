//
//  FlockFlock.hpp
//  FlockFlock
//
//  Created by Jonathan Zdziarski on 7/29/16.
//  Copyright © 2016 Jonathan Zdziarski. All rights reserved.
//

#ifndef __FLOCKFLOCK_HPP_
#define __FLOCKFLOCK_HPP_

#include <IOKit/IOService.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOLocks.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/kern_event.h>
#include <sys/kauth.h>
#include <sys/types.h>
#include <sys/kern_event.h>
#include <libkern/libkern.h>
#include <mach/mach_types.h>
#include <security/mac.h>
#include <security/mac_policy.h>
#include <security/mac_framework.h>
#include "FlockFlockClientShared.h"

struct mach_query_context
{
    IOLock *policy_lock, *reply_lock;
    struct policy_query_msg message;
    struct policy_response response;
    uint32_t security_token;
};

/* was going to use OSDictinoary but it's just an array too, so... */
struct pid_path
{
    uid_t uid;
    gid_t gid;
    pid_t pid;
    pid_t ppid;
    uint64_t tid;
    
    char path[PATH_MAX];
    struct pid_path *next;
};

struct posix_spawn_map
{
    pid_t pid;
    pid_t ppid;
    uint64_t tid;
    struct posix_spawn_map *next;
};

class com_zdziarski_driver_FlockFlock : public IOService
{
    OSDeclareDefaultStructors(com_zdziarski_driver_FlockFlock)
    
public:
    virtual bool init(OSDictionary *dictionary = NULL) override;
    virtual IOService *probe(IOService *provider, SInt32* score) override;
    virtual bool start(IOService *provider) override;
    virtual void stop(IOService *provider) override;
    virtual void free(void) override;
    virtual IOReturn setProperties(OSObject* properties) override;
    
    /* MAC policy methods and static hooks */
    
    static int ff_vnode_check_open_static(OSObject *provider, kauth_cred_t cred, struct vnode *vp, struct label *label, int acc_mode);
    int ff_vnode_check_open(kauth_cred_t cred, struct vnode *vp, struct label *label, int acc_mode);
    
    static int ff_kauth_callback_static(OSObject *provider, kauth_cred_t credential, void* idata, kauth_action_t action, uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3);
    int ff_kauth_callback(kauth_cred_t credential, void* idata, kauth_action_t action, uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3);

    static void ff_cred_label_associate_fork_static(OSObject *provider, kauth_cred_t cred, proc_t proc);
    void ff_cred_label_associate_fork(kauth_cred_t cred, proc_t proc);
    
    static int ff_get_agent_pid_static(OSObject *provider);
    int ff_evaluate_vnode_check_open(struct policy_query *);

    /* IOUserClient methods */
    bool startFilter();
    bool stopFilter();
    void clearMachPort();
    void clearAllRules();
    bool setMachPort(mach_port_t port);
    kern_return_t addClientPolicy(FlockFlockClientPolicy policy);

private:
    bool startPersistence();
    bool stopPersistence();

    bool initQueryContext(mach_query_context *context);
    void destroyQueryContext(mach_query_context *context);

    int sendPolicyQuery(struct policy_query *query, struct mach_query_context *context, bool lock);
    bool receivePolicyResponse(struct policy_response *response, struct mach_query_context *context);
    void houseKeeping(void);
    void houseKeepPosixSpawnMap();
    void houseKeepPathTable();
    void houseKeepMasterRuleTable();

public:
    mach_port_t notificationPort;
    struct mach_query_context policyContext;
    uint32_t userAgentPID;

private:
    bool filterActive, shouldStop;
    IOLock *lock;
    FlockFlockPolicyHierarchy policyRoot;
    FlockFlockPolicy lastPolicyAdded;
    struct pid_path *pid_root;
    struct posix_spawn_map *pid_map, *map_last_insert;
    
    /* file access MAC policy */
    mac_policy_handle_t policyHandle;
    struct mac_policy_ops policyOps;
    struct mac_policy_conf policyConf;
    
    /* persistence MAC policy; prevents tampering with FlockFlock core files */
    mac_policy_handle_t persistenceHandle;
    struct mac_policy_ops persistenceOps;
    struct mac_policy_conf persistenceConf;
    kauth_listener_t kauthListener = NULL;
};

#endif