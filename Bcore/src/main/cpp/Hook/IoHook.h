//
// Created by harold on 17/5/22.
//

#ifndef BLACKBOX_IOHOOK_H
#define BLACKBOX_IOHOOK_H

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <dlfcn.h>

#include "dobby.h"
#include "Log.h"


#define HOOK_SYMBOL(handle, func) hook_function(handle, #func, (void*) new_##func, (void**) &orig_##func)

#define HOOK_DEF(ret, func, ...) \
  ret (*orig_##func)(__VA_ARGS__); \
  ret new_##func(__VA_ARGS__)



class IoHook {
public:
    IoHook(){
        void *handle = NULL;
    }
    ~IoHook(){
    }

    static IoHook* get_instance();
};


#endif //BLACKBOX_IOHOOK_H
