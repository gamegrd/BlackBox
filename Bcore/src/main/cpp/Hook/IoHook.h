//
// Created by harold on 17/5/22.
//

#ifndef BLACKBOX_IOHOOK_H
#define BLACKBOX_IOHOOK_H

#include "dobby.h"
#include "Log.h"

class IoHook {
public:
    IoHook(){
    }
    ~IoHook(){
    }

    static IoHook* get_instance(){
        IoHook* ctx = nullptr;
        if (!ctx){
            ctx =  new IoHook();
            ALOGD("=========IoHook===========");
        }
        return ctx;
    }
};


#endif //BLACKBOX_IOHOOK_H
