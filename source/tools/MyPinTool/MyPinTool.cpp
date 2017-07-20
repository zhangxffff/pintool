
/*! @file
 *  This is an example of the PIN tool that demonstrates some basic PIN APIs 
 *  and could serve as the starting point for developing your first PIN tool
 */

#include <asm/unistd.h>
#include "pin.H"
#include <iostream>
#include <fstream>
#include <set>
#include <stack>
#include <ctype.h>
#include <map>
#include <list>
#include <algorithm>

#define DEBUG false

/* ================================================================== */
// Global variables 
/* ================================================================== */

static bool isMain = false;
static long long insCount = 0;
static stack<UINT32> shadowStack;

std::ostream * out = &cerr;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool",
    "o", "", "specify file name for MyPinTool output");

KNOB<BOOL>   KnobCount(KNOB_MODE_WRITEONCE,  "pintool",
    "count", "1", "count instructions, basic blocks and threads in the application");


/* ===================================================================== */
// Utilities
/* ===================================================================== */

/*!
 *  Print out help message.
 */
INT32 Usage() {
    cerr << "This tool prints out the number of dynamically executed " << endl <<
            "instructions, basic blocks and threads in the application." << endl << endl;

    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}

void handler(string *name) {
    insCount++;
    if (isMain) cout << *name << endl;
}

int callCount = 0;
int retCount = 0;

void callHandler(UINT32 esp) {
    if (!isMain) return;
    shadowStack.push(esp - 4);
    callCount++;
}

void retHandler(UINT32 esp) {
    if (!isMain) return;
    retCount++;
    if (shadowStack.empty()) {
        cout << "empty" << endl;
    } else {
        if (shadowStack.top() != esp) {
            cout << "ERROR: ret addr not match " << hex << esp << " " << shadowStack.top() << endl;
        }
        shadowStack.pop();
    }
}


VOID Instruction(INS ins, VOID *v) {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)handler, IARG_PTR, new string(INS_Disassemble(ins)), IARG_END);
    if (INS_IsCall(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)callHandler, IARG_REG_VALUE, REG_ESP, IARG_END);
    } else if (INS_IsRet(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)retHandler, IARG_REG_VALUE, REG_ESP, IARG_END);
    }
}


void triggerMain() {
    isMain = !isMain;
    if (isMain) cerr << "========[Main Function Begin]========" << endl;
    else cerr << "=========[Main Function End]=========" << endl;
}

bool isValidId(const string& str) {
    if (str.empty()) return false;
    if (!(isalpha(str[0]) || str[0] == '_')) return false;
    for (size_t i = 0; i < str.size(); i++) {
        if (!(isalnum(str[i]) || str[i] == '_')) return false;
    }
    return true;
}

map<string, int> rtnCount;

void rtnHandler(string *name) {
    if (rtnCount.find(*name) == rtnCount.end()) {
        rtnCount[*name] = 0;
    } else {
        rtnCount[*name]++;
    }
}

VOID Routine(RTN rtn, VOID *v) {
    RTN_Open(rtn);

    if (RTN_Name(rtn) == "_start") {
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)triggerMain, IARG_END);
    }
    /*
    if (isValidId(RTN_Name(rtn))) {
    */
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)rtnHandler,
                IARG_PTR, new string(RTN_Name(rtn)),
                IARG_REG_VALUE, REG_ESP, IARG_END);
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)rtnHandler,
                IARG_PTR, new string(RTN_Name(rtn)),
                IARG_REG_VALUE, REG_ESP, IARG_END);
/*
    }
    */
    if (RTN_Name(rtn) == "_start") {
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)triggerMain, IARG_END);
    }

    RTN_Close(rtn);
}


VOID Image(IMG img, VOID *v) {
}

/*!
 * Print out analysis results.
 * This function is called when the application exits.
 * @param[in]   code            exit code of the application
 * @param[in]   v               value specified by the tool in the 
 *                              PIN_AddFiniFunction function call
 */
VOID Fini(INT32 code, VOID *v) {
    cout << insCount << endl;
    cout << "call count: " << dec << callCount << endl;
    cout << "ret count: " << retCount << endl;
    for (map<string, int>::iterator p = rtnCount.begin(); p != rtnCount.end(); p++) {
        cout << p->first << ": " << p->second << endl;
    }
}


static bool firstRead = true;

VOID Syscall_entry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v) {

    if (PIN_GetSyscallNumber(ctx, std) == __NR_read) {
        if (firstRead) {
            firstRead = false;
            return;
        }

    }
}

/*!
 * The main procedure of the tool.
 * This function is called when the application image is loaded but not yet started.
 * @param[in]   argc            total number of elements in the argv array
 * @param[in]   argv            array of command line arguments, 
 *                              including pin -t <toolname> -- ...
 */
int main(int argc, char *argv[]) {
    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid 
    if( PIN_Init(argc,argv) ) {
        return Usage();
    }
    
    string fileName = KnobOutputFile.Value();

    if (!fileName.empty()) { out = new std::ofstream(fileName.c_str());}

    if (KnobCount) {

        PIN_InitSymbols();
        PIN_AddSyscallEntryFunction(Syscall_entry, 0);
        //IMG_AddInstrumentFunction(Image, 0);
        RTN_AddInstrumentFunction(Routine, 0);
        INS_AddInstrumentFunction(Instruction, 0);

        // Register function to be called when the application exits
        PIN_AddFiniFunction(Fini, 0);
    }
    
    cerr <<  "===============================================" << endl;
    cerr <<  "This application is instrumented by MyPinTool" << endl;
    if (!KnobOutputFile.Value().empty()) {
        cerr << "See file " << KnobOutputFile.Value() << " for analysis results" << endl;
    }
    cerr <<  "===============================================" << endl;

    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}

