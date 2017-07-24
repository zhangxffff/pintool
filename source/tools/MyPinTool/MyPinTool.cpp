
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
static vector<UINT32> shadowStack;
static vector<ADDRINT> bblVector;

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

void callHandler(UINT32 esp) {
    //if (!isMain) return;
    shadowStack.push_back(esp - 4);
}

void retHandler(UINT32 esp) {
    //if (!isMain) return;
    if (shadowStack.empty()) {
        cout << "[Warning]: empty" << endl;
    } else {
        if (shadowStack.back() != esp) {
            cout << "[Warning]: ret addr not match 0x" << hex << esp << " 0x" << shadowStack.back() << endl;
        }
        if (shadowStack.back() == esp) {
            shadowStack.pop_back();
        } else if (shadowStack.back() > esp) {
            return;
        } else {
            shadowStack.pop_back();
            retHandler(esp);
        }
    }
}

void memWriteHandler(string *ins, ADDRINT addr, UINT32 size, UINT32 value) {
    //cout << *ins << "\t" << size << hex << "\t0x" << addr << "\t" << dec << value << endl;
    if (find(shadowStack.rbegin(), shadowStack.rend(), addr) != shadowStack.rend()) {
        cout << "Write ret addr: " << "0x" << addr << "\tvalue: " << value << endl;
    }
}

void bblHandler(ADDRINT addr, string *str) {
    if (!isMain) return;
    bblVector.push_back(addr);
    //cout << *str << " " << addr << endl;
}


VOID Instruction(INS ins, VOID *v) {
    //recode ret addr in shadow stack
    if (INS_IsCall(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)callHandler, IARG_REG_VALUE, REG_ESP, IARG_END);
    } else if (INS_IsRet(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)retHandler, IARG_REG_VALUE, REG_ESP, IARG_END);
    }

    if (INS_IsMemoryWrite(ins)) {
        if (INS_IsMov(ins)) {
            if (INS_OperandIsReg(ins, 1)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)memWriteHandler,
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_MEMORYOP_EA, 0,
                        IARG_UINT32, INS_MemoryWriteSize(ins),
                        IARG_REG_VALUE, INS_OperandReg(ins, 1), IARG_END);
            } else if (INS_OperandIsImmediate(ins, 1)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)memWriteHandler,
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_MEMORYOP_EA, 0,
                        IARG_UINT32, INS_MemoryWriteSize(ins),
                        IARG_UINT64, INS_OperandImmediate(ins, 1), IARG_END);
            }
        }
    }

}

VOID Trace(TRACE trace, VOID *v) {
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        if (RTN_Valid(INS_Rtn(BBL_InsTail(bbl))))
        BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)bblHandler,
                IARG_ADDRINT, BBL_Address(bbl),
                IARG_PTR, new string(RTN_Name(INS_Rtn(BBL_InsTail(bbl)))), IARG_END);
    }
}

void triggerMain() {
    isMain = !isMain;
    if (isMain) cerr << "========[_start Begin]========" << endl;
    else cerr << "=========[_start End]=========" << endl;
}

bool isValidId(const string& str) {
    if (str.empty()) return false;
    if (!(isalpha(str[0]) || str[0] == '_')) return false;
    for (size_t i = 0; i < str.size(); i++) {
        if (!(isalnum(str[i]) || str[i] == '_')) return false;
    }
    return true;
}

static map<string, int> rtnMap;

void mallocHandler(ADDRINT size) {
    if (!isMain) return;
    cout << dec << size << endl;
}

void mallocResultHandler(string *addr) {
    if (!isMain) return;
    cout << hex << "0x" << *addr << endl;
}

VOID Routine(RTN rtn, VOID *v) {
    RTN_Open(rtn);

    if (RTN_Name(rtn) == "__libc_malloc"){
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)mallocHandler,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
        INS_InsertCall(RTN_InsHead(rtn), IPOINT_BEFORE, (AFUNPTR)mallocResultHandler,
                IARG_PTR, new string(INS_Disassemble(RTN_InsHead(rtn))), IARG_END);
    }

    if (RTN_Name(rtn) == "_start") {
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)triggerMain, IARG_END);
    }
    if (RTN_Name(rtn) == "_start") {
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)triggerMain, IARG_END);
    }

    /*
    if (isValidId(RTN_Name(rtn))) {
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)rtnHandler,
                IARG_PTR, new string(RTN_Name(rtn)),
                IARG_REG_VALUE, REG_ESP, IARG_END);
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)rtnHandler,
                IARG_PTR, new string(RTN_Name(rtn)),
                IARG_REG_VALUE, REG_ESP, IARG_END);
    }
    if (RTN_Name(rtn) == ".plt") {
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)triggerPLT, IARG_END);
    }

    if (RTN_Name(rtn) == ".plt") {
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)triggerPLT, IARG_END);
    }
    */

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
    /*
    cout << shadowStack.size() << endl;
    for (vector<ADDRINT>::iterator t = bblVector.begin(); t != bblVector.end(); t++) {
        cout << "0x" << hex << *t << endl;
    }
    for (map<string, int>::iterator it = rtnMap.begin(); it != rtnMap.end(); it++) {
        cout << it->first << " " << it->second << endl;
    }
    */
}



VOID Syscall_entry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v) {
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
        TRACE_AddInstrumentFunction(Trace, 0);

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

