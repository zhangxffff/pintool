
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

struct ReadEntity {
    UINT32 start;
    UINT32 size;
    char *data;
};

/* ================================================================== */
// Global variables 
/* ================================================================== */

static bool isStart = true;
static vector<UINT32> shadowStack;
static vector<ADDRINT> bblVector;
static vector<string*> bblRoutineVector;
static string inputFileName;
static string inputFilePath;
static list<pair<ADDRINT, ADDRINT> > mallocMem;
static vector<ReadEntity> readEntities;
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
    if (!isStart) return;
    shadowStack.push_back(esp - 4);
}

void retHandler(UINT32 esp) {
    if (!isStart) return;
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
    if (find(shadowStack.rbegin(), shadowStack.rend(), addr) != shadowStack.rend()) {
        cout << "[Write ret addr]\t" << "0x" << addr << "\t" << size << "\t" << value << endl;
    }
}

void memModifyHandler(ADDRINT addr, UINT32 size) {
    if (find(shadowStack.rbegin(), shadowStack.rend(), addr) != shadowStack.rend()) {
        cout << "[Modify ret addr]\t" << "0x" << addr << "\t" << size << endl;
    }
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
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)memModifyHandler,
                        IARG_PTR, new string(INS_Disassemble(ins)),
                        IARG_MEMORYOP_EA, 0,
                        IARG_UINT32, INS_MemoryWriteSize(ins),
                        IARG_UINT64, INS_OperandImmediate(ins, 1), IARG_END);
            }
        } else {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)memWriteHandler,
                    IARG_MEMORYOP_EA, 0,
                    IARG_UINT32, INS_MemoryWriteSize(ins), IARG_END);
        }
    }
}

string stripPath(const string &name) {
    size_t pos = name.rfind('/');
    if (pos != string::npos) {
        return name.substr(pos + 1);
    } else {
        return name;
    }
}

string stripName(const string &name) {
    size_t pos = name.rfind('/');
    if (pos != string::npos) {
        return name.substr(0, pos + 1);
    } else {
        return "./";
    }
}

void bblHandler(ADDRINT addr, string *str) {
    if (!isStart) return;
    if (!bblRoutineVector.empty() && 
            *str == *(bblRoutineVector.back()) && str->rfind("plt") == str->size() - 3) return;
    if (*str == ".plt") return;
    bblVector.push_back(addr);
    bblRoutineVector.push_back(str);
    //cout << "0x" << hex << addr << " " << *str << endl;
}

void outputTraceToFile() {
    string outputFileName = inputFilePath + inputFileName + ".trace";
    ofstream file;
    file.open(outputFileName.c_str(), ios::out | ios::binary);
    for (vector<ADDRINT>::iterator it = bblVector.begin(); it != bblVector.end(); it++) {
        file.write((char *)&*it, sizeof(ADDRINT));
    }
}

VOID Trace(TRACE trace, VOID *v) {
    RTN rtn = TRACE_Rtn(trace);
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        if (RTN_Valid(rtn) &&
                inputFileName == stripPath(IMG_Name(SEC_Img(RTN_Sec(rtn)))))
            BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)bblHandler,
                    IARG_ADDRINT, BBL_Address(bbl),
                    IARG_PTR, new string(RTN_Name(INS_Rtn(BBL_InsTail(bbl)))), IARG_END);
    }
}

void triggerMain() {
    isStart = !isStart;
    if (isStart) cerr << "========[_start Begin]========" << endl;
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

VOID Routine(RTN rtn, VOID *v) {
    RTN_Open(rtn);

    /*
    if (RTN_Name(rtn) == "_start") {
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)triggerMain, IARG_END);
    }
    if (RTN_Name(rtn) == "_start") {
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)triggerMain, IARG_END);
    }
    */

    RTN_Close(rtn);
}

void mallocHandler(ADDRINT size) {
    if (!isStart) return;
    mallocMem.push_back(make_pair(0, size));
}

void mallocResultHandler(ADDRINT addr) {
    if (!isStart) return;
    if (mallocMem.empty() || mallocMem.back().first != 0) {
        // should be error
    } else {
        mallocMem.back().first = addr;
    }
}

void freeHandler(ADDRINT addr) {
    if (!isStart) return;
    typeof(mallocMem.begin()) it;
    for (it = mallocMem.begin(); it != mallocMem.end(); it++) {
        if (it->first == addr) {
            break;
        }
    }
    if (it == mallocMem.end()) {
        //TODO free a unrelated address
    } else {
        mallocMem.erase(it);
    }
}


VOID Image(IMG img, VOID *v) {
    RTN rtn = RTN_FindByName(img, "malloc");
    if (RTN_Valid(rtn)) {
        RTN_Open(rtn);
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)mallocHandler,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)mallocResultHandler,
                IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
        RTN_Close(rtn);
    }
    rtn = RTN_FindByName(img, "free");
    if (RTN_Valid(rtn)) {
        RTN_Open(rtn);
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)freeHandler,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
        RTN_Close(rtn);
    }
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
    for (vector<ADDRINT>::iterator t = bblVector.begin(); t != bblVector.end(); t++) {
        cout << "0x" << hex << *t << endl;
    }
    for (map<string, int>::iterator it = rtnMap.begin(); it != rtnMap.end(); it++) {
        cout << it->first << " " << it->second << endl;
    }
    */
    outputTraceToFile();
}


void Syscall_exit(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v) {
    if (PIN_GetSyscallNumber(ctx, std) == __NR_read) {
        cout << "read exit" << endl;
        if (readEntities.empty() || readEntities.back().data != NULL) {
            cout << "read enter error" << endl;
        } else {
            UINT64 start = readEntities.back().start;
            UINT32 size = readEntities.back().size;
            readEntities.back().data = new char[size];
            PIN_SafeCopy(readEntities.back().data, (VOID *)start, size);
            cout << readEntities.back().data << endl;
        }
    }
}


VOID Syscall_entry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v) {
    if (PIN_GetSyscallNumber(ctx, std) == __NR_read) {
        ReadEntity entity;
        entity.start = PIN_GetSyscallArgument(ctx, std, 1);
        entity.size = PIN_GetSyscallArgument(ctx, std, 2);
        entity.data = NULL;
        readEntities.push_back(entity);
        //cout << "read " << entity.size << " to 0x" << hex << entity.start << endl;

        for (vector<UINT32>::iterator it = shadowStack.begin(); it != shadowStack.end(); it++) {
            if (*it >= entity.start && *it <= entity.start + entity.size) {
                cout << "[write] ret addr 0x" << hex << *it << endl;
            }
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

    // Get Input File Name
    for (int i = 0; i < argc; i++) {
        if(strcmp(argv[i], "--") == 0) {
            inputFileName = stripPath(argv[i + 1]);
            inputFilePath = stripName(argv[i + 1]);
            break;
        }
    }
    if (inputFileName.empty()) return Usage();

    string fileName = KnobOutputFile.Value();

    if (!fileName.empty()) { out = new std::ofstream(fileName.c_str());}

    if (KnobCount) {

        PIN_InitSymbols();
        PIN_AddSyscallEntryFunction(Syscall_entry, 0);
        //PIN_AddSyscallExitFunction(Syscall_exit, 0);
        IMG_AddInstrumentFunction(Image, 0);
        RTN_AddInstrumentFunction(Routine, 0);
        INS_AddInstrumentFunction(Instruction, 0);
        TRACE_AddInstrumentFunction(Trace, 0);

        // Register function to be called when the application exits
        PIN_AddFiniFunction(Fini, 0);
    }
    
    if (!KnobOutputFile.Value().empty()) {
        cerr << "See file " << KnobOutputFile.Value() << " for analysis results" << endl;
    }

    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}

