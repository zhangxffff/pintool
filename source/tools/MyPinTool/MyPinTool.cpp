
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

static bool isMain = true;
std::vector<UINT32> stackTopAddr;
std::map<REG, UINT32> regTaintBy;
std::map<UINT32, UINT32> addrTaintBy;
std::list<std::pair<UINT32, UINT32> > inputList;

void addrTaintedFrom(UINT32 addr, UINT32 inputAddr) {
    typeof(inputList.begin()) it = inputList.end();
    for (int i = inputList.size() - 1; i >= 0; i--) {
        it--;
        if (it->first <= inputAddr && inputAddr < it->first + it->second) {
            cerr << "[FATAL] Addr 0x" << std::hex << addr;
            cerr << "was tainted by " << inputAddr - it->first;
            cerr << " bytes of " << i << "th input" << endl;
        }
    }
}

UINT32 findTaintSrc(UINT32 addr) {
    while (addrTaintBy.find(addr) != addrTaintBy.end()) {
        if (addrTaintBy[addr] == addr) {
            return addr;
        } else {
            addr = addrTaintBy[addr];
        }
    }
    return 0;
}

void taintAddr(UINT32 addr, UINT32 inputAddr) {
    if (!isMain) return;
    //cerr << "[Affact]\t0x" << std::hex << addr << " by 0x" << inputAddr << endl;
    if (findTaintSrc(inputAddr) != 0) {
        addrTaintBy[addr] = findTaintSrc(inputAddr);
        if (DEBUG) cerr << "[Taint]\t0x" << std::hex << addr << " by 0x" << inputAddr << endl;
        if (std::find(stackTopAddr.begin(), stackTopAddr.end(), addr) != stackTopAddr.end()) {
            addrTaintedFrom(addr, addrTaintBy[addr]);
        }

    }
}

void untaintAddr(UINT32 addr) {
    if (!isMain) return;
    for (std::map<UINT32, UINT32>::iterator i = addrTaintBy.begin(); i != addrTaintBy.end(); ) {
        if (i->second == addr) {
            addrTaintBy.erase(i++);
        } else {
            i++;
        }
    }
    for (std::map<REG, UINT32>::iterator i = regTaintBy.begin(); i!= regTaintBy.end(); ) {
        if (i->second == addr) {
            regTaintBy.erase(i++);
        } else {
            i++;
        }
    }
}

void taintSomeAddr(UINT32 addr, UINT32 size) {
    for (UINT32 i = 0; i < size; i++) {
        untaintAddr(addr + i);
        addrTaintBy[addr + i] = addr + i;
    }
}

void untaintReg(REG reg) {
    if (!isMain) return;
    switch (reg) {
        case REG_EAX: case REG_AX: case REG_AH: case REG_AL:
            regTaintBy.erase(REG_EAX);
            regTaintBy.erase(REG_AX);
            if (reg != REG_AH) regTaintBy.erase(REG_AL);
            if (reg != REG_AL) regTaintBy.erase(REG_AH);
            break;

        case REG_EBX: case REG_BX: case REG_BH: case REG_BL:
            regTaintBy.erase(REG_EBX);
            regTaintBy.erase(REG_BX);
            if (reg != REG_BH) regTaintBy.erase(REG_BL);
            if (reg != REG_BL) regTaintBy.erase(REG_BH);
            break;

        case REG_ECX: case REG_CX: case REG_CH: case REG_CL:
            regTaintBy.erase(REG_ECX);
            regTaintBy.erase(REG_CX);
            if (reg != REG_CH) regTaintBy.erase(REG_CL);
            if (reg != REG_CL) regTaintBy.erase(REG_CH);
            break;

        case REG_EDX: case REG_DX: case REG_DH: case REG_DL:
            regTaintBy.erase(REG_EDX);
            regTaintBy.erase(REG_DX);
            if (reg != REG_DH) regTaintBy.erase(REG_DL);
            if (reg != REG_DL) regTaintBy.erase(REG_DH);
            break;

        default:
            regTaintBy.erase(reg);
    }
}

void taintRegByAddr(REG reg, UINT32 addr) {
    if (!isMain) return;
    //cerr << "[Affact]\t" << REG_StringShort(reg) << " by \t0x" << std::hex << addr << endl;
    if (findTaintSrc(addr) == 0) { 
        untaintReg(reg);
        return;
    }
    if (DEBUG) cerr << "[Taint]\t" << REG_StringShort(reg) << " by \t0x" << std::hex << addr << endl;
    switch (reg) {
        case REG_EAX:
            regTaintBy[REG_EAX] = addr;
            regTaintBy[REG_AX] = addr;
            regTaintBy[REG_AH] = addr + 1;
            regTaintBy[REG_AL] = addr;
            break;
        case REG_AX:
            regTaintBy.erase(REG_EAX);
            regTaintBy[REG_AX] = addr;
            regTaintBy[REG_AH] = addr + 1;
            regTaintBy[REG_AL] = addr;
            break;
        case REG_AH: case REG_AL:
            regTaintBy.erase(REG_EAX);
            regTaintBy.erase(REG_AX);
            regTaintBy[reg] = addr;
            break;

        case REG_EBX:
            regTaintBy[REG_EBX] = addr;
            regTaintBy[REG_BX] = addr;
            regTaintBy[REG_BH] = addr + 1;
            regTaintBy[REG_BL] = addr;
            break;
        case REG_BX:
            regTaintBy.erase(REG_EBX);
            regTaintBy[REG_BX] = addr;
            regTaintBy[REG_BH] = addr + 1;
            regTaintBy[REG_BL] = addr;
            break;
        case REG_BH: case REG_BL:
            regTaintBy.erase(REG_EBX);
            regTaintBy.erase(REG_BX);
            regTaintBy[reg] = addr;
            break;

        case REG_ECX:
            regTaintBy[REG_ECX] = addr;
            regTaintBy[REG_CX] = addr;
            regTaintBy[REG_CH] = addr + 1;
            regTaintBy[REG_CL] = addr;
            break;
        case REG_CX:
            regTaintBy.erase(REG_ECX);
            regTaintBy[REG_CX] = addr;
            regTaintBy[REG_CH] = addr + 1;
            regTaintBy[REG_CL] = addr;
            break;
        case REG_CH: case REG_CL:
            regTaintBy.erase(REG_ECX);
            regTaintBy.erase(REG_CX);
            regTaintBy[reg] = addr;
            break;

        case REG_EDX:
            regTaintBy[REG_EDX] = addr;
            regTaintBy[REG_DX] = addr;
            regTaintBy[REG_DH] = addr + 1;
            regTaintBy[REG_DL] = addr;
            break;
        case REG_DX:
            regTaintBy.erase(REG_EDX);
            regTaintBy[REG_DX] = addr;
            regTaintBy[REG_DH] = addr + 1;
            regTaintBy[REG_DL] = addr;
            break;
        case REG_DH: case REG_DL:
            regTaintBy.erase(REG_EDX);
            regTaintBy.erase(REG_DX);
            regTaintBy[reg] = addr;
            break;

        default:
            regTaintBy[reg] = addr;
    }
}

void taintRegByReg(REG desReg, REG srcReg) {
    if (!isMain) return;
    //cerr << "[Affact]\t" << REG_StringShort(desReg) << " by \t" << REG_StringShort(srcReg) << endl;
    if (regTaintBy.find(srcReg) == regTaintBy.end()) return;
    taintRegByAddr(desReg, regTaintBy[srcReg]);
    if (DEBUG) cerr << "[Taint]\t" << REG_StringShort(desReg) << " by \t" << REG_StringShort(srcReg) << endl;
}

void taintAddrByReg(UINT32 addr, REG reg) {
    if (!isMain) return;
    //cerr << "[Affact]\t0x" << std::hex << addr << " by \t" << REG_StringShort(reg) << endl;
    if (regTaintBy.find(reg) == regTaintBy.end()) return;
    else taintAddr(addr, regTaintBy[reg]);
    if (DEBUG) cerr << "[Taint]\t0x" << std::hex << addr << " by \t" << REG_StringShort(reg) << endl;
}

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

void dotaint(void *str) {
    if (!isMain) return;
    cerr << *(string *)str << endl;
}

VOID Instruction(INS ins, VOID *v) {
    if (INS_MemoryOperandCount(ins) == 2 && !INS_IsCall(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)taintAddr,
                IARG_MEMORYOP_EA, 0,
                IARG_MEMORYOP_EA, 0, IARG_END);

    } else if (INS_MemoryOperandCount(ins) == 1 && INS_MemoryOperandIsRead(ins, 0)
            && INS_OperandIsReg(ins, 0) && !INS_OperandRead(ins, 0)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)taintRegByAddr,
                IARG_UINT32, INS_RegW(ins, 0),
                IARG_MEMORYOP_EA, 0, IARG_END);
    } else if (INS_MemoryOperandCount(ins) == 1 && INS_MemoryOperandIsWritten(ins, 0)
            && (INS_OperandIsReg(ins, 0) || INS_OperandIsReg(ins, 1))
            && !INS_MemoryOperandIsRead(ins, 0)) {
        REG reg;
        if (INS_OperandIsReg(ins, 0)) reg = INS_OperandReg(ins, 0);
        else reg = INS_OperandReg(ins, 1);
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)taintAddrByReg,
                IARG_MEMORYOP_EA, 0,
                IARG_UINT32, reg, IARG_END);
    } else if (INS_OperandCount(ins) > 1 && INS_OperandIsReg(ins, 0) 
            && INS_OperandIsReg(ins, 1) && !INS_OperandRead(ins, 0)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)taintRegByReg,
                IARG_UINT32, INS_OperandReg(ins, 0),
                IARG_UINT32, INS_OperandReg(ins, 1), IARG_END);
    }
}


void triggerMain() {
    isMain = !isMain;
    if (isMain) cerr << "========[Main Function Begin]========" << endl;
    else cerr << "=========[Main Function End]=========" << endl;
}

void pushStackAddr(void *rtnName, UINT32 addr) {
    if (!isMain) return;
    cerr << "Enter 0x" << std::hex << addr << "\t" << *(string*)rtnName << endl;
    stackTopAddr.push_back(addr);
}
void popStackAddr(void *rtnName) {
    if (!isMain) return;
    if (stackTopAddr.empty()) return;
    cerr << "Leave 0x" << std::hex << stackTopAddr.back() << "\t" << *(string*)rtnName << endl;
    stackTopAddr.pop_back();
}


bool isValidId(const string& str) {
    if (str.empty()) return false;
    if (!(isalpha(str[0]) || str[0] == '_')) return false;
    for (size_t i = 0; i < str.size(); i++) {
        if (!(isalnum(str[i]) || str[i] == '_')) return false;
    }
    return true;
}
VOID Routine(RTN rtn, VOID *v) {
    RTN_Open(rtn);

    if (RTN_Name(rtn) == "main") {
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)triggerMain, IARG_END);
    }
    if (isValidId(RTN_Name(rtn))) {
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)pushStackAddr,
                IARG_PTR, new string(RTN_Name(rtn)),
                IARG_REG_VALUE, REG_ESP, IARG_END);
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)popStackAddr,
                IARG_PTR, new string(RTN_Name(rtn)),
                IARG_END);
    }
    if (RTN_Name(rtn) == "main") {
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
}


static bool firstRead = true;

VOID Syscall_entry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v) {
    UINT32 start, size;

    if (PIN_GetSyscallNumber(ctx, std) == __NR_read) {
        if (firstRead) {
            firstRead = false;
            return;
        }

        start = static_cast<UINT32>((PIN_GetSyscallArgument(ctx, std, 1)));
        size  = static_cast<UINT32>((PIN_GetSyscallArgument(ctx, std, 2)));

        taintSomeAddr(start, size);
        inputList.push_back(std::make_pair(start, size));
        cerr << "[READ]\tbytes from " << std::hex << "0x" << start << " to 0x" << start+size << std::endl;
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

