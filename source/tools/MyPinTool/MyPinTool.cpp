
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

/* ================================================================== */
// Global variables 
/* ================================================================== */

static bool isMain = false;
std::set<UINT32> taintedAddr;
std::set<REG> taintedReg;
std::stack<UINT32> stackTopAddr;
std::map<REG, UINT32> regTaintBy;
std::map<UINT32, UINT32> addrTaintBy;


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
    if (findTaintSrc(inputAddr) != 0) {
        addrTaintBy[addr] = inputAddr;
        cout << "[Taint]\t0x" << std::hex << addr << " by 0x" << inputAddr << endl;
    }
}

void taintSomeAddr(UINT32 addr, UINT32 size) {
    for (UINT32 i = 0; i < size; i++) {
        addrTaintBy[addr + i] = addr + i;
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
    if (findTaintSrc(addr) == 0) untaintReg(reg);
    cout << "[Taint]\t" << REG_StringShort(reg) << " by \t0x" << std::hex << addr << endl;
    switch (reg) {
        case REG_EAX:
            regTaintBy[REG_EAX] = addr;
            regTaintBy[REG_AX] = addr;
            regTaintBy[REG_AH] = addr + 1;
            regTaintBy[REG_AL] = addr;
            break;
        case REG_AX:
            regTaintBy[REG_EAX] = 0;
            regTaintBy[REG_AX] = addr;
            regTaintBy[REG_AH] = addr + 1;
            regTaintBy[REG_AL] = addr;
            break;
        case REG_AH:
            regTaintBy[REG_EAX] = 0;
            regTaintBy[REG_AX] = 0;
            regTaintBy[REG_AH] = addr;
            break;
        case REG_AL:
            regTaintBy[REG_EAX] = 0;
            regTaintBy[REG_AX] = 0;
            regTaintBy[REG_AL] = addr;
            break;

        case REG_EBX:
            regTaintBy[REG_EBX] = addr;
            regTaintBy[REG_BX] = addr;
            regTaintBy[REG_BH] = addr + 1;
            regTaintBy[REG_BL] = addr;
            break;
        case REG_BX:
            regTaintBy[REG_EBX] = 0;
            regTaintBy[REG_BX] = addr;
            regTaintBy[REG_BH] = addr + 1;
            regTaintBy[REG_BL] = addr;
            break;
        case REG_BH:
            regTaintBy[REG_EBX] = 0;
            regTaintBy[REG_BX] = 0;
            regTaintBy[REG_BH] = addr;
            break;
        case REG_BL:
            regTaintBy[REG_EBX] = 0;
            regTaintBy[REG_BX] = 0;
            regTaintBy[REG_BL] = addr;
            break;

        case REG_ECX:
            regTaintBy[REG_ECX] = addr;
            regTaintBy[REG_CX] = addr;
            regTaintBy[REG_CH] = addr + 1;
            regTaintBy[REG_CL] = addr;
            break;
        case REG_CX:
            regTaintBy[REG_ECX] = 0;
            regTaintBy[REG_CX] = addr;
            regTaintBy[REG_CH] = addr + 1;
            regTaintBy[REG_CL] = addr;
            break;
        case REG_CH:
            regTaintBy[REG_ECX] = 0;
            regTaintBy[REG_CX] = 0;
            regTaintBy[REG_CH] = addr;
            break;
        case REG_CL:
            regTaintBy[REG_ECX] = 0;
            regTaintBy[REG_CX] = 0;
            regTaintBy[REG_CL] = addr;
            break;

        case REG_EDX:
            regTaintBy[REG_EDX] = addr;
            regTaintBy[REG_DX] = addr;
            regTaintBy[REG_DH] = addr + 1;
            regTaintBy[REG_DL] = addr;
            break;
        case REG_DX:
            regTaintBy[REG_EDX] = 0;
            regTaintBy[REG_DX] = addr;
            regTaintBy[REG_DH] = addr + 1;
            regTaintBy[REG_DL] = addr;
            break;
        case REG_DH:
            regTaintBy[REG_EDX] = 0;
            regTaintBy[REG_DX] = 0;
            regTaintBy[REG_DH] = addr;
            break;
        case REG_DL:
            regTaintBy[REG_EDX] = 0;
            regTaintBy[REG_DX] = 0;
            regTaintBy[REG_DL] = addr;
            break;

        default:
            regTaintBy[reg] = addr;
    }
}

void taintRegByReg(REG desReg, REG srcReg) {
    if (!isMain) return;
    if (regTaintBy.find(srcReg) == regTaintBy.end()) return;
    taintRegByAddr(desReg, regTaintBy[srcReg]);
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
    cout << *(string *)str << endl;
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
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)dotaint,
                IARG_PTR, new string(INS_Disassemble(ins)), IARG_END);
    }
}


void triggerMain() {
    isMain = !isMain;
    if (isMain) cout << "========[Main Function Begin]========" << endl;
    else cout << "=========[Main Function End]=========" << endl;
}

void pushStackAddr(void *rtnName, UINT32 addr) {
    if (!isMain) return;
    cout << "Enter 0x" << std::hex << addr << "\t" << *(string*)rtnName << endl;
    stackTopAddr.push(addr);
}
void popStackAddr(void *rtnName) {
    if (!isMain) return;
    if (stackTopAddr.empty()) return;
    cout << "Leave 0x" << std::hex << stackTopAddr.top() << "\t" << *(string*)rtnName << endl;
    stackTopAddr.pop();
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


static bool first_read = true;

VOID Syscall_entry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v) {
  UINT64 start, size;

  if (PIN_GetSyscallNumber(ctx, std) == __NR_read) {
      if (first_read) {
          first_read = false;
          return;
      }

      start = static_cast<UINT32>((PIN_GetSyscallArgument(ctx, std, 1)));
      size  = static_cast<UINT32>((PIN_GetSyscallArgument(ctx, std, 2)));

      taintSomeAddr(start, size);

      std::cout << "[READ]\tbytes from " << std::hex << "0x" << start << " to 0x" << start+size << std::endl;
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
        IMG_AddInstrumentFunction(Image, 0);
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

