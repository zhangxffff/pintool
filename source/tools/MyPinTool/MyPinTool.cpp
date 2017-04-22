
/*! @file
 *  This is an example of the PIN tool that demonstrates some basic PIN APIs 
 *  and could serve as the starting point for developing your first PIN tool
 */

#include <asm/unistd.h>
#include "pin.H"
#include <iostream>
#include <fstream>
#include <set>

/* ================================================================== */
// Global variables 
/* ================================================================== */

std::set<UINT32> taintedAddr;
std::set<REG> taintedReg;

void taintAddr(UINT32 addr) {
    taintedAddr.insert(addr);
}

void taintAddr(UINT32 addr, UINT32 size) {
    for (UINT32 i = 0; i < size; i++) {
        taintedAddr.insert(addr + size);
    }
}

void taintReg(REG reg) {
    switch (reg) {
        case REG_EAX:   taintedReg.insert(REG_EAX);
        case REG_AX:    taintedReg.insert(REG_AX);
        case REG_AH:    taintedReg.insert(REG_AH);
            if (reg == REG_AH) break;
        case REG_AL:    taintedReg.insert(REG_AL);
            break;

        case REG_EBX:   taintedReg.insert(REG_EBX);
        case REG_BX:    taintedReg.insert(REG_BX);
        case REG_BH:    taintedReg.insert(REG_BH);
            if (reg == REG_BH) break;
        case REG_BL:    taintedReg.insert(REG_BL);
            break;

        case REG_ECX:   taintedReg.insert(REG_ECX);
        case REG_CX:    taintedReg.insert(REG_CX);
        case REG_CH:    taintedReg.insert(REG_CH);
            if (reg == REG_CH) break;
        case REG_CL:    taintedReg.insert(REG_CL);
            break;

        case REG_EDX:   taintedReg.insert(REG_EDX);
        case REG_DX:    taintedReg.insert(REG_DX);
        case REG_DH:    taintedReg.insert(REG_DH);
            if (reg == REG_DH) break;
        case REG_DL:    taintedReg.insert(REG_DL);
            break;


        default:
            taintedReg.insert(reg);
    }
}

void untaintReg(REG reg) {
    switch (reg) {
        case REG_EAX: case REG_AX: case REG_AH: case REG_AL:
            taintedReg.erase(REG_EAX);
            taintedReg.erase(REG_AX);
            if (reg != REG_AH) taintedReg.erase(REG_AL);
            if (reg != REG_AL) taintedReg.erase(REG_AH);
            break;

        case REG_EBX: case REG_BX: case REG_BH: case REG_BL:
            taintedReg.erase(REG_EBX);
            taintedReg.erase(REG_BX);
            if (reg != REG_BH) taintedReg.erase(REG_BL);
            if (reg != REG_BL) taintedReg.erase(REG_BH);
            break;

        case REG_ECX: case REG_CX: case REG_CH: case REG_CL:
            taintedReg.erase(REG_ECX);
            taintedReg.erase(REG_CX);
            if (reg != REG_CH) taintedReg.erase(REG_CL);
            if (reg != REG_CL) taintedReg.erase(REG_CH);
            break;

        case REG_EDX: case REG_DX: case REG_DH: case REG_DL:
            taintedReg.erase(REG_EDX);
            taintedReg.erase(REG_DX);
            if (reg != REG_DH) taintedReg.erase(REG_DL);
            if (reg != REG_DL) taintedReg.erase(REG_DH);
            break;

        default:
            taintedReg.erase(reg);
    }
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

void dotaint(UINT32 addr, UINT32 addr_ebp, void *str) {
    if (addr > addr_ebp) {
        cout << addr << "\t";
        cout << addr_ebp << "\t";
        cout << *(string*)str << endl;
    }
}
VOID Instruction(INS ins, VOID *v) {
    if (INS_IsMemoryWrite(ins) && INS_OperandCount(ins) > 1)
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)dotaint,
                IARG_MEMORYOP_EA, 0,
                IARG_REG_VALUE, REG_EBP,
                IARG_PTR, new string(INS_Disassemble(ins)), IARG_END);
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

      taintAddr(start, size);

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

        PIN_AddSyscallEntryFunction(Syscall_entry, 0);
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

