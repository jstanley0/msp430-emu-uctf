#include <unistd.h>
#include <sys/time.h>
#include "emu.h"

struct inprec {
	uint64_t	 ir_insn;
	size_t		 ir_len;
	char		 ir_inp[0];
};

uint16_t	 pc_start;
uint8_t		 pageprot[0x100];
uint16_t	 registers[16];
uint8_t		 memory[0x10000];
uint64_t	 start;
uint64_t	 insns;
uint64_t	 insnlimit;
uint64_t	 insnreplaylim;
uint16_t	 syminplen;
bool		 off;
bool		 unlocked;
bool		 dep_enabled;
bool		 replay_mode;
bool		 ctrlc;

GHashTable	*input_record;			// insns -> inprec

FILE		*trace;
static bool	 diverged;


// Fast random numbers:
// 18:16 < rmmh> int k = 0x123456; int rand() { k=30903*(k&65535)+(k>>16);
//               return(k&65535); }

void
print_ips(void)
{
	uint64_t end = now();

	if (end == start)
		end++;

	printf("Approx. %llu instructions per second (Total: %llu).\n",
	    (uint64_t)insns * 1000000 / (end - start), (uint64_t)insns);
}

void
init(void)
{

	trace = fopen("msp430_trace.txt", "wb");
	ASSERT(trace, "fopen");

	insns = 0;
	off = unlocked = false;
	start = now();
	//memset(memory, 0, sizeof(memory));
	memset(registers, 0, sizeof registers);
	memset(pageprot, DEP_R|DEP_W|DEP_X, sizeof pageprot);
	dep_enabled = false;
}

void
destroy(void)
{
	fflush(trace);
	fclose(trace);
	trace = NULL;
}

#ifndef EMU_CHECK
static void
ctrlc_handler(int s)
{

	(void)s;
	ctrlc = true;
}

void
usage(void)
{
	printf("usage: msp430-emu FLAGS [binaryimage]\n"
		"\n"
		"  FLAGS:\n"
		"    -g    Debug with GDB\n");
		exit(1);
}

int
main(int argc, char **argv)
{
	size_t rd, idx;
	const char *romfname;
	FILE *romfile;
	int opt;
	bool waitgdb = false;

	if (argc < 2)
		usage();

	while ((opt = getopt(argc, argv, "g")) != -1) {
		switch (opt) {
		case 'g':
			waitgdb = true;
			break;
		default:
			usage();
			break;
		}
	}

	if (optind >= argc)
		usage();

	romfname = argv[optind];

	romfile = fopen(romfname, "rb");
	ASSERT(romfile, "fopen");

	input_record = g_hash_table_new_full(NULL, NULL, NULL, free);
	ASSERT(input_record, "x");

	init();

	idx = 0;
	while (true) {
		rd = fread(&memory[idx], 1, sizeof(memory) - idx, romfile);
		if (rd == 0)
			break;
		idx += rd;
	}
	printf("Loaded %zu words from image.\n", idx/2);
	memwriteword(0x10, 0x4130); // callgate

	fclose(romfile);

	signal(SIGINT, ctrlc_handler);

	registers[PC] = memword(0xfffe);

	if (waitgdb)
		gdbstub_init();

	emulate();

	printf("Got CPUOFF, stopped.\n");
	gdbstub_stopped();

	print_regs();
	print_ips();

	return 0;
}
#endif

#define INST_INFO_SIZE 120
void
append_format(char *buffer, size_t sz, const char *format, ...)
{
	size_t len = strlen(buffer);
	va_list args;
	
	if (len >= sz - 1) return;
	va_start(args, format);
	vsnprintf(buffer + len, sz - len, format, args);
	va_end(args);
}

void
emulate1(void)
{
	uint16_t instr;

	pc_start = registers[PC];
	char inst_info[INST_INFO_SIZE];
	inst_info[0] = '\0';

#ifdef BF
	if (registers[PC] & 0x1) {
		//printf("insn addr unaligned");
		off = true;
		return;
	}
#else
	ASSERT((registers[PC] & 0x1) == 0, "insn addr unaligned");
#endif

	depcheck(registers[PC], DEP_X);
	instr = memword(registers[PC]);

	// dec r15; jnz -2 busy loop
	if ((instr == 0x831f || instr == 0x533f) &&
	    memword(registers[PC]+2) == 0x23fe) {
		//insns += (2ul * registers[15]) + 1;
		registers[15] = 0;

		registers[SR] &= ~(SR_C | SR_N | SR_V);
		registers[SR] |= SR_Z;
		registers[PC] += 4;
		goto out;
	}

	switch (bits(instr, 15, 13)) {
	case 0:
		handle_single(instr, inst_info);
		break;
	case 0x2000:
		handle_jump(instr, inst_info);
		break;
	default:
		handle_double(instr, inst_info);
		break;
	}

	fprintf(trace, "%08llx %02x %s\n", insns, pc_start, inst_info);

out:
	insns++;
}

static void
dumpmem(uint16_t addr, unsigned len)
{

	for (unsigned i = 0; i < len; i++) {
		printf("%02x", membyte(addr+i));
		if (i % 0x10 == 0xf)
			printf("\n");
	}
}

void
emulate(void)
{

#ifndef QUIET
	printf("Initial register state:\n");
	print_regs();
	printf("============================================\n\n");
#endif

	while (true) {
		if (ctrlc) {
			printf("Got ^C, stopping...\n");
			abort_nodump();
		}


#ifndef EMU_CHECK
		if (replay_mode && insns >= insnreplaylim) {
			replay_mode = false;
			insnreplaylim = 0;
			// return control to remote GDB
			stepone = true;
		}

		if (!replay_mode)
			gdbstub_intr();

		if (replay_mode && insnreplaylim < insns) {
			init();
			registers[PC] = memword(0xfffe);
			continue;
		}
#endif

		if (registers[PC] == 0x0010) {

			// Callgate
			if (registers[SR] & 0x8000) {
				unsigned op = (registers[SR] >> 8) & 0x7f;
				callgate(op);
			}
		}

		if (off)
			break;

		emulate1();

		ASSERT(registers[CG] == 0, "CG");
		if (off || registers[SR] & SR_CPUOFF) {
			off = true;
			break;
		}

		if (insnlimit && insns >= insnlimit) {
#ifndef BF
			printf("\nXXX Hit insn limit, halting XXX\n");
#endif
			break;
		}
	}
}

void
inc_reg(uint16_t reg, uint16_t bw)
{
	uint16_t inc = 2;

	if (reg != PC && reg != SP && bw)
		inc = 1;

	registers[reg] = (registers[reg] + inc) & 0xffff;
}

void
dec_reg(uint16_t reg, uint16_t bw)
{
	uint16_t inc = 2;

	if (reg != PC && reg != SP && bw)
		inc = 1;

	registers[reg] = (registers[reg] - inc) & 0xffff;
}

void
handle_jump(uint16_t instr, char *inst_info)
{
	char opcode[10];
	
	uint16_t cnd = bits(instr, 12, 10) >> 10,
		 offset = bits(instr, 9, 0);
	bool shouldjump = false;

	// sign-extend
	if (offset & 0x200)
		offset |= 0xfc00;

	// double
	offset = (offset << 1) & 0xffff;

	inc_reg(PC, 0);


	switch (cnd) {
	case 0x0:
		// JNZ
		strlcpy(opcode, "JNZ", sizeof(opcode));
		if ((registers[SR] & SR_Z) == 0)
			shouldjump = true;
		break;
	case 0x1:
		// JZ
		strlcpy(opcode, "JZ", sizeof(opcode));
		if (registers[SR] & SR_Z)
			shouldjump = true;
		break;
	case 0x2:
		// JNC
		strlcpy(opcode, "JNC", sizeof(opcode));
		if ((registers[SR] & SR_C) == 0)
			shouldjump = true;
		break;
	case 0x3:
		// JC
		strlcpy(opcode, "JC", sizeof(opcode));
		if (registers[SR] & SR_C)
			shouldjump = true;
		break;
	case 0x5:
		// JGE
		strlcpy(opcode, "JGE", sizeof(opcode));
		{
		bool N = !!(registers[SR] & SR_N),
		     V = !!(registers[SR] & SR_V);
		shouldjump = ((N ^ V) == 0);
		}
		break;
	case 0x6:
		// JL
		strlcpy(opcode, "JL", sizeof(opcode));
		{
		bool N = !!(registers[SR] & SR_N),
		     V = !!(registers[SR] & SR_V);
		shouldjump = (N ^ V);
		}
		break;
	case 0x7:
		// JMP
		strlcpy(opcode, "JMP", sizeof(opcode));
		shouldjump = true;
		break;
	default:
		unhandled(instr);
		break;
	}

	append_format(inst_info, INST_INFO_SIZE, "%s %04x %s", opcode, (registers[PC] + offset) & 0xffff, shouldjump ? "Y" : "n");
	if (shouldjump)
		registers[PC] = (registers[PC] + offset) & 0xffff;
}

void
handle_single(uint16_t instr, char *inst_info)
{
	enum operand_kind srckind, dstkind;
	uint16_t constbits = bits(instr, 12, 10) >> 10,
		 bw = bits(instr, 6, 6),
		 As = bits(instr, 5, 4),
		 dsrc = bits(instr, 3, 0),
		 srcval, srcnum = 0, dstval;
	unsigned res = (uns)-1;
	uint16_t setflags = 0,
		 clrflags = 0;
	char source_info[50];
	char dest_info[50];
	char opcode[20];

	inc_reg(PC, 0);

	// Bogus initialization for GCC
	srcval = 0xffff;
	srckind = OP_FLAGSONLY;

	load_src(instr, dsrc, As, bw, &srcval, &srckind);

	if (off)
		return;

	dstkind = srckind;
	dstval = srcval;

	// Load addressed src values
	switch (srckind) {
	case OP_REG:
			srcnum = registers[srcval];
			snprintf(source_info, sizeof(source_info), "r%d:%04x", srcval, srcnum);
		break;
	case OP_MEM:
			if (bw) {
				srcnum = membyte(srcval);
				snprintf(source_info, sizeof(source_info), "b[%04x]:%02x", srcval, srcnum);
			}
			else {
				srcnum = memword(srcval);
				snprintf(source_info, sizeof(source_info), "w[%04x]:%04x", srcval, srcnum);
			}
		break;
	case OP_CONST:
		srcnum = srcval;
		snprintf(source_info, sizeof(source_info), "#%04x", srcnum);
		break;
	default:
		ASSERT(false, "illins");
		break;
	}

	// '0x0000' is an illegal instruction, but #uctf ignores bits 0x1800 in
	// single-op instructions. We'll do it just for zero, trap on
	// everything else...
	if (constbits != 0x4 && instr != 0x0 && instr != 0x03)
		illins(instr);

	switch (bits(instr, 9, 7)) {
	case 0x000:
		// RRC
   		strlcpy(opcode, "RRC", sizeof(opcode));

		if (bw)
			srcnum &= 0xff;
		res = srcnum >> 1;

		if (registers[SR] & SR_C) {
			if (bw)
				res |= 0x80;
			else
				res |= 0x8000;
		}

		if (srcnum & 0x1)
			setflags |= SR_C;
		else
			clrflags |= SR_C;
		if (res & 0x8000)
			setflags |= SR_N;
		// doesn't clear N
		if (res)
			clrflags |= SR_Z;
		// doesn't set Z
		break;
	case 0x080:
		// SWPB (no flags)
   		strlcpy(opcode, "SWPB", sizeof(opcode));
		res = ((srcnum & 0xff) << 8) | (srcnum >> 8);
		break;
	case 0x100:
   		strlcpy(opcode, "RRA", sizeof(opcode));

		// RRA (flags)
		if (bw)
			srcnum &= 0xff;
		res = srcnum >> 1;
		if (bw && (0x80 & srcnum))
			res |= 0x80;
		else if (bw == 0 && (0x8000 & srcnum))
			res |= 0x8000;

		clrflags |= SR_Z;
		if (0x8000 & res)
			setflags |= SR_N;
		break;
	case 0x180:
		// SXT (sets flags)
   		strlcpy(opcode, "SXT", sizeof(opcode));
		
		if (srcnum & 0x80)
			res = srcnum | 0xff00;
		else
			res = srcnum & 0x00ff;

		andflags(res, &setflags, &clrflags);
		break;
	case 0x200:
		// PUSH (no flags)
   		strlcpy(opcode, "PUSH", sizeof(opcode));
		dec_reg(SP, 0);
		dstval = registers[SP];
		dstkind = OP_MEM;

		res = srcnum;
		break;
	case 0x280:
		// CALL (no flags)
   		strlcpy(opcode, "CALL", sizeof(opcode));
		
		// Call [src]
		res = srcnum;
		dstval = PC;
		dstkind = OP_REG;

		// Push PC+1
		dec_reg(SP, 0);
		memwriteword(registers[SP], registers[PC]);
		break;
	default:
		unhandled(instr);
		break;
	}

	if (setflags || clrflags) {
		ASSERT((setflags & clrflags) == 0, "set/clr flags shouldn't overlap");
			registers[SR] |= setflags;
			registers[SR] &= ~clrflags;
			registers[SR] &= 0x1ff;
	}

	if (dstkind == OP_REG) {
		ASSERT(res != (uns)-1, "res never set");

		if (bw)
			res &= 0x00ff;
		
		if (dstval != CG) {
			uint16_t oldval = registers[dstval];
			registers[dstval] = res & 0xffff;
			snprintf(dest_info, sizeof(dest_info), "r%d:%04x => %04x", dstval, oldval, registers[dstval]);
		}
	} else if (dstkind == OP_MEM) {
		depcheck(dstval, DEP_W);
		if (bw) {
			uint8_t oldval = memory[dstval];
			memory[dstval] = (res & 0xff);
			snprintf(dest_info, sizeof(dest_info), "b[%04x]:%02x => %02x", dstval, oldval, memory[dstval]);
		}
		else {
			uint16_t oldval = memword(dstval);
			memwriteword(dstval, res);
			snprintf(dest_info, sizeof(dest_info), "w[%04x]:%04x => %04x", dstval, oldval, res);
		}
	} else if (dstkind == OP_CONST) {
		ASSERT(instr == 0x3, "instr: %04x", instr);
	} else {
		ASSERT(dstkind == OP_FLAGSONLY, "x: %u", dstkind);
		
	}
	
	append_format(inst_info, INST_INFO_SIZE, "%s %s, %s", opcode, source_info, dest_info);
}

void
handle_double(uint16_t instr, char *inst_info)
{
	enum operand_kind srckind, dstkind;
	uint16_t dsrc = bits(instr, 11, 8) >> 8,
		 Ad = bits(instr, 7, 7),
		 bw = bits(instr, 6, 6),
		 As = bits(instr, 5, 4),
		 ddst = bits(instr, 3, 0);
	uint16_t srcval /*absolute addr or register number or constant*/,
		 dstval /*absolute addr or register number*/;
	unsigned res = (unsigned)-1,
		 dstnum = 0, srcnum = 0 /*as a number*/;
	uint16_t setflags = 0,
		 clrflags = 0;
	char source_info[50];
	char dest_info[50];
	char opcode[20];
	opcode[0] = '\0';

	inc_reg(PC, 0);

	// Bogus initialization to quiet GCC
	srckind = OP_FLAGSONLY;
	srcval = 0xffff;

	load_src(instr, dsrc, As, bw, &srcval, &srckind);
	load_dst(instr, ddst, Ad, &dstval, &dstkind);

	if (off)
		return;

	// Load addressed src values
	switch (srckind) {
	case OP_REG:
		srcnum = registers[srcval];
		snprintf(source_info, sizeof(source_info), "r%d:%04x", srcval, srcnum);			
		break;
	case OP_MEM:
		if (bw) {
			srcnum = membyte(srcval);
			snprintf(source_info, sizeof(source_info), "b[%04x]:%02x", srcval, srcnum);				
		} else {
			srcnum = memword(srcval);
			snprintf(source_info, sizeof(source_info), "w[%04x]:%04x", srcval, srcnum);				
		}
		break;
	case OP_CONST:
		srcnum = srcval;
		snprintf(source_info, sizeof(source_info), "#%04x", srcnum);		
		break;
	default:
		ASSERT(false, "illins");
		break;
	}

	// Load addressed dst values
	switch (dstkind) {
	case OP_REG:
		dstnum = registers[dstval];
		snprintf(dest_info, sizeof(dest_info), "r%d:%04x", dstval, dstnum);
		break;
	case OP_MEM:
		if (bw) {
			dstnum = membyte(dstval);
			snprintf(dest_info, sizeof(dest_info), "b[%04x]:%02x", dstval, dstnum);				
		} else {
			dstnum = memword(dstval);
			snprintf(dest_info, sizeof(dest_info), "w[%04x]:%04x", dstval, dstnum);				
		}
		break;
	case OP_CONST:
		ASSERT(instr == 0x4303 || instr == 0x03, "nop");
		strlcpy(inst_info, "NOP", INST_INFO_SIZE);
		return;
	default:
		ASSERT(false, "illins");
		break;
	}


	switch (bits(instr, 15, 12)) {
	case 0x4000:
		// MOV (no flags)
		strlcpy(opcode, "MOV", sizeof(opcode));
		res = srcnum;
		break;
	case 0x5000:
		// ADD (flags)
		strlcpy(opcode, "ADD", sizeof(opcode));
		if (bw) {
			dstnum &= 0xff;
			srcnum &= 0xff;
		}
		res = dstnum + srcnum;
		addflags(res, bw, &setflags, &clrflags);
		if (bw)
			res &= 0x00ff;
		else
			res &= 0xffff;
		break;
	case 0x6000:
		// ADDC (flags)
		strlcpy(opcode, "ADDC", sizeof(opcode));
		if (bw) {
			dstnum &= 0xff;
			srcnum &= 0xff;
		}
		res = dstnum + srcnum + ((registers[SR] & SR_C) ? 1 : 0);
		addflags(res, bw, &setflags, &clrflags);
		if (bw)
			res &= 0x00ff;
		else
			res &= 0xffff;
		break;
	case 0x9000:
		// CMP (flags)
		strlcpy(opcode, "CMP", sizeof(opcode));
		dstkind = OP_FLAGSONLY;
		// FALLTHROUGH
	case 0x8000:
		// SUB (flags)
		if (!opcode[0]) strlcpy(opcode, "SUB", sizeof(opcode));
		srcnum = ~srcnum & 0xffff;
		if (bw) {
			dstnum &= 0xff;
			srcnum &= 0xff;
		}
		res = dstnum + srcnum + 1;
		addflags(res, bw, &setflags, &clrflags);
		if (bw)
			res &= 0x00ff;
		else
			res &= 0xffff;
		break;
	case 0xa000:
		// DADD (flags)
		strlcpy(opcode, "DADD", sizeof(opcode));
		{
			unsigned carry = 0;
			bool setn = false;

			res = 0;
			for (unsigned i = 0; i < ((bw)? 8 : 16); i += 4) {
				unsigned a = bits(srcnum, i+3, i) >> i,
					 b = bits(dstnum, i+3, i) >> i,
					 partial;
				partial = a + b + carry;
				setn = !!(partial & 0x8);
				if (partial >= 10) {
					partial -= 10;
					carry = 1;
				} else
					carry = 0;

				res |= ((partial & 0xf) << i);
			}

			if (setn)
				setflags |= SR_N;
			if (carry)
				setflags |= SR_C;
			else
				clrflags |= SR_C;
		}
		break;
	case 0xc000:
		// BIC
		strlcpy(opcode, "BIC", sizeof(opcode));
		res = dstnum & ~srcnum;
		break;
	case 0xd000:
		// BIS (no flags)
		strlcpy(opcode, "BIS", sizeof(opcode));
		res = dstnum | srcnum;
		break;
	case 0xe000:
		// XOR (flags)
		strlcpy(opcode, "XOR", sizeof(opcode));
		res = dstnum ^ srcnum;
		if (bw)
			res &= 0x00ff;
		andflags(res, &setflags, &clrflags);
		break;
	case 0xb000:
		// BIT
		strlcpy(opcode, "BIT", sizeof(opcode));
		dstkind = OP_FLAGSONLY;
		// FALLTHROUGH
	case 0xf000:
		// AND (flags)
		if(!opcode[0]) strlcpy(opcode, "AND", sizeof(opcode));
		res = dstnum & srcnum;
		if (bw)
			res &= 0x00ff;
		andflags(res, &setflags, &clrflags);
		break;
	default:
		unhandled(instr);
		break;
	}

	if (setflags || clrflags) {
		ASSERT((setflags & clrflags) == 0, "set/clr flags shouldn't overlap");
		registers[SR] |= setflags;
		registers[SR] &= ~clrflags;
		registers[SR] &= 0x1ff;
	}

	if (dstkind == OP_REG) {
		ASSERT(res != (unsigned)-1, "res never set");

		if (bw) {
			res &= 0x00ff;
			append_format(dest_info, sizeof(dest_info), " => %02x", res);
		} else {
			append_format(dest_info, sizeof(dest_info), " => %04x", res);
		}

		registers[dstval] = res & 0xffff;
	} else if (dstkind == OP_MEM) {
		depcheck(dstval, DEP_W);
		if (bw) {
			memory[dstval] = (res & 0xff);
			append_format(dest_info, sizeof(dest_info), " => %02x", memory[dstval]);
		} else {
			memwriteword(dstval, res);
			append_format(dest_info, sizeof(dest_info), " => %04x", res);			
		}
	} else
		ASSERT(dstkind == OP_FLAGSONLY, "x");
		
	append_format(inst_info, INST_INFO_SIZE, "%s %s, %s", opcode, source_info, dest_info);
}

// R0 only supports AS_IDX, AS_INDINC (inc 2), AD_IDX.
// R2 only supports AS_R2_*, AD_R2_ABS (and direct for both).
// R3 only supports As (no Ad).

void
load_src(uint16_t instr, uint16_t instr_decode_src, uint16_t As, uint16_t bw,
    uint16_t *srcval, enum operand_kind *srckind)
{
	uint16_t extensionword;

	switch (instr_decode_src) {
	case SR:
		switch (As) {
		case AS_REG:
			*srckind = OP_REG;
			*srcval = instr_decode_src;
			break;
		case AS_R2_ABS:
			extensionword = memword(registers[PC]);
			inc_reg(PC, 0);

			*srckind = OP_MEM;
			*srcval = extensionword;
			break;
		case AS_R2_4:
			*srckind = OP_CONST;
			*srcval = 4;
			break;
		case AS_R2_8:
			*srckind = OP_CONST;
			*srcval = 8;
			break;
		default:
			illins(instr);
			break;
		}
		break;
	case CG:
		switch (As) {
		case AS_R3_0:
			*srckind = OP_CONST;
			*srcval = 0;
			break;
		case AS_R3_1:
			*srckind = OP_CONST;
			*srcval = 1;
			break;
		case AS_R3_2:
			*srckind = OP_CONST;
			*srcval = 2;
			break;
		case AS_R3_NEG:
			*srckind = OP_CONST;
			*srcval = 0xffff;
			break;
		default:
			illins(instr);
			break;
		}
		break;
	default:
		switch (As) {
		case AS_REG:
			*srckind = OP_REG;
			*srcval = instr_decode_src;
			break;
		case AS_IDX:
			extensionword = memword(registers[PC]);
			inc_reg(PC, 0);
			*srckind = OP_MEM;
			*srcval = (registers[instr_decode_src] + extensionword)
			    & 0xffff;
			break;
		case AS_REGIND:
			*srckind = OP_MEM;
			*srcval = registers[instr_decode_src];
			break;
		case AS_INDINC:
			*srckind = OP_MEM;

			*srcval = registers[instr_decode_src];
			inc_reg(instr_decode_src, bw);
			break;
		default:
			illins(instr);
			break;
		}
		break;
	}
}

// R0 only supports AS_IDX, AS_INDINC (inc 2), AD_REG, AD_IDX.
// R2 only supports AS_R2_*, AD_R2_ABS.
// R3 only supports As (no Ad).

void
load_dst(uint16_t instr, uint16_t instr_decode_dst, uint16_t Ad,
    uint16_t *dstval, enum operand_kind *dstkind)
{
	uint16_t extensionword;

	if (instr_decode_dst == CG) {
#ifdef BF
		if (instr != 0x4303 && instr != 0x0003)
			illins(instr);
#else
		ASSERT(instr == 0x4303, "nop");
#endif
		*dstkind = OP_CONST;
		*dstval = 0;
		return;
	}

	if (Ad == AD_REG) {
		*dstkind = OP_REG;
		*dstval = instr_decode_dst;
	} else {
		uint16_t regval = 0;

		ASSERT(Ad == AD_IDX, "Ad");

		extensionword = memword(registers[PC]);
		inc_reg(PC, 0);

		if (instr_decode_dst != SR) {
			regval = registers[instr_decode_dst];
		}

		*dstkind = OP_MEM;
		*dstval = (regval + extensionword) & 0xffff;
	}
}

void
_unhandled(const char *f, unsigned l, uint16_t instr)
{

#ifdef BF
	off = true;
#else
	printf("%s:%u: Instruction: %#04x @PC=%#04x is not implemented\n",
	    f, l, (unsigned)instr, (unsigned)pc_start);
	printf("Raw at PC: ");
	for (unsigned i = 0; i < 6; i++)
		printf("%02x", memory[pc_start+i]);
	printf("\n");
	abort_nodump();
#endif
}

void
_illins(const char *f, unsigned l, uint16_t instr)
{

#ifdef BF
	off = true;
#else
	printf("%s:%u: ILLEGAL Instruction: %#04x @PC=%#04x\n",
	    f, l, (unsigned)instr, (unsigned)pc_start);
	printf("Raw at PC: ");
	for (unsigned i = 0; i < 6; i++)
		printf("%02x", memory[pc_start+i]);
	printf("\n");
	abort_nodump();
#endif
}

uint16_t
membyte(uint16_t addr)
{

	return memory[addr];
}

#ifndef REALLYFAST
uint16_t
memword(uint16_t addr)
{

	ASSERT((addr & 0x1) == 0, "word load unaligned: %#04x",
	    (unsigned)addr);
	return memory[addr] | ((uint16_t)memory[addr+1] << 8);
}
#endif

#ifndef REALLYFAST
uint16_t
bits(uint16_t v, unsigned max, unsigned min)
{
	uint16_t mask;

	ASSERT(max < 16 && max >= min, "bit-select");
	ASSERT(min < 16, "bit-select");

	mask = ((unsigned)1 << (max+1)) - 1;
	if (min > 0)
		mask &= ~( (1<<min) - 1 );

	return v & mask;
}
#endif

void
abort_nodump(void)
{

	print_regs();
	print_ips();

#ifndef EMU_CHECK
	gdbstub_stopped();
#endif
	exit(1);
}

static void
printmemword(const char *pre, uint16_t addr)
{

	printf("%s", pre);
		printf("%02x", membyte(addr+1));
		printf("%02x", membyte(addr));
}

static void
printreg(unsigned reg)
{


	printf("%04x  ", registers[reg]);
}

void
print_regs(void)
{

	printf("pc  ");
	printreg(PC);
	printf("sp  ");
	printreg(SP);
	printf("sr  ");
	printreg(SR);
	printf("cg  ");
	printreg(CG);
	printf("\n");

	for (unsigned i = 4; i < 16; i += 4) {
		for (unsigned j = i; j < i + 4; j++) {
			printf("r%02u ", j);
			printreg(j);
		}
		printf("\n");
	}

	printf("instr:");
	for (unsigned i = 0; i < 4; i++)
		printmemword("  ", (pc_start & 0xfffe) + 2*i);
	printf("\nstack:");
	for (unsigned i = 0; i < 4; i++)
		printmemword("  ", (registers[SP] & 0xfffe) + 2*i);
	printf("\n      ");
	for (unsigned i = 4; i < 8; i++)
		printmemword("  ", (registers[SP] & 0xfffe) + 2*i);
	printf("\n");

}

uint16_t
sr_flags(void)
{

	return registers[SR] & (SR_V | SR_CPUOFF | SR_N | SR_Z | SR_C);
}

#ifndef REALLYFAST
void
memwriteword(uint16_t addr, uint16_t word)
{

	ASSERT((addr & 0x1) == 0, "word store unaligned: %#04x",
	    (uns)addr);
	memory[addr] = word & 0xff;
	memory[addr+1] = (word >> 8) & 0xff;
}
#endif

#ifndef REALLYFAST
void
addflags(unsigned res, uint16_t bw, uint16_t *set, uint16_t *clr)
{
	unsigned sz = 16;

	if (bw)
		sz = 8;

	if (bw == 0 && (res & 0x8000))
		*set |= SR_N;
	else
		*clr |= SR_N;

	// #uctf never sets V. Only clear on arithmetic, though.
	*clr |= SR_V;
	*clr |= 0xfe00;
#if 0
	if ((res & 0x8000) ^ (orig & 0x8000))
		*set |= SR_V;
#endif

	if ((res & ((1 << sz) - 1)) == 0)
		*set |= SR_Z;
	else
		*clr |= SR_Z;

	if (res & (1 << sz))
		*set |= SR_C;
	else
		*clr |= SR_C;
}
#endif

// set flags based on result; used in AND, SXT, ...
void
andflags(uint16_t res, uint16_t *set, uint16_t *clr)
{

	*clr |= SR_V;
	*clr |= 0xfe00;

	if (res & 0x8000)
		*set |= SR_N;
	else
		*clr |= SR_N;
	if (res == 0) {
		*set |= SR_Z;
		*clr |= SR_C;
	} else {
		*clr |= SR_Z;
		*set |= SR_C;
	}
}

uint64_t
now(void)
{
#if 0
	struct timespec ts;
	int rc;

	rc = clock_gettime(CLOCK_REALTIME, &ts);
	ASSERT(rc == 0, "clock_gettime: %d:%s", errno, strerror(errno));

	return ((uint64_t)sec * ts.tv_sec + (ts.tv_nsec / 1000));
#else
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (uint64_t)sec * tv.tv_sec + tv.tv_usec;
#endif
}

void
callgate(unsigned op)
{
	uint16_t argaddr = registers[SP] + 8,
		 getsaddr;
	unsigned bufsz;

	switch (op) {
	case 0x0:
#ifndef QUIET
		if (!replay_mode)
			putchar((char)membyte(argaddr));
#endif
		break;
	case 0x2:
		getsaddr = memword(argaddr);
		bufsz = (uns)memword(argaddr+2);
		getsn(getsaddr, bufsz);
		fprintf(trace, "** INT 2: gets: %d bytes at address %04x\n", bufsz, getsaddr);
		break;
	case 0x10:
		// Turn on DEP
		if (dep_enabled)
			break;
		for (unsigned i = 0; i < sizeof(pageprot); i++) {
			if ((pageprot[i] & DEP_W) && (pageprot[i] & DEP_X)) {
				printf("Enable DEP invalid: page %u +WX!\n",
				    i);
				abort_nodump();
			}
		}
		dep_enabled = true;
		break;
	case 0x11:
		// Set page protection
		{
		uint16_t page, wr;
		page = memword(argaddr);
		wr = memword(argaddr+2);

		ASSERT(page < 0x100, "page");
		ASSERT(wr == 0 || wr == 1, "w/x");

		pageprot[page] &= ~( wr? DEP_X : DEP_W );
		}
		break;
	case 0x20:
		// RNG
		registers[15] = 0;
		fprintf(trace, "** INT 20: rng: %04x\n", (int)registers[15]);
		break;
	case 0x7d:
		// writes a non-zero byte to supplied pointer if password is
		// correct (arg[0]). password is never correct.
		memory[memword(argaddr+2)] = 0;
		fprintf(trace, "** INT 7D: password callgate: 0 at address %04x\n", argaddr + 2);
		break;
	case 0x7e:
		// triggers unlock if password is correct; nop
		fprintf(trace, "** INT 7E: not opening the door :P\n");
		break;
	case 0x7f:
		// unlock.
		fprintf(trace, "** INT 7F: pwn3d\n");
		win();
		break;
	default:
		unhandled(0x4130);
		break;
	}
}

void
win(void)
{

	printf("The lock opens; you win!\n\n");
	print_regs();
	print_ips();
	off = true;
	unlocked = true;
}

#ifndef EMU_CHECK
static void
ins_inprec(char *dat, size_t sz)
{
	struct inprec *new_inp = malloc(sizeof *new_inp + sz + 1);

	ASSERT(new_inp, "oom");

	new_inp->ir_insn = insns;
	new_inp->ir_len = sz + 1;
	memcpy(new_inp->ir_inp, dat, sz);
	new_inp->ir_inp[sz] = 0;

	g_hash_table_insert(input_record, ptr(insns), new_inp);
}

void
getsn(uint16_t addr, uint16_t bufsz)
{
	struct inprec *prev_inp;
	char *buf;

	ASSERT((size_t)addr + bufsz < 0xffff, "overflow");
	//memset(&memory[addr], 0, bufsz);

	if (bufsz <= 1)
		return;

	prev_inp = g_hash_table_lookup(input_record, ptr(insns));
	if (replay_mode)
		ASSERT(prev_inp, "input at insn:%ju not found!\n",
		    (uintmax_t)insns);

	if (prev_inp) {
		memcpy(&memory[addr], prev_inp->ir_inp, prev_inp->ir_len);
		return;
	}

	printf("Gets (':'-prefix for hex)> ");
	fflush(stdout);

	buf = malloc(2 * bufsz + 2);
	ASSERT(buf, "oom");
	buf[0] = 0;

	if (fgets(buf, 2 * bufsz + 2, stdin) == NULL)
		goto out;

	if (buf[0] != ':') {
		strlcpy((char*)&memory[addr], buf, bufsz);
		memory[addr + strlen(buf)] = 0;
		ins_inprec(buf, bufsz);
	} else {
		unsigned i;
		for (i = 0; i < bufsz - 1u; i++) {
			unsigned byte;

			if (buf[2*i+1] == 0 || buf[2*i+2] == 0) {
				memory[addr+i] = 0;
				break;
			}

			sscanf(&buf[2*i+1], "%02x", &byte);
			//printf("%02x", byte);
			memory[addr + i] = byte;
		}
		ins_inprec((void*)&memory[addr], i);
	}
out:
	free(buf);
}
#endif

void
depcheck(uint16_t addr, unsigned perm)
{

	if (!dep_enabled)
		return;

	if (pageprot[addr >> 8] & perm)
		return;

	printf("DEP: Page 0x%02x is not %s!\n", (uns)addr >> 8,
	    (perm == DEP_W)? "writable" : "executable");
	abort_nodump();
}
