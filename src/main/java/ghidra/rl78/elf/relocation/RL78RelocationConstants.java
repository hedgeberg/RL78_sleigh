package ghidra.rl78.elf.relocation;

public class RL78RelocationConstants {

	public static final int R_RL78_NONE = 0x00;

	public static final int R_RL78_DIR32 = 0x01;
	public static final int R_RL78_DIR24S = 0x02;
	public static final int R_RL78_DIR16 = 0x03;
	public static final int R_RL78_DIR16U = 0x04;
	public static final int R_RL78_DIR16S = 0x05;
	public static final int R_RL78_DIR8 = 0x06;
	public static final int R_RL78_DIR8U = 0x07;
	public static final int R_RL78_DIR8S = 0x08;

	public static final int R_RL78_DIR24S_PCREL = 0x09;
	public static final int R_RL78_DIR16S_PCREL = 0x0a;
	public static final int R_RL78_DIR8S_PCREL = 0x0b;

	public static final int R_RL78_DIR16UL = 0x0c;
	public static final int R_RL78_DIR16UW = 0x0d;
	public static final int R_RL78_DIR8UL = 0x0e;
	public static final int R_RL78_DIR8UW = 0x0f;
	public static final int R_RL78_DIR32_REV = 0x10;
	public static final int R_RL78_DIR16_REV = 0x11;
	public static final int R_RL78_DIR3U_PCREL = 0x12;

	public static final int R_RL78_RH_RELAX = 0x2d;
	public static final int R_RL78_RH_SFR = 0x2e;
	public static final int R_RL78_RH_SADDR = 0x2f;

	public static final int R_RL78_ABS32 = 0x41;
	public static final int R_RL78_ABS24S = 0x42;
	public static final int R_RL78_ABS16 = 0x43;
	public static final int R_RL78_ABS16U = 0x44;
	public static final int R_RL78_ABS16S = 0x45;
	public static final int R_RL78_ABS8 = 0x46;
	public static final int R_RL78_ABS8U = 0x47;
	public static final int R_RL78_ABS8S = 0x48;
	public static final int R_RL78_ABS24S_PCREL = 0x49;
	public static final int R_RL78_ABS16S_PCREL = 0x4a;
	public static final int R_RL78_ABS8S_PCREL = 0x4b;
	public static final int R_RL78_ABS16UL = 0x4c;
	public static final int R_RL78_ABS16UW = 0x4d;
	public static final int R_RL78_ABS8UL = 0x4e;
	public static final int R_RL78_ABS8UW = 0x4f;
	public static final int R_RL78_ABS32_REV = 0x50;
	public static final int R_RL78_ABS16_REV = 0x51;

	public static final int R_RL78_SYM = 0x80;
	public static final int R_RL78_OPneg = 0x81;
	public static final int R_RL78_OPadd = 0x82;
	public static final int R_RL78_OPsub = 0x83;
	public static final int R_RL78_OPmul = 0x84;
	public static final int R_RL78_OPdiv = 0x85;
	public static final int R_RL78_OPshla = 0x86;
	public static final int R_RL78_OPshra = 0x87;
	public static final int R_RL78_OPsctsize = 0x88;
	public static final int R_RL78_OPscttop = 0x8d;
	public static final int R_RL78_OPand = 0x90;
	public static final int R_RL78_OPor = 0x91;
	public static final int R_RL78_OPxor = 0x92;
	public static final int R_RL78_OPnot = 0x93;
	public static final int R_RL78_OPmod = 0x94;
	public static final int R_RL78_OPromtop = 0x95;
	public static final int R_RL78_OPramtop = 0x96;

	private RL78RelocationConstants() {
	}
}
