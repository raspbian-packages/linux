#ifndef __NVBIOS_CSTEP_H__
#define __NVBIOS_CSTEP_H__
u16 nvbios_cstepTe(struct nvkm_bios *,
		   u8 *ver, u8 *hdr, u8 *cnt, u8 *len, u8 *xnr, u8 *xsz);

struct nvbios_cstepE {
	u8  pstate;
	u8  index;
};

u16 nvbios_cstepEe(struct nvkm_bios *, int idx, u8 *ver, u8 *hdr);
u16 nvbios_cstepEp(struct nvkm_bios *, int idx, u8 *ver, u8 *hdr,
		   struct nvbios_cstepE *);
u16 nvbios_cstepEm(struct nvkm_bios *, u8 pstate, u8 *ver, u8 *hdr,
		   struct nvbios_cstepE *);

struct nvbios_cstepX {
	u32 freq;
	u8  unkn[2];
	u8  voltage;
};

u16 nvbios_cstepXe(struct nvkm_bios *, int idx, u8 *ver, u8 *hdr);
u16 nvbios_cstepXp(struct nvkm_bios *, int idx, u8 *ver, u8 *hdr,
		   struct nvbios_cstepX *);
#endif
