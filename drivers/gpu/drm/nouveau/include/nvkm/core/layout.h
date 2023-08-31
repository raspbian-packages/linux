/* SPDX-License-Identifier: MIT */
NVKM_LAYOUT_ONCE(NVKM_SUBDEV_TOP     , struct nvkm_top     ,      top)
NVKM_LAYOUT_ONCE(NVKM_SUBDEV_GSP     , struct nvkm_gsp     ,      gsp)
NVKM_LAYOUT_ONCE(NVKM_SUBDEV_VFN     , struct nvkm_vfn     ,      vfn)
NVKM_LAYOUT_ONCE(NVKM_SUBDEV_PCI     , struct nvkm_pci     ,      pci)
NVKM_LAYOUT_ONCE(NVKM_SUBDEV_VBIOS   , struct nvkm_bios    ,     bios)
NVKM_LAYOUT_ONCE(NVKM_SUBDEV_DEVINIT , struct nvkm_devinit ,  devinit)
NVKM_LAYOUT_ONCE(NVKM_SUBDEV_PRIVRING, struct nvkm_subdev  , privring)
NVKM_LAYOUT_ONCE(NVKM_SUBDEV_GPIO    , struct nvkm_gpio    ,     gpio)
NVKM_LAYOUT_ONCE(NVKM_SUBDEV_I2C     , struct nvkm_i2c     ,      i2c)
NVKM_LAYOUT_ONCE(NVKM_SUBDEV_FUSE    , struct nvkm_fuse    ,     fuse)
NVKM_LAYOUT_ONCE(NVKM_SUBDEV_MXM     , struct nvkm_subdev  ,      mxm)
NVKM_LAYOUT_ONCE(NVKM_SUBDEV_MC      , struct nvkm_mc      ,       mc)
NVKM_LAYOUT_ONCE(NVKM_SUBDEV_BUS     , struct nvkm_bus     ,      bus)
NVKM_LAYOUT_ONCE(NVKM_SUBDEV_TIMER   , struct nvkm_timer   ,    timer)
NVKM_LAYOUT_ONCE(NVKM_SUBDEV_INSTMEM , struct nvkm_instmem ,     imem)
NVKM_LAYOUT_ONCE(NVKM_SUBDEV_FB      , struct nvkm_fb      ,       fb)
NVKM_LAYOUT_ONCE(NVKM_SUBDEV_LTC     , struct nvkm_ltc     ,      ltc)
NVKM_LAYOUT_ONCE(NVKM_SUBDEV_MMU     , struct nvkm_mmu     ,      mmu)
NVKM_LAYOUT_ONCE(NVKM_SUBDEV_BAR     , struct nvkm_bar     ,      bar)
NVKM_LAYOUT_ONCE(NVKM_SUBDEV_FAULT   , struct nvkm_fault   ,    fault)
NVKM_LAYOUT_ONCE(NVKM_SUBDEV_ACR     , struct nvkm_acr     ,      acr)
NVKM_LAYOUT_ONCE(NVKM_SUBDEV_PMU     , struct nvkm_pmu     ,      pmu)
NVKM_LAYOUT_ONCE(NVKM_SUBDEV_VOLT    , struct nvkm_volt    ,     volt)
NVKM_LAYOUT_ONCE(NVKM_SUBDEV_ICCSENSE, struct nvkm_iccsense, iccsense)
NVKM_LAYOUT_ONCE(NVKM_SUBDEV_THERM   , struct nvkm_therm   ,    therm)
NVKM_LAYOUT_ONCE(NVKM_SUBDEV_CLK     , struct nvkm_clk     ,      clk)
NVKM_LAYOUT_INST(NVKM_SUBDEV_IOCTRL  , struct nvkm_subdev  ,   ioctrl, 3)
NVKM_LAYOUT_ONCE(NVKM_SUBDEV_FLA     , struct nvkm_subdev  ,      fla)

NVKM_LAYOUT_ONCE(NVKM_ENGINE_BSP     , struct nvkm_engine  ,      bsp)
NVKM_LAYOUT_INST(NVKM_ENGINE_CE      , struct nvkm_engine  ,       ce, 10)
NVKM_LAYOUT_ONCE(NVKM_ENGINE_CIPHER  , struct nvkm_engine  ,   cipher)
NVKM_LAYOUT_ONCE(NVKM_ENGINE_DISP    , struct nvkm_disp    ,     disp)
NVKM_LAYOUT_ONCE(NVKM_ENGINE_DMAOBJ  , struct nvkm_dma     ,      dma)
NVKM_LAYOUT_ONCE(NVKM_ENGINE_FIFO    , struct nvkm_fifo    ,     fifo)
NVKM_LAYOUT_ONCE(NVKM_ENGINE_GR      , struct nvkm_gr      ,       gr)
NVKM_LAYOUT_ONCE(NVKM_ENGINE_IFB     , struct nvkm_engine  ,      ifb)
NVKM_LAYOUT_ONCE(NVKM_ENGINE_ME      , struct nvkm_engine  ,       me)
NVKM_LAYOUT_ONCE(NVKM_ENGINE_MPEG    , struct nvkm_engine  ,     mpeg)
NVKM_LAYOUT_ONCE(NVKM_ENGINE_MSENC   , struct nvkm_engine  ,    msenc)
NVKM_LAYOUT_ONCE(NVKM_ENGINE_MSPDEC  , struct nvkm_engine  ,   mspdec)
NVKM_LAYOUT_ONCE(NVKM_ENGINE_MSPPP   , struct nvkm_engine  ,    msppp)
NVKM_LAYOUT_ONCE(NVKM_ENGINE_MSVLD   , struct nvkm_engine  ,    msvld)
NVKM_LAYOUT_INST(NVKM_ENGINE_NVDEC   , struct nvkm_nvdec   ,    nvdec, 5)
NVKM_LAYOUT_INST(NVKM_ENGINE_NVENC   , struct nvkm_nvenc   ,    nvenc, 3)
NVKM_LAYOUT_ONCE(NVKM_ENGINE_NVJPG   , struct nvkm_engine  ,    nvjpg)
NVKM_LAYOUT_ONCE(NVKM_ENGINE_OFA     , struct nvkm_engine  ,      ofa)
NVKM_LAYOUT_ONCE(NVKM_ENGINE_PM      , struct nvkm_pm      ,       pm)
NVKM_LAYOUT_ONCE(NVKM_ENGINE_SEC     , struct nvkm_engine  ,      sec)
NVKM_LAYOUT_ONCE(NVKM_ENGINE_SEC2    , struct nvkm_sec2    ,     sec2)
NVKM_LAYOUT_ONCE(NVKM_ENGINE_SW      , struct nvkm_sw      ,       sw)
NVKM_LAYOUT_ONCE(NVKM_ENGINE_VIC     , struct nvkm_engine  ,      vic)
NVKM_LAYOUT_ONCE(NVKM_ENGINE_VP      , struct nvkm_engine  ,       vp)
