/*
Copyright (c) 2022-2023 xCuri0 <zkqri0@gmail.com>
SPDX-License-Identifier: MIT
*/
#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/DxeServicesTableLib.h>
#include <Pi/PiDxeCis.h>
#include <Protocol/PciRootBridgeIo.h>
#include <IndustryStandard/Pci22.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Guid/EventGroup.h>
#include "include/pciRegs.h"
#include "include/PciHostBridgeResourceAllocation.h"

#ifdef _MSC_VER
#pragma warning(disable:28251)
#include <intrin.h>
#pragma warning(default:28251)
#endif

#define PCI_POSSIBLE_ERROR(val) ((val) == 0xffffffff)

// for quirk
#define PCI_VENDOR_ID_ATI 0x1002

// if system time is before this year then CMOS reset will be detected and rebar will be disabled.
#define BUILD_YEAR 2023

// a3c5b77a-c88f-4a93-bf1c-4a92a32c65ce
static GUID reBarStateGuid = { 0xa3c5b77a, 0xc88f, 0x4a93, {0xbf, 0x1c, 0x4a, 0x92, 0xa3, 0x2c, 0x65, 0xce}};

// 0: disabled
// >0: maximum BAR size (2^x) set to value. UINT8_MAX for unlimited
static UINT8 reBarState = 0;

static EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL *pciResAlloc;
static EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL *pciRootBridgeIo;

static EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL_PREPROCESS_CONTROLLER o_PreprocessController;
static EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL_NOTIFY_PHASE o_NotifyPhase;

/* ---------------------------------------------------------------------------
 * CMP 170HX (GA100) BAR1 widening quirk.
 *
 * The card's XVE block only advertises 64MB of Resizable BAR at POST, which
 * makes the firmware size each slot's prefetch window to 96MB (64MB BAR1 +
 * 32MB BAR3) -- zero slack, so no runtime resize can ever produce a larger
 * BAR1.  The resize-capable strap is gated by two XVE registers that are only
 * reachable through BAR0:
 *
 *   0x88724  GU_XVE_BAR1_CYA    = 0x30          (also re-latches BAR1 size)
 *   0x88dcc  GU_XVE_BAR1_REBAR  = 0x8000000a
 *
 * BAR0 is not assigned yet when PreprocessController runs, so we temporarily
 * point it at a 16MB block of MMIO space reserved through the GCD, verify the
 * mapping by reading PMC_BOOT_0 (0x170000A1 on GA100), do the two writes,
 * then put BAR0/command back exactly as we found them.  If any check fails the
 * quirk is abandoned and the card keeps its stock 64MB BAR1.
 *
 * ReBarCmpMode     UINT8   0 = quirk off (default), 1 = widen mask + set size
 * ReBarCmpSizeMB   UINT32  requested BAR1 size in MB (0 = use ReBarState)
 * ReBarDiag        buffer  per-device result record, readable from Linux
 * --------------------------------------------------------------------------- */
#define GU_CMP_VID                 0x10DE
#define GU_CMP_DID                 0x20C2
#define GU_XVE_BAR1_CYA_OFFSET     0x00088724u
#define GU_XVE_BAR1_REBAR_OFFSET   0x00088DCCu
#define GU_XVE_CYA_VALUE           0x00000030u
#define GU_XVE_REBAR_VALUE         0x8000000Au
#define GU_CMP_PMC_BOOT_0          0x170000A1u
#define GU_CMP_BAR0_LEN            0x01000000ULL
#define GU_CMP_BAR1_MIN            0x04000000ULL  /* 64MB, the stock size */
#define GU_CMP_BAR3_LEN            0x02000000ULL   /* 32MB */
#define GU_CMP_MAX_PLACE           8
#define GU_CMP_MAX_CHAIN           6

#define GU_DIAG_SIGNATURE          0x47444252u   /* "RBDG" */
#define GU_DIAG_MAX                8

#pragma pack(1)
typedef struct {
    UINT32 BusDevFn;
    UINT32 Status;      /* 0x1 widened, 0x10 probe failed, 0x20 no candidate, 0x40 size set, 0x200 diag only */
    UINT32 MaskBefore;
    UINT32 MaskAfter;
    UINT32 CyaRead;
    UINT32 RebRead;
    UINT32 SizeBefore;
    UINT32 SizeAfter;
    UINT32 Bar0AtPost;
    UINT32 SizeWanted;
    UINT32 Mmio32Desc;      /* 32-bit MMIO descriptors seen in the GCD */
    UINT32 CandidatesTried;
    UINT32 LastProbeAddr;
    UINT32 LastProbeVal;
    UINT32 LastStatus;      /* status returned by the RootBridgeIo path */
    UINT32 Bar0Readback;    /* BAR0 read back after programming a candidate */
    UINT32 CommandReg;      /* PCI command register as found */
    UINT32 Pmcsr;           /* bits 0-15 before, 16-31 after forcing D0 */
    UINT32 Bar0Late;        /* BAR0 once the firmware has programmed it */
    UINT32 LayoutBaseHi;    /* layout: address chosen for this card */
    UINT32 LayoutBaseLo;
    UINT32 LayoutStat;      /* layout: 1 ok, 0x1X00 choose-base, 0x2000 gcd, 0x3000 chain */
} GU_CMP_DIAG_ENTRY;

typedef struct {
    UINT32 Signature;
    UINT32 Count;
    GU_CMP_DIAG_ENTRY Entry[GU_DIAG_MAX];
} GU_CMP_DIAG;
#pragma pack()

/* The quirk is off unless configured.  Values come from the ReBarCmp* variables;
 * a build may pin them with -DGU_CMP_BUILD_MODE / -DGU_CMP_BUILD_SIZE_MB /
 * -DGU_CMP_BUILD_BUSES for a fixed deployment.  No platform-specific data lives
 * in this file. */
/* A CmpPreset.h placed next to this file can pin the quirk for a fixed
 * deployment (mode, size, bus filter, aperture anchors) without modifying the
 * driver.  It is not part of the tree, so upstream builds stay default-off. */
#if defined(__has_include)
#if __has_include("CmpPreset.h")
#include "CmpPreset.h"
#endif
#endif

#ifndef GU_CMP_BUILD_MODE
#define GU_CMP_BUILD_MODE        0
#endif
#ifndef GU_CMP_BUILD_SIZE_MB
#define GU_CMP_BUILD_SIZE_MB     0
#endif
#ifndef GU_CMP_BUILD_BUSES
#define GU_CMP_BUILD_BUSES       NULL
#endif
#ifndef GU_CMP_BUILD_ANCHORS
#define GU_CMP_BUILD_ANCHORS     NULL
#endif
#ifndef GU_CMP_DIAG_WRITE
#define GU_CMP_DIAG_WRITE        0     /* publish the ReBarDiag variable */
#endif

static UINT8  cmpMode = GU_CMP_BUILD_MODE;
static UINT8  cmpRan = 0;
static UINT32 cmpSizeMB = GU_CMP_BUILD_SIZE_MB;
static char  *cmpBuses = GU_CMP_BUILD_BUSES;
static char  *cmpAnchors = GU_CMP_BUILD_ANCHORS;
static CHAR8  cmpBusesBuf[64];
static CHAR8  cmpAnchorsBuf[192];
static GU_CMP_DIAG cmpDiag;
static EFI_HANDLE  cmpHandle[GU_DIAG_MAX];

static UINT32 cmpBar1Mask(UINTN pciAddress, UINTN epos);
static UINT32 cmpBar1Size(UINTN pciAddress, UINTN epos);

/* find last set bit and return the index of it */
INTN fls(UINT32 x)
{
    UINT32 r;

    #ifdef _MSC_VER
    _BitScanReverse64(&r, x);
    #else
    // taken from linux x86 bitops.h
    asm("bsrl %1,%0"
	    : "=r" (r)
	    : "rm" (x), "0" (-1));
    #endif

    return r;
}

UINT64 pciAddrOffset(UINTN pciAddress, INTN offset)
{
    UINTN reg = (pciAddress & 0xffffffff00000000) >> 32;
    UINTN bus = (pciAddress & 0xff000000) >> 24;
    UINTN dev = (pciAddress & 0xff0000) >> 16;
    UINTN func = (pciAddress & 0xff00) >> 8;

    return EFI_PCI_ADDRESS(bus, dev, func, ((INT64)reg + offset));
}

// created these functions to make it easy to read as we are adapting alot of code from Linux
EFI_STATUS pciReadConfigDword(UINTN pciAddress, INTN pos, UINT32 *buf)
{
    return pciRootBridgeIo->Pci.Read(pciRootBridgeIo, EfiPciWidthUint32, pciAddrOffset(pciAddress, pos), 1, buf);
}

EFI_STATUS pciWriteConfigDword(UINTN pciAddress, INTN pos, UINT32 *buf)
{
    return pciRootBridgeIo->Pci.Write(pciRootBridgeIo, EfiPciWidthUint32, pciAddrOffset(pciAddress, pos), 1, buf);
}
EFI_STATUS pciReadConfigWord(UINTN pciAddress, INTN pos, UINT16 *buf)
{
    return pciRootBridgeIo->Pci.Read(pciRootBridgeIo, EfiPciWidthUint16, pciAddrOffset(pciAddress, pos), 1, buf);
}

EFI_STATUS pciWriteConfigWord(UINTN pciAddress, INTN pos, UINT16 *buf)
{
    return pciRootBridgeIo->Pci.Write(pciRootBridgeIo, EfiPciWidthUint16, pciAddrOffset(pciAddress, pos), 1, buf);
}

EFI_STATUS pciReadConfigByte(UINTN pciAddress, INTN pos, UINT8 *buf)
{
    return pciRootBridgeIo->Pci.Read(pciRootBridgeIo, EfiPciWidthUint8, pciAddrOffset(pciAddress, pos), 1, buf);
}

EFI_STATUS pciWriteConfigByte(UINTN pciAddress, INTN pos, UINT8 *buf)
{
    return pciRootBridgeIo->Pci.Write(pciRootBridgeIo, EfiPciWidthUint8, pciAddrOffset(pciAddress, pos), 1, buf);
}

// adapted from linux pci_find_ext_capability
UINT16 pciFindExtCapability(UINTN pciAddress, INTN cap)
{
    INTN ttl;
    UINT32 header;
    UINT16 pos = PCI_CFG_SPACE_SIZE;

    /* minimum 8 bytes per capability */
    ttl = (PCI_CFG_SPACE_EXP_SIZE - PCI_CFG_SPACE_SIZE) / 8;

    if (EFI_ERROR(pciReadConfigDword(pciAddress, pos, &header)))
        return 0;
    /*
     * If we have no capabilities, this is indicated by cap ID,
     * cap version and next pointer all being 0. Or it could also be all FF
     */
    if (header == 0 || PCI_POSSIBLE_ERROR(header))
        return 0;

    while (ttl-- > 0)
    {
        if (PCI_EXT_CAP_ID(header) == cap && pos != 0)
            return pos;

        pos = PCI_EXT_CAP_NEXT(header);
        if (pos < PCI_CFG_SPACE_SIZE)
            break;

        if (EFI_ERROR(pciReadConfigDword(pciAddress, pos, &header)))
            break;
    }
    return 0;
}

INTN pciRebarFindPos(UINTN pciAddress, INTN pos, UINT8 bar)
{
    UINTN nbars, i;
    UINT32 ctrl;

    pciReadConfigDword(pciAddress, pos + PCI_REBAR_CTRL, &ctrl);
    nbars = (ctrl & PCI_REBAR_CTRL_NBAR_MASK) >>
            PCI_REBAR_CTRL_NBAR_SHIFT;

    for (i = 0; i < nbars; i++, pos += 8)
    {
        UINTN bar_idx;

        pciReadConfigDword(pciAddress, pos + PCI_REBAR_CTRL, &ctrl);
        bar_idx = ctrl & PCI_REBAR_CTRL_BAR_IDX;
        if (bar_idx == bar)
            return pos;
    }
    return -1;
}

UINT32 pciRebarGetPossibleSizes(UINTN pciAddress, UINTN epos, UINT16 vid, UINT16 did, UINT8 bar)
{
    INTN pos;
    UINT32 cap;

    pos = pciRebarFindPos(pciAddress, (INTN)epos, bar);
    if (pos < 0)
        return 0;

    pciReadConfigDword(pciAddress, pos + PCI_REBAR_CAP, &cap);
    cap &= PCI_REBAR_CAP_SIZES;

    /* Sapphire RX 5600 XT Pulse has an invalid cap dword for BAR 0 */
    if (vid == PCI_VENDOR_ID_ATI && did == 0x731f &&
        bar == 0 && cap == 0x7000)
        cap = 0x3f000;

    return cap >> 4;
}

INTN pciRebarSetSize(UINTN pciAddress, UINTN epos, UINT8 bar, UINT8 size)
{
    INTN pos;
    UINT32 ctrl;

    pos = pciRebarFindPos(pciAddress, (INTN)epos, bar);
    if (pos < 0)
        return pos;

    pciReadConfigDword(pciAddress, pos + PCI_REBAR_CTRL, &ctrl);
    ctrl &= (UINT32)~PCI_REBAR_CTRL_BAR_SIZE;
    ctrl |= (UINT32)size << PCI_REBAR_CTRL_BAR_SHIFT;

    pciWriteConfigDword(pciAddress, pos + PCI_REBAR_CTRL, &ctrl);
    return 0;
}

static GU_CMP_DIAG_ENTRY *cmpDiagEntry(UINTN pciAddress)
{
    UINT32 id = (UINT32)(pciAddress & 0xFFFFFFFF);
    UINT32 i;

    for (i = 0; i < GU_DIAG_MAX; i++) {
        if (cmpDiag.Entry[i].BusDevFn == id)
            return &cmpDiag.Entry[i];
    }
    for (i = 0; i < GU_DIAG_MAX; i++) {
        if (cmpDiag.Entry[i].BusDevFn == 0) {
            cmpDiag.Entry[i].BusDevFn = id;
            if (cmpDiag.Count < i + 1)
                cmpDiag.Count = i + 1;
            return &cmpDiag.Entry[i];
        }
    }
    return &cmpDiag.Entry[GU_DIAG_MAX - 1];
}

static VOID cmpDiagFlush(VOID)
{
#if GU_CMP_DIAG_WRITE
    UINTN size = sizeof(cmpDiag);

    cmpDiag.Signature = GU_DIAG_SIGNATURE;
    gRT->SetVariable(L"ReBarDiag", &reBarStateGuid,
                     EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
                     size, &cmpDiag);
#endif
}

/* 32-bit MMIO access to a candidate BAR0 base.
 *
 * PciRootBridgeIo->Mem on this firmware only covers the apertures it has
 * already published (below-4G Mem is empty here), so every protocol access to
 * a 32-bit candidate fails.  Direct identity-mapped access is the primary path;
 * the protocol is kept as a fallback and its status is recorded. */
static UINT32 cmpRead32(UINT32 base, GU_CMP_DIAG_ENTRY *e)
{
    UINT32     val = 0;
    EFI_STATUS st;

    st = pciRootBridgeIo->Mem.Read(pciRootBridgeIo, EfiPciWidthUint32, base, 1, &val);
    if (!EFI_ERROR(st)) {
        e->LastStatus = 0;
        return val;
    }
    e->LastStatus = (UINT32)st;
    return *(volatile UINT32 *)(UINTN)base;
}

static VOID cmpWrite32(UINT32 base, UINT32 val)
{
    *(volatile UINT32 *)(UINTN)base = val;
}

/* Widen the mask and select BAR1's size once the firmware has programmed BAR0.
 *
 * At EfiPciHostBridgeEndResourceAllocation the BARs are assigned, so BAR0 is
 * finally reachable; 32-bit MMIO is not routed earlier, which is why the
 * before-collection attempt cannot work on this platform.  The BAR1 size is
 * then left at the requested value and the kernel -- booted with pci=realloc --
 * sizes the switch/root windows from it. */
static VOID cmpApplyOne(UINTN pciAddress, GU_CMP_DIAG_ENTRY *e)
{
    UINTN  epos;
    UINT32 mask, bar0, wanted;
    UINT8  size;
    UINT16 cmd, origCmd;

    epos = pciFindExtCapability(pciAddress, PCI_EXT_CAP_ID_REBAR);
    if (!epos) {
        e->Status |= 0x100;
        return;
    }

    pciReadConfigDword(pciAddress, PCI_BASE_ADDRESS_0, &bar0);
    e->Bar0Late = bar0 & 0xFFFFFFF0u;
    if (e->Bar0Late == 0 || e->Bar0Late >= 0xFFFFFFF0u) {
        e->Status |= 0x20;
        return;
    }

    pciReadConfigWord(pciAddress, PCI_COMMAND, &cmd);
    origCmd = cmd;
    {
        UINT16 on = (UINT16)(cmd | PCI_COMMAND_MEMORY);
        pciWriteConfigWord(pciAddress, PCI_COMMAND, &on);
    }
    gBS->Stall(1000);

    e->LastProbeAddr = e->Bar0Late;
    e->LastProbeVal = cmpRead32(e->Bar0Late, e);
    if (e->LastProbeVal != GU_CMP_PMC_BOOT_0) {
        e->Status |= 0x10;
        pciWriteConfigWord(pciAddress, PCI_COMMAND, &origCmd);
        return;
    }

    cmpWrite32(e->Bar0Late + GU_XVE_BAR1_CYA_OFFSET, GU_XVE_CYA_VALUE);
    cmpWrite32(e->Bar0Late + GU_XVE_BAR1_REBAR_OFFSET, GU_XVE_REBAR_VALUE);
    e->CyaRead = cmpRead32(e->Bar0Late + GU_XVE_BAR1_CYA_OFFSET, e);
    e->RebRead = cmpRead32(e->Bar0Late + GU_XVE_BAR1_REBAR_OFFSET, e);
    e->Status |= 0x1;

    pciWriteConfigWord(pciAddress, PCI_COMMAND, &origCmd);

    mask = cmpBar1Mask(pciAddress, epos);
    e->MaskAfter = mask;
    if (!(mask & 0x1FFC0))
        return;                 /* the write did not take; leave BAR1 alone */

    wanted = cmpSizeMB ? cmpSizeMB : (1u << MIN((UINT8)fls(mask), reBarState));
    e->SizeWanted = wanted;
    size = (UINT8)fls(mask);
    while (size > 0 && ((1u << size) > wanted || !(mask & (1u << size))))
        size--;
    if (size > 0 && pciRebarSetSize(pciAddress, epos, 1, size) >= 0)
        e->Status |= 0x40;
    e->SizeAfter = cmpBar1Size(pciAddress, epos);

    /* Optional: leave BAR1/BAR3 unassigned so the OS assigns them from scratch
     * and sizes the bridge windows itself.  Memory decoding must be off while
     * the bases are zero, otherwise the card would decode at address 0. */
    if (cmpMode & 0x2) {
        UINT32 zero = 0;
        UINT16 off = (UINT16)(origCmd & ~PCI_COMMAND_MEMORY);

        pciWriteConfigWord(pciAddress, PCI_COMMAND, &off);
        pciWriteConfigDword(pciAddress, PCI_BASE_ADDRESS_1, &zero);
        pciWriteConfigDword(pciAddress, PCI_BASE_ADDRESS_1 + 4, &zero);
        pciWriteConfigDword(pciAddress, PCI_BASE_ADDRESS_3, &zero);
        pciWriteConfigDword(pciAddress, PCI_BASE_ADDRESS_3 + 4, &zero);
        e->Status |= 0x80;
    }
}


/* ---- optional window layout ----------------------------------------------
 *
 * The firmware sizes each switch port's prefetchable window for one 64MB
 * BAR1, so nothing can grow it afterwards.  When asked to (mode bit 2) we lay
 * the windows out ourselves once the firmware has programmed everything: each
 * card gets an aligned slot window big enough for its BAR1 + BAR3, its slot
 * port gets that window, and every shared ancestor up to the root port is
 * stretched to cover the whole tree.  Addresses are taken from just below the
 * tree's current root-port window, i.e. inside the same bridge aperture and
 * adjacent to a range already known to be in use.
 * ------------------------------------------------------------------------- */

typedef struct {
    UINTN  dev;
    UINTN  chain[GU_CMP_MAX_CHAIN];   /* parents, nearest first */
    UINTN  nchain;
    UINT64 base;
    EFI_HANDLE handle;                /* root bridge this card hangs off */
    GU_CMP_DIAG_ENTRY *diag;
} GU_CMP_PLACE;

/* find the bridge whose secondary bus is 'target', looking at most 8 buses down */
static BOOLEAN cmpBridgeWithSecondary(UINT8 target, UINTN *found, UINT8 *parentBus)
{
    INTN b;
    UINTN dev, fn;

    if (target == 0)
        return FALSE;
    for (b = (INTN)target - 1; b >= 0 && b >= (INTN)target - 8; b--) {
        for (dev = 0; dev < 32; dev++) {
            for (fn = 0; fn < 2; fn++) {
                UINTN a = EFI_PCI_ADDRESS((UINT8)b, dev, fn, 0);
                UINT16 vid = 0;
                UINT8 hdr = 0, sec = 0;

                pciReadConfigWord(a, 0, &vid);
                if (vid == 0xFFFF || vid == 0)
                    continue;
                pciReadConfigByte(a, 0x0E, &hdr);          /* header type */
                if ((hdr & 0x7F) != 0x01)
                    continue;
                pciReadConfigByte(a, 0x19, &sec);
                if (sec == target) {
                    *found = a;
                    *parentBus = (UINT8)b;
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}

static VOID cmpSetPfxWindow(UINTN addr, UINT64 base, UINT64 limit)
{
    UINT16 cmd, off;
    UINT16 b = (UINT16)((((UINT32)base) >> 16 & 0xFFF0) | 0x1);
    UINT16 l = (UINT16)((((UINT32)limit) >> 16 & 0xFFF0) | 0x1);
    UINT32 bu = (UINT32)(base >> 32);
    UINT32 lu = (UINT32)(limit >> 32);

    pciReadConfigWord(addr, PCI_COMMAND, &cmd);
    off = (UINT16)(cmd & ~PCI_COMMAND_MEMORY);
    pciWriteConfigWord(addr, PCI_COMMAND, &off);
    pciWriteConfigDword(addr, 0x2C, &lu);
    pciWriteConfigWord(addr, 0x26, &l);
    pciWriteConfigDword(addr, 0x28, &bu);
    pciWriteConfigWord(addr, 0x24, &b);
    pciWriteConfigWord(addr, PCI_COMMAND, &cmd);
}

static VOID cmpSetBar64(UINTN addr, UINT8 bar, UINT64 value)
{
    UINT32 lo = (UINT32)value;
    UINT32 hi = (UINT32)(value >> 32);

    pciWriteConfigDword(addr, (INTN)(PCI_BASE_ADDRESS_0 + 4 * bar), &lo);
    pciWriteConfigDword(addr, (INTN)(PCI_BASE_ADDRESS_0 + 4 * bar + 4), &hi);
}

static UINT64 cmpPfxBase(UINTN addr)
{
    UINT16 lo = 0;
    UINT32 hi = 0;

    pciReadConfigWord(addr, 0x24, &lo);
    pciReadConfigDword(addr, 0x28, &hi);
    return ((UINT64)hi << 32) | ((UINT64)(lo & 0xFFF0) << 16);
}

/* Some firmware leaves a whole tree's 64-bit windows at zero and expects the OS
 * to assign them, so there is nothing in config space to anchor on.  For those
 * trees the usable range can be supplied as ReBarCmpAnchors, "bus:end,..." in
 * hex, where end is the first address past the aperture.  Nothing about any
 * particular board lives in this file. */
static UINT64 cmpConfiguredAnchor(UINT8 rootBus)
{
    UINTN i;

    if (cmpAnchors == NULL)
        return 0;
    for (i = 0; cmpAnchors[i] != 0; ) {
        UINTN bus = 0, val = 0;
        UINT64 anchor = 0;
        BOOLEAN haveBus = FALSE, haveVal = FALSE;

        while (cmpAnchors[i] == ' ' || cmpAnchors[i] == ',')
            i++;
        if (cmpAnchors[i] == 0)
            break;
        while (cmpAnchors[i] != 0 && cmpAnchors[i] != ',') {
            CHAR8 c = cmpAnchors[i++];
            UINTN d;

            if (c == ':') {
                haveBus = TRUE;
                bus = val;
                val = 0;
                continue;
            }
            if (c >= '0' && c <= '9')
                d = (UINTN)(c - '0');
            else if (c >= 'a' && c <= 'f')
                d = (UINTN)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F')
                d = (UINTN)(c - 'A' + 10);
            else
                continue;
            val = (val << 4) | d;
        }
        haveVal = TRUE;
        if (haveBus && haveVal) {
            anchor = (UINT64)val;
            if ((bus & 0xFF) == rootBus)
                return anchor;
        }
    }
    return 0;
}

/* Pick a base for the whole tree: below the lowest window the firmware has
 * already programmed anywhere in the chain.  Root ports often read back as 0
 * at this point, so we take the minimum non-zero value over the whole chain;
 * that address is inside the tree's apertures by construction. */
static EFI_STATUS cmpChooseBase(UINTN *chain, UINTN nchain, UINT64 need, UINT64 align, UINT64 *out, UINT64 *startOut)
{
    UINT64 anchor = 0;
    UINTN i;

    for (i = 0; i < nchain; i++) {
        UINT64 b = cmpPfxBase(chain[i]);

        if (b != 0 && (anchor == 0 || b < anchor))
            anchor = b;
    }
    if (anchor == 0)
        anchor = cmpConfiguredAnchor((UINT8)((chain[nchain - 1] >> 24) & 0xFF));
    if (startOut != NULL)
        *startOut = anchor;
    if (anchor < need)
        return EFI_UNSUPPORTED;
    *out = (anchor - need) & ~(align - 1);
    if (gDS != NULL) {
        EFI_GCD_MEMORY_SPACE_DESCRIPTOR d;

        if (EFI_ERROR(gDS->GetMemorySpaceDescriptor(*out, &d)) ||
            d.GcdMemoryType != EfiGcdMemoryTypeMemoryMappedIo ||
            d.BaseAddress > *out || d.BaseAddress + d.Length < *out + need)
            return EFI_NOT_FOUND;
    }
    return EFI_SUCCESS;
}

static VOID cmpLayoutGroup(GU_CMP_PLACE *place, UINTN n)
{
    UINT64 bar1, winLen, span, need, base = 0;
    UINTN i;

    if (n == 0)
        return;
    if (place[0].nchain < 2) {
        place[0].diag->LayoutStat = 0x3000;
        return;
    }
    /* the PCI access helpers use a single global protocol pointer, so point it
     * at this group's root bridge before touching anything */
    if (place[0].handle != NULL &&
        EFI_ERROR(gBS->HandleProtocol(place[0].handle, &gEfiPciRootBridgeIoProtocolGuid,
                                      (VOID **)&pciRootBridgeIo)))
        return;
    bar1 = ((UINT64)(cmpSizeMB ? cmpSizeMB : 8192u)) << 20;
    if (bar1 < GU_CMP_BAR1_MIN)
        bar1 = GU_CMP_BAR1_MIN;
    winLen = bar1 + GU_CMP_BAR3_LEN;
    span = (winLen + bar1 - 1) & ~(bar1 - 1);
    need = (n - 1) * span + winLen;

    {
        UINT64 start = 0;
        EFI_STATUS st = cmpChooseBase(place[0].chain, place[0].nchain, need, bar1, &base, &start);

        if (EFI_ERROR(st)) {
            place[0].diag->LayoutStat = (st == EFI_UNSUPPORTED) ? 0x1000 : 0x2000;
            place[0].diag->LayoutBaseHi = (UINT32)(start >> 32);
            place[0].diag->LayoutBaseLo = (UINT32)start;
            place[0].diag->LastProbeAddr = (UINT32)place[0].chain[place[0].nchain - 1];
            place[0].diag->LastProbeVal = (UINT32)need;
            return;
        }
    }

    for (i = 0; i < n; i++) {
        UINT64 w = base + i * span;
        UINT16 cmd, off;

        place[i].base = w;
        cmpSetPfxWindow(place[i].chain[0], w, w + winLen - 1);

        pciReadConfigWord(place[i].dev, PCI_COMMAND, &cmd);
        off = (UINT16)(cmd & ~PCI_COMMAND_MEMORY);
        pciWriteConfigWord(place[i].dev, PCI_COMMAND, &off);
        cmpSetBar64(place[i].dev, 1, w);
        cmpSetBar64(place[i].dev, 3, w + bar1);
        pciWriteConfigWord(place[i].dev, PCI_COMMAND, &cmd);
    }
    for (i = 1; i < place[0].nchain; i++)
        cmpSetPfxWindow(place[0].chain[i], base, base + need - 1);

    /* record what we did and whether the slot port kept it */
    for (i = 0; i < n; i++) {
        UINT16 lo = 0;
        UINT32 hi = 0;
        UINT64 got;

        UINT32 barLo = 0, barHi = 0;
        UINT64 bar;

        pciReadConfigWord(place[i].chain[0], 0x24, &lo);
        pciReadConfigDword(place[i].chain[0], 0x28, &hi);
        got = ((UINT64)hi << 32) | ((UINT64)(lo & 0xFFF0) << 16);
        pciReadConfigDword(place[i].dev, PCI_BASE_ADDRESS_0 + 4, &barLo);
        pciReadConfigDword(place[i].dev, PCI_BASE_ADDRESS_0 + 8, &barHi);
        bar = ((UINT64)barHi << 32) | ((UINT64)(barLo & 0xFFFFFFF0));
        place[i].diag->LayoutBaseHi = (UINT32)(place[i].base >> 32);
        place[i].diag->LayoutBaseLo = (UINT32)place[i].base;
        place[i].diag->LayoutStat = 1 |
            ((got == place[i].base) ? 0 : 0x4000) |
            ((bar == place[i].base) ? 0 : 0x8000);
    }
}

static BOOLEAN cmpBusListed(UINT8 bus)
{
    UINTN i;

    if (cmpBuses == NULL || *cmpBuses == '\0')
        return TRUE;
    for (i = 0; cmpBuses[i] != '\0'; ) {
        UINTN v = 0;

        while (cmpBuses[i] == ' ' || cmpBuses[i] == ',')
            i++;
        if (cmpBuses[i] == '\0')
            break;
        while (cmpBuses[i] != '\0' && cmpBuses[i] != ',') {
            CHAR8 c = cmpBuses[i++];
            UINTN d;

            if (c >= '0' && c <= '9')
                d = (UINTN)(c - '0');
            else if (c >= 'a' && c <= 'f')
                d = (UINTN)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F')
                d = (UINTN)(c - 'A' + 10);
            else
                continue;
            v = (v << 4) | d;
        }
        if ((v & 0xFF) == bus)
            return TRUE;
    }
    return FALSE;
}

static VOID cmpLayout(VOID)
{
    GU_CMP_PLACE place[GU_CMP_MAX_PLACE];
    UINTN n = 0, i, j;

    for (i = 0; i < GU_DIAG_MAX && n < GU_CMP_MAX_PLACE; i++) {
        UINTN dev, bus, parent;
        UINT8 parentBus = 0;

        if (cmpDiag.Entry[i].BusDevFn == 0 || cmpHandle[i] == NULL)
            continue;
        dev = cmpDiag.Entry[i].BusDevFn;
        bus = (dev >> 24) & 0xFF;
        if (!cmpBusListed((UINT8)bus))
            continue;
        gBS->HandleProtocol(cmpHandle[i], &gEfiPciRootBridgeIoProtocolGuid, (VOID **)&pciRootBridgeIo);

        place[n].dev = dev;
        place[n].nchain = 0;
        place[n].handle = cmpHandle[i];
        place[n].diag = &cmpDiag.Entry[i];
        while (place[n].nchain < GU_CMP_MAX_CHAIN) {
            if (!cmpBridgeWithSecondary((UINT8)bus, &parent, &parentBus))
                break;
            place[n].chain[place[n].nchain++] = parent;
            bus = parentBus;
            if (bus == 0)
                break;
        }
        if (place[n].nchain > 0) {
            place[n].diag->Mmio32Desc = (UINT32)place[n].nchain;
            place[n].diag->CandidatesTried = (UINT32)place[n].chain[0];
            n++;
        } else {
            cmpDiag.Entry[i].LastStatus |= 0x1000;      /* walk failed */
        }
    }

    for (i = 0; i < n; i++) {
        GU_CMP_PLACE group[GU_CMP_MAX_PLACE];
        UINTN gn = 0;

        if (place[i].dev == 0)
            continue;
        group[gn++] = place[i];
        for (j = i + 1; j < n; j++) {
            if (place[j].dev == 0)
                continue;
            if (place[j].chain[place[j].nchain - 1] == place[i].chain[place[i].nchain - 1]) {
                group[gn++] = place[j];
                place[j].dev = 0;
            }
        }
        cmpLayoutGroup(group, gn);
    }
}

static VOID cmpApplyAll(VOID)
{
    UINTN i;

    if (cmpRan || cmpMode == 0)
        return;
    cmpRan = 1;
    for (i = 0; i < GU_DIAG_MAX; i++) {
        EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL *io = NULL;

        if (cmpDiag.Entry[i].BusDevFn == 0)
            continue;
        if (cmpHandle[i] == NULL ||
            EFI_ERROR(gBS->HandleProtocol(cmpHandle[i], &gEfiPciRootBridgeIoProtocolGuid, (VOID **)&io)) ||
            io == NULL) {
            cmpDiag.Entry[i].Status |= 0x400;   /* root bridge handle unusable */
            cmpDiagFlush();
            continue;
        }
        pciRootBridgeIo = io;
        cmpApplyOne(cmpDiag.Entry[i].BusDevFn, &cmpDiag.Entry[i]);
    }
    if (cmpMode & 0x4)
        cmpLayout();
    cmpDiagFlush();
}

static UINT32 cmpBar1Mask(UINTN pciAddress, UINTN epos)
{
    return pciRebarGetPossibleSizes(pciAddress, epos, GU_CMP_VID, GU_CMP_DID, 1);
}

static UINT32 cmpBar1Size(UINTN pciAddress, UINTN epos)
{
    INTN pos = pciRebarFindPos(pciAddress, (INTN)epos, 1);
    UINT32 ctrl;

    if (pos < 0)
        return 0;
    pciReadConfigDword(pciAddress, pos + PCI_REBAR_CTRL, &ctrl);
    return (ctrl & PCI_REBAR_CTRL_BAR_SIZE) >> PCI_REBAR_CTRL_BAR_SHIFT;
}

static VOID cmpSetupDevice(EFI_HANDLE handle, UINTN pciAddress)
{
    GU_CMP_DIAG_ENTRY *e;
    UINTN epos;
    UINT32 mask, bar0now;

    e = cmpDiagEntry(pciAddress);
    cmpHandle[(UINTN)(e - &cmpDiag.Entry[0])] = handle;
    e->Status = 0;
    e->Bar0AtPost = 0;
    e->Bar0Late = 0;
    e->Mmio32Desc = 0;
    e->CandidatesTried = 0;
    e->LastStatus = 0;
    e->LastProbeAddr = 0;
    e->LastProbeVal = 0;
    e->CyaRead = 0;
    e->RebRead = 0;

    epos = pciFindExtCapability(pciAddress, PCI_EXT_CAP_ID_REBAR);
    if (!epos) {
        e->Status = 0x100;
        cmpDiagFlush();
        return;
    }

    mask = cmpBar1Mask(pciAddress, epos);
    e->MaskBefore = mask;
    e->SizeBefore = cmpBar1Size(pciAddress, epos);
    pciReadConfigDword(pciAddress, PCI_BASE_ADDRESS_0, &bar0now);
    e->Bar0AtPost = bar0now;

    /* The actual work happens at EndResourceAllocation; here we only record
     * the device and what the firmware presented before sizing. */
    e->Status = 0x200;
    cmpDiagFlush();
}

VOID reBarSetupDevice(EFI_HANDLE handle, EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_PCI_ADDRESS addrInfo)
{
    UINTN epos;
    UINT16 vid, did;
    UINTN pciAddress;

    gBS->HandleProtocol(handle, &gEfiPciRootBridgeIoProtocolGuid, (void **)&pciRootBridgeIo);

    pciAddress = EFI_PCI_ADDRESS(addrInfo.Bus, addrInfo.Device, addrInfo.Function, 0);
    pciReadConfigWord(pciAddress, 0, &vid);
    pciReadConfigWord(pciAddress, 2, &did);

    if (vid == 0xFFFF)
        return;

    DEBUG((DEBUG_INFO, "ReBarDXE: Device vid:%x did:%x\n", vid, did));

    if (vid == GU_CMP_VID && did == GU_CMP_DID)
    {
        cmpSetupDevice(handle, pciAddress);
        return;
    }

    epos = pciFindExtCapability(pciAddress, PCI_EXT_CAP_ID_REBAR);
    if (epos)
    {
        for (UINT8 bar = 0; bar < 6; bar++)
        {
            UINT32 rBarS = pciRebarGetPossibleSizes(pciAddress, epos, vid, did, bar);
            if (!rBarS)
                continue;
            // start with size from fls
            for (UINT8 n = MIN((UINT8)fls(rBarS), reBarState); n > 0; n--) {
                // check if size is supported
                if (rBarS & (1 << n)) {
                    pciRebarSetSize(pciAddress, epos, bar, n);
                    break;
                }
            }
        }
    }
}

EFI_STATUS EFIAPI PreprocessControllerOverride (
  IN  EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL  *This,
  IN  EFI_HANDLE                                        RootBridgeHandle,
  IN  EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_PCI_ADDRESS       PciAddress,
  IN  EFI_PCI_CONTROLLER_RESOURCE_ALLOCATION_PHASE      Phase
  )
{
    // call the original method
    EFI_STATUS status = o_PreprocessController(This, RootBridgeHandle, PciAddress, Phase);

    DEBUG((DEBUG_INFO, "ReBarDXE: Hooked PreprocessController called %d\n", Phase));

    // EDK2 PciBusDxe setups Resizable BAR twice so we will do same
    if (Phase <= EfiPciBeforeResourceCollection) {
        reBarSetupDevice(RootBridgeHandle, PciAddress);
    }

    return status;
}

EFI_STATUS EFIAPI NotifyPhaseOverride(
    IN EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL *This,
    IN EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PHASE   Phase)
{
    EFI_STATUS status = o_NotifyPhase(This, Phase);

    /* the work happens on ReadyToBoot: the platform rewrites bridge windows
     * after the last PCI phase, so anything written there is lost */

    return status;
}

static EFI_EVENT cmpReadyEvent = NULL;

static VOID EFIAPI cmpOnReadyToBoot(EFI_EVENT Event, VOID *Context)
{
    cmpApplyAll();
}

static VOID cmpInstallReadyToBoot(VOID)
{
    if (cmpReadyEvent != NULL)
        return;
    gBS->CreateEventEx(EVT_NOTIFY_SIGNAL, TPL_CALLBACK, cmpOnReadyToBoot, NULL,
                       &gEfiEventReadyToBootGuid, &cmpReadyEvent);
}

VOID pciHostBridgeResourceAllocationProtocolHook()
{
    EFI_STATUS status;
    UINTN handleCount;
    EFI_HANDLE *handleBuffer;

    status = gBS->LocateHandleBuffer(
        ByProtocol,
        &gEfiPciHostBridgeResourceAllocationProtocolGuid,
        NULL,
        &handleCount,
        &handleBuffer);

    if (EFI_ERROR(status))
        goto free;

    status = gBS->OpenProtocol(
        handleBuffer[0],
        &gEfiPciHostBridgeResourceAllocationProtocolGuid,
        (VOID **)&pciResAlloc,
        gImageHandle,
        NULL,
        EFI_OPEN_PROTOCOL_GET_PROTOCOL);

    if (EFI_ERROR(status))
        goto free;

    DEBUG((DEBUG_INFO, "ReBarDXE: Hooking EfiPciHostBridgeResourceAllocationProtocol->PreprocessController\n"));

    // Hook PreprocessController and NotifyPhase
    o_PreprocessController = pciResAlloc->PreprocessController;
    pciResAlloc->PreprocessController = &PreprocessControllerOverride;
    o_NotifyPhase = pciResAlloc->NotifyPhase;
    pciResAlloc->NotifyPhase = &NotifyPhaseOverride;

free:
    FreePool(handleBuffer);
}

EFI_STATUS EFIAPI rebarInit(
    IN EFI_HANDLE imageHandle,
    IN EFI_SYSTEM_TABLE *systemTable)
{
    UINTN bufferSize = 1;
    EFI_STATUS status;
    UINT32 attributes;
    EFI_TIME time;

    DEBUG((DEBUG_INFO, "ReBarDXE: Loaded\n"));

    // Read ReBarState variable
    status = gRT->GetVariable(L"ReBarState", &reBarStateGuid,
        &attributes,
        &bufferSize, &reBarState);

    // any attempts to overflow reBarState should result in EFI_BUFFER_TOO_SMALL
    if (status != EFI_SUCCESS)
        reBarState = 0;

    // CMP 170HX quirk knobs (optional variables); the test build ignores them
    {
        UINTN  sz;

        /* a value pinned at build time is authoritative; the variables only
         * fill in what the build left open */
#if GU_CMP_BUILD_MODE == 0
        UINT8 mode = 0;

        sz = 1;
        if (!EFI_ERROR(gRT->GetVariable(L"ReBarCmpMode", &reBarStateGuid, &attributes, &sz, &mode)) && mode != 0)
            cmpMode = mode;
#endif
#if GU_CMP_BUILD_SIZE_MB == 0
        UINT32 mb = 0;

        sz = sizeof(mb);
        if (!EFI_ERROR(gRT->GetVariable(L"ReBarCmpSizeMB", &reBarStateGuid, &attributes, &sz, &mb)) && mb != 0)
            cmpSizeMB = mb;
#endif
        if (cmpBuses == NULL) {
            sz = sizeof(cmpBusesBuf);
            if (!EFI_ERROR(gRT->GetVariable(L"ReBarCmpBuses", &reBarStateGuid, &attributes, &sz, cmpBusesBuf)) &&
                cmpBusesBuf[0] != 0) {
                cmpBusesBuf[sizeof(cmpBusesBuf) - 1] = 0;
                cmpBuses = cmpBusesBuf;
            }
        }
        if (cmpAnchors == NULL) {
            sz = sizeof(cmpAnchorsBuf);
            if (!EFI_ERROR(gRT->GetVariable(L"ReBarCmpAnchors", &reBarStateGuid, &attributes, &sz, cmpAnchorsBuf)) &&
                cmpAnchorsBuf[0] != 0) {
                cmpAnchorsBuf[sizeof(cmpAnchorsBuf) - 1] = 0;
                cmpAnchors = cmpAnchorsBuf;
            }
        }
    }
    cmpDiag.Signature = GU_DIAG_SIGNATURE;
    cmpDiag.Count = 0;

    if (reBarState)
    {
        DEBUG((DEBUG_INFO, "ReBarDXE: Enabled, maximum BAR size 2^%u MB\n", reBarState));

        // Detect CMOS reset by checking if year before BUILD_YEAR
        status = gRT->GetTime (&time, NULL);
        if (time.Year < BUILD_YEAR) {
            reBarState = 0;
            bufferSize = 1;
            attributes = EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS;

            status = gRT->SetVariable(L"ReBarState", &reBarStateGuid,
                attributes,
                bufferSize, &reBarState);

            return EFI_SUCCESS;
        }

        // For overriding PciHostBridgeResourceAllocationProtocol
        pciHostBridgeResourceAllocationProtocolHook();
        // CMP quirk: the actual work is deferred to ReadyToBoot
        cmpInstallReadyToBoot();
    }

    return EFI_SUCCESS;
}
