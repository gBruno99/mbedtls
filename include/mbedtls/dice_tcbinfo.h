#ifndef DICE_TCBINFO_H
#define DICE_TCBINFO_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct measure {
    unsigned char OID_algo[10];
    int oid_len;
    unsigned char digest[64];
}
measure;

typedef struct dice_tcbInfo {
    unsigned char vendor[32];
    int l_ven;
    unsigned char model[32];
    int l_mod;
    unsigned char version[32];
    int l_ver;
    int svn;
    int layer;
    int index;
    unsigned char flags[4];
    unsigned char vendorInfo[16];
    int l_vi;
    unsigned char type[16];
    int l_ty;
    unsigned char flagMask[4];
    measure fwids[2];
} 
dice_tcbInfo;

void init_dice_tcbInfo(dice_tcbInfo *tcbInfo);
void set_dice_tcbInfo_vendor(dice_tcbInfo *tcbInfo, unsigned char vendor[], int lv);
void set_dice_tcbInfo_version(dice_tcbInfo *tcbInfo, unsigned char version[], int lv);
void set_dice_tcbInfo_model(dice_tcbInfo *tcbInfo, unsigned char model[], int l);
void set_dice_tcbInfo_vi(dice_tcbInfo *tcbInfo, unsigned char vi[], int l);
void set_dice_tcbInfo_type(dice_tcbInfo *tcbInfo, unsigned char type[], int l);
void set_dice_tcbInfo_measure(dice_tcbInfo *tcbInfo, measure m);
int setting_tcbInfo(dice_tcbInfo *tcbInfo, unsigned char vendor[], int l_ven, unsigned char model[], int l_m, unsigned char version[], int l_ver,
                    int svn, int layer, int index, unsigned char flags[], int l_f, unsigned char vendor_info[], int l_vf, unsigned char type[], int l_t,
                    measure measures[], int l_mea);

#ifdef __cplusplus
}
#endif

#endif