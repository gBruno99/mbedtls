#include "mbedtls/dice_tcbinfo.h"
#include <string.h>

void init_dice_tcbInfo(dice_tcbInfo *tcbInfo)
{
    tcbInfo->vendor[0] = '\0';
    tcbInfo->l_ven = 0;
    tcbInfo->model[0] = '\0';
    tcbInfo->l_mod = 0;
    tcbInfo->l_ver = 0;
    tcbInfo->version[0] = '\0';
    tcbInfo->svn = -1;
    tcbInfo->layer = -1;
    tcbInfo->index = -1;
    tcbInfo->flags[0] = 0x0;
    tcbInfo->flags[1] = 0x0;
    tcbInfo->flags[2] = 0x0;
    tcbInfo->flags[3] = 0x0;
    tcbInfo->vendorInfo[0] = '\0';
    tcbInfo->l_vi = 0;
    tcbInfo->type[0] = '\0';
    tcbInfo->l_ty = 0;
    tcbInfo->flagMask[0] = 0x0;
    tcbInfo->flagMask[1] = 0x0;
    tcbInfo->flagMask[2] = 0x0;
    tcbInfo->flagMask[3] = 0x0;
    for (int i = 0; i < 2; i++)
    {
        tcbInfo->fwids[i].digest[0] = '\0';
        tcbInfo->fwids[i].OID_algo[0] = '0';
        tcbInfo->fwids[i].oid_len = 0;
    }
}

void set_dice_tcbInfo_vendor(dice_tcbInfo *tcbInfo, unsigned char vendor[], int lv)
{
    memcpy(tcbInfo->vendor, vendor, lv);
    tcbInfo->l_ven = lv;
}

void set_dice_tcbInfo_version(dice_tcbInfo *tcbInfo, unsigned char version[], int lv)
{
    memcpy(tcbInfo->version, version, lv);
    tcbInfo->l_ver = lv;
}

void set_dice_tcbInfo_model(dice_tcbInfo *tcbInfo, unsigned char model[], int l)
{
    memcpy(tcbInfo->model, model, l);
    tcbInfo->l_mod = l;
}

void set_dice_tcbInfo_vi(dice_tcbInfo *tcbInfo, unsigned char vi[], int l)
{
    memcpy(tcbInfo->vendorInfo, vi, l);
    tcbInfo->l_vi = l;
}

void set_dice_tcbInfo_type(dice_tcbInfo *tcbInfo, unsigned char type[], int l)
{
    memcpy(tcbInfo->type, type, l);
    tcbInfo->l_ty = l;
}

void set_dice_tcbInfo_measure(dice_tcbInfo *tcbInfo, measure m)
{
    memcpy(tcbInfo->fwids[0].digest, m.digest, 64);
    memcpy(tcbInfo->fwids[0].OID_algo, m.OID_algo, m.oid_len);
    tcbInfo->fwids[0].oid_len = m.oid_len;
}

int setting_tcbInfo(dice_tcbInfo *tcbInfo, unsigned char vendor[], int l_ven, unsigned char model[], int l_m, unsigned char version[], int l_ver,
                    int svn, int layer, int index, unsigned char flags[], int l_f, unsigned char vendor_info[], int l_vf, unsigned char type[], int l_t,
                    measure measures[], int l_mea)
{
    if ((l_ven > 64) || (l_m > 64) || (l_ver > 64) || (l_f > 4) || (l_vf > 16) || (l_t > 16) || (l_mea > 10))
        return 1;
    if ((l_ven < 0) || (l_m < 0) || (l_ver < 0) || (l_f < 0) || (l_vf < 0) || (l_t < 0) || (l_mea < 0))
        return 1;
    memcpy(tcbInfo->vendor, vendor, l_ven);
    memcpy(tcbInfo->model, model, l_m);
    memcpy(tcbInfo->version, version, l_ver);
    memcpy(tcbInfo->flags, flags, l_f);
    memcpy(tcbInfo->vendorInfo, vendor_info, l_vf);
    memcpy(tcbInfo->type, type, l_t);
    tcbInfo->svn = svn;
    tcbInfo->layer = layer;
    tcbInfo->index = index;
    for (int i = 0; i < l_mea; i++)
    {
        memcpy(tcbInfo->fwids[i].digest, measures[i].digest, 64);
        memcpy(tcbInfo->fwids[i].OID_algo, measures[i].OID_algo, measures[i].oid_len);
        tcbInfo->fwids[i].oid_len = measures[i].oid_len;
    }
    return 0;
}
