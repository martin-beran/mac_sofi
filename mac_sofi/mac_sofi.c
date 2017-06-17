/*-
 * Copyright (c) 2015-2016 Martin Beran. All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * MAC module implementing the SOFI (Subjects and Objects with Floating
 * Integrity) security model.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD: $");

#include <machine/_inttypes.h>
#include <sys/extattr.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/mac.h>
#include <sys/proc.h>
#include <sys/sbuf.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/systm.h>
#include <sys/vnode.h>

#include <security/mac/mac_policy.h>
#include <security/mac/mac_internal.h>

#include <mac_sofi.h>

SYSCTL_DECL(_security_mac);

static SYSCTL_NODE(_security_mac, OID_AUTO, sofi, CTLFLAG_RW, 0,
    "mac_sofi policy controls");

static int	sofi_enabled = 0;
SYSCTL_INT(_security_mac_sofi, OID_AUTO, enabled, CTLFLAG_RWTUN,
    &sofi_enabled, 0, "Enforce SOFI policy");
TUNABLE_INT("security.mac.sofi.enabled", &sofi_enabled);

static int	sofi_root = 0;
SYSCTL_INT(_security_mac_sofi, OID_AUTO, root, CTLFLAG_RWTUN,
    &sofi_root, 0, "Enforce SOFI policy for superuser processes "
    "(if belonging to sofi_gid group)");
TUNABLE_INT("security.mac.sofi.root", &sofi_root);

static int	sofi_gid = 65534; /* nobody */
SYSCTL_INT(_security_mac_sofi, OID_AUTO, gid, CTLFLAG_RWTUN,
    &sofi_gid, 0, "Enforce SOFI policy for processes with this effective GID,"
    " or any effective GID if negative");
TUNABLE_INT("security.mac.sofi.gid", &sofi_gid);

static unsigned long	sofi_debug_flags = 0;
SYSCTL_ULONG(_security_mac_sofi, OID_AUTO, debug, CTLFLAG_RWTUN,
    &sofi_debug_flags, 0, "Debugging flags");
TUNABLE_ULONG("security.mac.sofi.debug", &sofi_debug_flags);

/* slot in struct label */
static int sofi_slot;
static int sofi_slot_kenv = -1;
#define	SLOT(l) ((struct mac_sofi_label *)mac_label_get((l), sofi_slot))
#define	SLOT_SET(l, v) mac_label_set((l), sofi_slot, (uintptr_t)(v))
#define	PSLOT(l) ((struct mac_sofi_proc_label *)mac_label_get((l), sofi_slot))
#define	PSLOT_SET(l, v) mac_label_set((l), sofi_slot, (uintptr_t)(v))

/* forward declarations */
static struct mac_sofi_label *
sofi_label_alloc(unsigned short n_acl, mac_sofi_acl_sz sz, int flag);

static void
sofi_destroy_label(struct label *label);

/*
 * Internal functions
 */

MALLOC_DECLARE(M_SOFI_LABEL);
MALLOC_DEFINE(M_SOFI_LABEL, "sofi_label", "MAC SOFI entity labels");

/* Debugging */

#define	SOFI_DEBUG(flag, ...) \
	do { \
		if (sofi_debug_flags & (flag)) \
			printf(__VA_ARGS__); \
	} while (0)

#define	SOFI_DEBUG_TMP(...)	SOFI_DEBUG(SOFI_DBG_TMP, __VA_ARGS__)

#define	SOFI_DEBUG0_OP(format) \
	SOFI_DEBUG(SOFI_DBG_OP, "%s(): " format "\n", __FUNCTION__)

#define SOFI_DEBUG_OP(format, ...) \
	SOFI_DEBUG(SOFI_DBG_OP, "%s(): " format "\n", __FUNCTION__, __VA_ARGS__)

#define SOFI_DEBUG0_ENFORCE(format, ...) \
	SOFI_DEBUG(SOFI_DBG_ENFORCE, "%s(): " format "\n", __FUNCTION__)

#define SOFI_DEBUG_ENFORCE(format, ...) \
	SOFI_DEBUG(SOFI_DBG_ENFORCE, "%s(): " format "\n", __FUNCTION__, \
	    __VA_ARGS__)

static size_t
sofi_int_to_string(struct sbuf *sb, mac_sofi_ia *v, const char *sep);

static void
sofi_dbg_int(const char *format, mac_sofi_ia *v)
{
	struct sbuf *dbg;

	if ((sofi_debug_flags & SOFI_DBG_INT) == 0)
		return;

	dbg = sbuf_new_auto();
	sofi_int_to_string(dbg, v, "");
	sbuf_finish(dbg);
	printf(format, sbuf_data(dbg));
	sbuf_delete(dbg);
}

/* Label modification */

/* Sets an integrity to empty (not containing any IA) */
static inline void
sofi_int_clear(mac_sofi_ia *integrity)
{
	*integrity = MAC_SOFI_IA_SET_LAST(MAC_SOFI_IA_NULL, 1);
}

/* Copies intergrity */
static void
sofi_int_copy(mac_sofi_ia *src, mac_sofi_ia *dst)
{
	do {
		*dst = *src++;
	} while (!MAC_SOFI_IA_IS_LAST(*dst++));
}

/* Sets an integrity to root (superuser, all IAs) */
static inline void
sofi_int_set_root(mac_sofi_ia *integrity)
{
	*integrity = MAC_SOFI_IA_SET_LAST(MAC_SOFI_IA_ROOT, 1);
}

/* Computes meet of two integrities dst &= src */
static void
sofi_int_meet(mac_sofi_ia *src, mac_sofi_ia *dst)
{
	mac_sofi_ia *p = dst;
	int last = 0;
	int some = 0;

	if (MAC_SOFI_IA_IS_ROOT(*src))
		return;
	if (MAC_SOFI_IA_IS_ROOT(*dst)) {
		sofi_int_copy(src, dst);
		return;
	}
	do {
		if (MAC_SOFI_IA_IS_LAST(*dst) || MAC_SOFI_IA_IS_LAST(*src))
			last = 1;
		if (MAC_SOFI_IA_TV(*dst) == MAC_SOFI_IA_TV(*src)) {
			if (some)
				++p;
			else
				some = 1;
			*p = MAC_SOFI_IA_TV(*dst);
			++dst;
			++src;
		} else if (MAC_SOFI_IA_TV(*dst) < MAC_SOFI_IA_TV(*src))
			++dst;
		else /* MAC_SOFI_IA_TV(*dst) > MAC_SOFI_IA_TV(*src) */
			++src;
	} while (!last);
	*p = MAC_SOFI_IA_SET_LAST(some ? *p : MAC_SOFI_IA_NULL, 1);
}

/* Computes join of two integrities dst |= src */
static void
sofi_int_join(mac_sofi_ia *src, mac_sofi_ia *dst)
{
	mac_sofi_int nint;
	mac_sofi_ia *ps, *pd, *pn;

	if (MAC_SOFI_IA_IS_ROOT(*dst))
		return;
	if (MAC_SOFI_IA_IS_ROOT(*src)) {
		sofi_int_set_root(dst);
		return;
	}
	if (MAC_SOFI_IA_IS_NULL(*src))
		return;
	if (MAC_SOFI_IA_IS_NULL(*dst)) {
		sofi_int_copy(src, dst);
		return;
	}

	ps = src;
	pd = dst;
	pn = nint;
	for (;;) {
		if (ps != NULL && pd != NULL &&
		    MAC_SOFI_IA_TV(*ps) == MAC_SOFI_IA_TV(*pd))
		{
			*pn = MAC_SOFI_IA_TV(*ps);
			if (!MAC_SOFI_IA_IS_LAST(*ps))
				++ps;
			else
				ps = NULL;
			if (!MAC_SOFI_IA_IS_LAST(*pd))
				++pd;
			else
				pd = NULL;
		} else if (ps != NULL &&
		    (pd == NULL || MAC_SOFI_IA_TV(*ps) < MAC_SOFI_IA_TV(*pd)))
		{
			*pn = MAC_SOFI_IA_TV(*ps);
			if (!MAC_SOFI_IA_IS_LAST(*ps))
				++ps;
			else
				ps = NULL;
		} else { // pd != NULL && (ps == NULL || *pd < *ps)
			*pn = MAC_SOFI_IA_TV(*pd);
			if (!MAC_SOFI_IA_IS_LAST(*pd))
				++pd;
			else
				pd = NULL;
		}
		if (ps == NULL && pd == NULL)
			break;
		if (pn - nint == MAC_SOFI_ISZ_MAX - 1)
			break;
		++pn;
	}

	*pn = MAC_SOFI_IA_SET_LAST(*pn, 1);
        sofi_int_copy(nint, dst);
}

static void
sofi_acl_copy(struct mac_sofi_label *src, struct mac_sofi_label *dst, size_t i)
{
	dst->sz[i] = MAC_SOFI_I_B(dst, i) + MAC_SOFI_I_SZ(src, i);
	memcpy(&MAC_SOFI_I_ACL(dst, i, 0), &MAC_SOFI_I_ACL(src, i, 0),
	    MAC_SOFI_I_SZ(src, i) * sizeof(mac_sofi_ia));
}

/* Creates a new label from old and modification labels */
static struct mac_sofi_label *
sofi_modify_label(struct mac_sofi_label *old, struct mac_sofi_label *mod,
    int flags)
{
	struct mac_sofi_label *res;
	size_t sz = 0;
	size_t i;

	sz += MAC_SOFI_I_SZ(mod->flags & MAC_SOFI_LF_FTR ? mod : old,
	    MAC_SOFI_FTR);
	sz += MAC_SOFI_I_SZ(mod->flags & MAC_SOFI_LF_FGW ? mod : old,
	    MAC_SOFI_FGW);
	sz += MAC_SOFI_I_SZ(mod->flags & MAC_SOFI_LF_FAR ? mod : old,
	    MAC_SOFI_FAR);
	KASSERT(old->n_acl == MAC_SOFI_ACLSZ, "old->n_acl != MAC_SOFI_ACLSZ"); 
	KASSERT(mod->n_acl == MAC_SOFI_ACLSZ, "old->n_acl != MAC_SOFI_ACLSZ"); 
	for (i = MAC_SOFI_ACL_ACL; i < MAC_SOFI_ACLSZ; ++i)
		sz +=
		    MAC_SOFI_I_SZ(mod->flags & MAC_SOFI_LF_ACL ? mod : old, i);
	res = sofi_label_alloc(old->n_acl, sz, flags);
	if (res == NULL)
		return (NULL);
	res->flags = old->flags;
	sofi_int_copy((mod->flags & MAC_SOFI_LF_I ? mod : old)->integrity,
	    res->integrity);
	sofi_int_copy((mod->flags & MAC_SOFI_LF_MIN ? mod : old)->min_int,
	    res->min_int);
	sofi_acl_copy(mod->flags & MAC_SOFI_LF_FTR ? mod : old, res,
	    MAC_SOFI_FTR);
	sofi_acl_copy(mod->flags & MAC_SOFI_LF_FGW ? mod : old, res,
	    MAC_SOFI_FGW);
	sofi_acl_copy(mod->flags & MAC_SOFI_LF_FAR ? mod : old, res,
	    MAC_SOFI_FAR);
	for (i = MAC_SOFI_ACL_ACL; i < MAC_SOFI_ACLSZ; ++i)
		sofi_acl_copy(mod->flags & MAC_SOFI_LF_ACL ? mod : old, res, i);
	return (res);
}

/* Creates a copy of a label */
static struct mac_sofi_label *
sofi_create_label_copy(struct mac_sofi_label *old , int flag)
{
	struct mac_sofi_label *copy;

	copy = sofi_label_alloc(old->n_acl, old->sz[old->n_acl - 1], flag);
	if (copy != NULL)
		memcpy(copy, old, SOFI_LABEL_SZ(old));
	return (copy);
}

static void
sofi_set_label_copy(struct mac_sofi_label *src, struct label *dst)
{
	sofi_destroy_label(dst);
	SLOT_SET(dst, src);
}

static void
sofi_copy_label(struct label *src, struct label *dst, int flag)
{
	struct mac_sofi_label *l;
	
	l = sofi_create_label_copy(SLOT(src), flag);
	if (l != NULL)
		sofi_set_label_copy(l, dst);
}

static void
sofi_copy_label_op(struct label *src, struct label *dst)
{
	SOFI_DEBUG_OP("%p -> %p", src, dst); 
	sofi_copy_label(src, dst, M_NOWAIT);
}

static void
sofi_move_label(struct label *src, struct label *dst)
{
	sofi_set_label_copy(SLOT(src), dst);
	SLOT_SET(src, NULL);
}

/* Label allocation */

static struct mac_sofi_label *
sofi_label_alloc(unsigned short n_acl, mac_sofi_acl_sz sz, int flag)
{
	struct mac_sofi_label *ms;
	size_t i;

	ms = malloc(SOFI_LABEL_ALLOC_SZ(n_acl, sz), M_SOFI_LABEL,
	    M_ZERO | flag);
	if (ms != NULL) {
		ms->flags = 0;
		ms->n_acl = n_acl;
		sofi_int_clear(ms->integrity);
		sofi_int_clear(ms->min_int);
		for (i = 0; i < n_acl; ++i)
			ms->sz[i] = 0;
	}
	return (ms);
}

/* Sets MAC_SOFI_IA_ROOT (all IAs) for FTR and FAR. */
static void
sofi_init_label(struct label *label, int flag)
{
	struct mac_sofi_label *ms;
        size_t i;

	ms = sofi_label_alloc(MAC_SOFI_ACLSZ, 3, flag);
	if (ms != NULL) {
		ms->sz[MAC_SOFI_FTR] = 1;
		ms->sz[MAC_SOFI_FGW] = 2;
		for (i = MAC_SOFI_FAR; i < ms->n_acl; ++i)
			ms->sz[i] = 3;
		MAC_SOFI_I_ACL(ms, MAC_SOFI_FTR, 0) =
		    MAC_SOFI_IA_SET_LAST(MAC_SOFI_IA_ROOT, 1);
		MAC_SOFI_I_ACL(ms, MAC_SOFI_FGW, 0) =
		    MAC_SOFI_IA_SET_LAST(MAC_SOFI_IA_NULL, 1);
		MAC_SOFI_I_ACL(ms, MAC_SOFI_FAR, 0) =
		    MAC_SOFI_IA_SET_LAST(MAC_SOFI_IA_ROOT, 1);
		SLOT_SET(label, ms);
	}
}

static void
sofi_init_label_root(struct label *label, int flag)
{
	sofi_init_label(label, flag);
	sofi_int_set_root(SLOT(label)->integrity);
}

static void
sofi_init_label_op(struct label *label)
{
	SOFI_DEBUG_OP("%p", label);
	sofi_init_label_root(label, M_WAITOK);
}

/*Initialize to root integrity */
static void
sofi_proc_init_label(struct label *label)
{
	struct mac_sofi_proc_label *ms;

	SOFI_DEBUG_OP("%p", label);
	ms = malloc(sizeof(struct mac_sofi_proc_label), M_SOFI_LABEL,
	    M_ZERO | M_WAITOK);
	sofi_int_set_root(ms->integrity);
	mtx_init(&ms->mtx, MAC_SOFI_MOD_NAME " proc lock", NULL, MTX_DEF);
	PSLOT_SET(label, ms);
}

static void
sofi_label_free(struct mac_sofi_label *label)
{
	free(label, M_SOFI_LABEL);
}

static void
sofi_destroy_label(struct label *label)
{
	sofi_label_free(SLOT(label));
	SLOT_SET(label, NULL);
}

static void
sofi_destroy_label_op(struct label *label)
{
	SOFI_DEBUG_OP("%p", label);
	sofi_destroy_label(label);
}

static void
sofi_proc_destroy_label(struct label *label)
{
	SOFI_DEBUG_OP("%p", label);
	mtx_destroy(&PSLOT(label)->mtx);
	free(PSLOT(label), M_SOFI_LABEL);
	PSLOT_SET(label, NULL);
}

/*
 * Converting between internal and external (string) format
 */

static size_t
sofi_int_to_string(struct sbuf *sb, mac_sofi_ia *v, const char *sep)
{
	size_t n = 0;
	
	do {
		if (!MAC_SOFI_IA_IS_NULL(*v)) {
			sbuf_printf(sb, "%s%"PRIx32, sep, MAC_SOFI_IA_TV(*v));
			sep = MAC_SOFI_EXT_SEP_IA;
			++n;
		}
	} while (!MAC_SOFI_IA_IS_LAST(*v++));
	return (n);
}

static void
sofi_acl_to_string(struct sbuf *sb, mac_sofi_ia *v, size_t sz)
{
	const char *sep = "";
	size_t n, i;

	for (n = 0; n < sz;) {
		i = sofi_int_to_string(sb, v + n, sep);
		n += i == 0 ? 1 : i;
		if (i != 0)
			sep = MAC_SOFI_EXT_SEP_ACL;
	}
}

static int
sofi_to_string(struct sbuf *sb, struct mac_sofi_label *ms)
{
	sbuf_cat(sb, MAC_SOFI_EXT_INTEGRITY);
	sofi_int_to_string(sb, &ms->integrity[0], "");
	sbuf_cat(sb, MAC_SOFI_EXT_MIN_INT);
	sofi_int_to_string(sb, &ms->min_int[0], "");
	sbuf_cat(sb, MAC_SOFI_EXT_FTR);
	sofi_int_to_string(sb, &MAC_SOFI_I_ACL(ms, MAC_SOFI_FTR, 0), "");
	sbuf_cat(sb, MAC_SOFI_EXT_FGW);
	sofi_int_to_string(sb, &MAC_SOFI_I_ACL(ms, MAC_SOFI_FGW, 0), "");
	sbuf_cat(sb, MAC_SOFI_EXT_FAR);
	sofi_int_to_string(sb, &MAC_SOFI_I_ACL(ms, MAC_SOFI_FAR, 0), "");
	sbuf_cat(sb, MAC_SOFI_EXT_ACL_ACL);
	sofi_acl_to_string(sb, &MAC_SOFI_I_ACL(ms, MAC_SOFI_ACL_ACL, 0),
	    MAC_SOFI_I_SZ(ms, MAC_SOFI_ACL_ACL));
	sbuf_cat(sb, MAC_SOFI_EXT_ACL_R);
	sofi_acl_to_string(sb, &MAC_SOFI_I_ACL(ms, MAC_SOFI_ACL_R, 0),
	    MAC_SOFI_I_SZ(ms, MAC_SOFI_ACL_R));
	sbuf_cat(sb, MAC_SOFI_EXT_ACL_W);
	sofi_acl_to_string(sb, &MAC_SOFI_I_ACL(ms, MAC_SOFI_ACL_W, 0),
	    MAC_SOFI_I_SZ(ms, MAC_SOFI_ACL_W));
	if (sbuf_error(sb) != 0)
		return (EINVAL);
	return (0);
}

static int
sofi_externalize_label(struct label *label, char *element_name,
    struct sbuf *sb, int *claimed)
{
	struct mac_sofi_label *ms;
	int error;

	if (strcmp(MAC_SOFI_LABEL_NAME, element_name) != 0)
		return (0);
	(*claimed)++;
	ms = SLOT(label);
	error = sofi_to_string(sb, ms);
	SOFI_DEBUG_OP("label=%p str=%.*s error=%d", label,
	    (int)sb->s_len, sb->s_buf, error);
	return (error);
}

static mac_sofi_acl_sz
sofi_parse_space(char *str)
{
	mac_sofi_acl_sz space = 3;
	char *d, *p;

	d = str + strcspn(str, "TGACRW");
	while (*d != '\0') {
		switch (*d) {
		case 'T':
		case 'G':
		case 'A':
			--space;
			break;
		}
		++d;
		p = d + strcspn(d, ",:TGACRW");
		if (p != d || *p != *MAC_SOFI_EXT_SEP_IA)
			++space;
		d = p;
	}
	return (space);
}

/* Parsing lowercase hex number, MAC_SOFI_IA_NULL for empty string */
static mac_sofi_ia
sofi_parse_ia(char **p)
{
	char *b = *p;
	uint64_t res = 0;

	for (;; ++(*p)) {
		if (**p >= '0' && **p <= '9')
			res = 16 * res + **p - '0';
		else if (**p >= 'a' && **p <= 'f')
			res = 16 * res + **p - 'a' + 10;
		else
			break;
		if (res >= MAC_SOFI_IA_NULL) {
			/* too big number */
			*p = NULL;
			return (MAC_SOFI_IA_NULL);
		}
	}
	if (b == *p)
		return (MAC_SOFI_IA_NULL);
	else
		return (res);
}

static int
sofi_cmp_integrity(const void *p1, const void *p2)
{
	mac_sofi_ia a = *(const mac_sofi_ia *)p1;
	mac_sofi_ia b = *(const mac_sofi_ia *)p2;

	return ((a > b) - (a < b));
}

static int
sofi_unique_integrity(mac_sofi_ia *i, int n)
{
	mac_sofi_ia *ui = i;
	int un;
	
	if (n == 0)
		return (0);
	for (un = 1, --n, ++i; n > 0; --n, ++i)
		if (*ui != *i && !MAC_SOFI_IA_IS_ROOT(*ui)) {
			*(++ui) = *i;
			++un;
		}
	return (un);
}

static int
sofi_sort_integrity(mac_sofi_ia *i, int n)
{
	qsort(i, n, sizeof(mac_sofi_ia), &sofi_cmp_integrity);
	return (sofi_unique_integrity(i, n));
}

static int
sofi_parse_integrity(mac_sofi_ia *i, char **p)
{
	int n;
	mac_sofi_ia ia;

	for (n = 0; n < MAC_SOFI_ISZ_MAX; ++(*p)) {
		ia = sofi_parse_ia(p);
		if (*p == NULL)
			return (-1);
		if (ia != MAC_SOFI_IA_NULL)
			i[n++] = ia;
		if (**p != *MAC_SOFI_EXT_SEP_IA) {
			n = sofi_sort_integrity(i, n);
			if (n > 0)
				i[n - 1] = MAC_SOFI_IA_SET_LAST(i[n - 1], 1);
			return (n);
		}
	}
	return (-1);
}

static int
sofi_parse_acl(mac_sofi_ia *i, char **p)
{
	int n, ni;
	
	for (n = 0; n < MAC_SOFI_ACL_MAX; ++(*p)) {
		ni = sofi_parse_integrity(i, p);
		if (ni == -1)
			return (-1);
		i += ni;
		n += ni;
		if (**p != *MAC_SOFI_EXT_SEP_ACL)
			return (n);
	}
	return (-1);
}

static int
sofi_parse(struct mac_sofi_label **ms, char *str)
{
	struct mac_sofi_label *label;
	mac_sofi_acl_sz space, used;
	int isz;
	char *d;

	*ms = NULL;
	space = sofi_parse_space(str);
	if (space > MAC_SOFI_ACL_MAX * MAC_SOFI_ACLSZ)
		return (E2BIG);
	label = sofi_label_alloc(MAC_SOFI_ACLSZ, space, M_WAITOK);
	/* I = integrity */
	d = str + strcspn(str,
	    MAC_SOFI_EXT_INTEGRITY MAC_SOFI_EXT_MIN_INT
	    MAC_SOFI_EXT_FTR       MAC_SOFI_EXT_FGW     MAC_SOFI_EXT_FAR
	    MAC_SOFI_EXT_ACL_ACL   MAC_SOFI_EXT_ACL_R   MAC_SOFI_EXT_ACL_W);
	if (*d == *MAC_SOFI_EXT_INTEGRITY) {
		label->flags |= MAC_SOFI_LF_I;
		++d;
                switch (sofi_parse_integrity(label->integrity, &d)) {
		case -1:
			goto error;
		case 0:
			label->integrity[0] =
			    MAC_SOFI_IA_SET_LAST(MAC_SOFI_IA_NULL, 1);
			break;
		default:
			break;
		}
		str = d;
	}
	/* M = minimum integrity */
	d = str + strcspn(str,
	    MAC_SOFI_EXT_MIN_INT
	    MAC_SOFI_EXT_FTR     MAC_SOFI_EXT_FGW   MAC_SOFI_EXT_FAR
	    MAC_SOFI_EXT_ACL_ACL MAC_SOFI_EXT_ACL_R MAC_SOFI_EXT_ACL_W);
	if (*d == *MAC_SOFI_EXT_MIN_INT) {
		label->flags |= MAC_SOFI_LF_MIN;
		++d;
		switch (sofi_parse_integrity(label->min_int, &d)) {
		case -1:
			goto error;
		case 0:
			label->min_int[0] =
			    MAC_SOFI_IA_SET_LAST(MAC_SOFI_IA_NULL, 1);
			break;
		default:
			break;
		}
		str = d;
	}
	/* T = FTR */
	used = 0;
	d = str + strcspn(str,
	    MAC_SOFI_EXT_FTR     MAC_SOFI_EXT_FGW   MAC_SOFI_EXT_FAR
	    MAC_SOFI_EXT_ACL_ACL MAC_SOFI_EXT_ACL_R MAC_SOFI_EXT_ACL_W);
	isz = 0;
	if (*d == *MAC_SOFI_EXT_FTR) {
		label->flags |= MAC_SOFI_LF_FTR;
		++d;
                isz = sofi_parse_integrity(
		    &MAC_SOFI_I_ACL(label, MAC_SOFI_FTR, 0), &d);
		switch (isz) {
		case -1:
			goto error;
		case 0:
			MAC_SOFI_I_ACL(label, MAC_SOFI_FTR, 0) =
			    MAC_SOFI_IA_SET_LAST(MAC_SOFI_IA_NULL, 1);
			isz = 1;
			break;
		default:
                        break;
		}
		str = d;
	} else {
		MAC_SOFI_I_ACL(label, MAC_SOFI_FTR, 0) =
		    MAC_SOFI_IA_SET_LAST(MAC_SOFI_IA_NULL, 1);
		isz = 1;
	}
	used += isz;
	label->sz[MAC_SOFI_FTR] = used;
	/* G = FGW */
	d = str + strcspn(str,
	    MAC_SOFI_EXT_FGW     MAC_SOFI_EXT_FAR
	    MAC_SOFI_EXT_ACL_ACL MAC_SOFI_EXT_ACL_R MAC_SOFI_EXT_ACL_W);
	isz = 0;
	if (*d == *MAC_SOFI_EXT_FGW) {
		label->flags |= MAC_SOFI_LF_FGW;
		++d;
		isz = sofi_parse_integrity(
		    &MAC_SOFI_I_ACL(label, MAC_SOFI_FGW, 0), &d);
		switch (isz) {
		case -1:
			goto error;
		case 0:
			MAC_SOFI_I_ACL(label, MAC_SOFI_FGW, 0) =
			    MAC_SOFI_IA_SET_LAST(MAC_SOFI_IA_NULL, 1);
			isz = 1;
			break;
		default:
			break;
		}
		str = d;
	} else {
		MAC_SOFI_I_ACL(label, MAC_SOFI_FGW, 0) =
		    MAC_SOFI_IA_SET_LAST(MAC_SOFI_IA_NULL, 1);
		isz = 1;
	}
	used += isz;
	label->sz[MAC_SOFI_FGW] = used;
        /* A = FAR */
	d = str + strcspn(str,
	    MAC_SOFI_EXT_FAR
	    MAC_SOFI_EXT_ACL_ACL MAC_SOFI_EXT_ACL_R MAC_SOFI_EXT_ACL_W);
	isz = 0;
	if (*d == *MAC_SOFI_EXT_FAR) {
		label->flags |= MAC_SOFI_LF_FAR;
		++d;
		isz = sofi_parse_integrity(
		    &MAC_SOFI_I_ACL(label, MAC_SOFI_FAR, 0), &d);
		switch (isz) {
		case -1:
			goto error;
		case 0:
			MAC_SOFI_I_ACL(label, MAC_SOFI_FAR, 0) =
			    MAC_SOFI_IA_SET_LAST(MAC_SOFI_IA_NULL, 1);
			isz = 1;
			break;
		default:
			break;
		}
		str = d;
	} else {
		MAC_SOFI_I_ACL(label, MAC_SOFI_FAR, 0) =
		    MAC_SOFI_IA_SET_LAST(MAC_SOFI_IA_NULL, 1);
		isz = 1;
	}
	used += isz;
	label->sz[MAC_SOFI_FAR] = used;
        /* C = ACL for change ACL */
	d = str + strcspn(str,
	    MAC_SOFI_EXT_ACL_ACL MAC_SOFI_EXT_ACL_R MAC_SOFI_EXT_ACL_W);
	isz = 0;
	if (*d == *MAC_SOFI_EXT_ACL_ACL) {
		label->flags |= MAC_SOFI_LF_ACL;
		++d;
		isz = sofi_parse_acl(
		    &MAC_SOFI_I_ACL(label, MAC_SOFI_ACL_ACL, 0), &d);
		if (isz == -1)
			goto error;
		str = d;
	}
	used += isz;
	label->sz[MAC_SOFI_ACL_ACL] = used;
	/* R = ACL for read */
	d = str + strcspn(str,
	    MAC_SOFI_EXT_ACL_R MAC_SOFI_EXT_ACL_W);
	isz = 0;
	if (*d == *MAC_SOFI_EXT_ACL_R) {
		label->flags |= MAC_SOFI_LF_ACL;
		++d;
		isz = sofi_parse_acl(
		    &MAC_SOFI_I_ACL(label, MAC_SOFI_ACL_R, 0), &d);
		if (isz == -1)
			goto error;
		str = d;
	}
	used += isz;
	label->sz[MAC_SOFI_ACL_R] = used;
	/* W = ACL for write */
	d = str + strcspn(str,
	    MAC_SOFI_EXT_ACL_W);
	isz = 0;
	if (*d == *MAC_SOFI_EXT_ACL_W) {
		label->flags |= MAC_SOFI_LF_ACL;
		++d;
		isz = sofi_parse_acl(
		    &MAC_SOFI_I_ACL(label, MAC_SOFI_ACL_W, 0), &d);
		if (isz == -1)
			goto error;
		str = d;
	}
	used += isz;
	label->sz[MAC_SOFI_ACL_W] = used;
        /* end */
	if (*d != '\0')
		goto error;
	KASSERT(used <= space, "sofi_parse: used > space"); 
	*ms = label;
	return (0);
error:
	sofi_label_free(label);
	return (EINVAL);
}

static int
sofi_internalize_label(struct label *label, char *element_name,
    char *element_data, int *claimed)
{
	struct mac_sofi_label *ms;
	int error;

	if (strcmp(MAC_SOFI_LABEL_NAME, element_name) != 0)
		return (0);
	(*claimed)++;
	SOFI_DEBUG_OP("label=%p str=%s", label, element_data);
	error = sofi_parse(&ms, element_data);
	if (error)
		return (error);
	sofi_set_label_copy(ms, label);
	return (0);
}

/* whether to enforce SOFI: 1 = enforce, 0 = ignore */
static int
sofi_enforce(struct ucred *cred)
{
	if (!sofi_enabled)
		return (0);
	if (!sofi_root && cred->cr_uid == 0)
		return (0);
	if (sofi_gid >= 0 && !groupmember(sofi_gid, cred))
		return (0);
	return (1);
}

/*
 * SOFI algorithm core: testing ACLs, recomputing integrities
 */

static mac_sofi_ia *
sofi_i_subset(mac_sofi_ia *a, mac_sofi_ia *b)
{
	if (MAC_SOFI_IA_IS_ROOT(*b))
		return (NULL);
	if (MAC_SOFI_IA_IS_ROOT(*a))
		goto fail;
	if (MAC_SOFI_IA_IS_NULL(*a))
		return (NULL);
	if (MAC_SOFI_IA_IS_NULL(*b))
		goto fail;
        for (;;) {
		if (MAC_SOFI_IA_TV(*a) == MAC_SOFI_IA_TV(*b)) {
			if (MAC_SOFI_IA_IS_LAST(*a++))
				return (NULL);
			if (MAC_SOFI_IA_IS_LAST(*b++))
				goto fail;
		} else if (MAC_SOFI_IA_TV(*a) < MAC_SOFI_IA_TV(*b))
			goto fail;
		else /* MAC_SOFI_IA_TV(*a) > MAC_SOFI_IA_TV(*b) */
			if (MAC_SOFI_IA_IS_LAST(*b++))
				goto fail;
	}

	return (NULL);
fail:
	while(!MAC_SOFI_IA_IS_LAST(*a++))
		;
	return (a);
}

static int
sofi_i_subset2(mac_sofi_ia *a, mac_sofi_ia *b1, mac_sofi_ia *b2)
{
	int step;

	if (MAC_SOFI_IA_IS_ROOT(*b1) || MAC_SOFI_IA_IS_ROOT(*b2))
		return (1);
	if (MAC_SOFI_IA_IS_ROOT(*a))
		return (0);
	if (MAC_SOFI_IA_IS_NULL(*a))
		return (1);
	if (MAC_SOFI_IA_IS_NULL(*b1)) {
		if (MAC_SOFI_IA_IS_NULL(*b2))
			return (0);
		else
			b1 = b2;
	} else
		if (MAC_SOFI_IA_IS_NULL(*b2))
			b2 = b1;
	do {
		if (MAC_SOFI_IA_TV(*a) == MAC_SOFI_IA_TV(*b1)) {
			if (MAC_SOFI_IA_IS_LAST(*a++))
			    return (1);
			if (!MAC_SOFI_IA_IS_LAST(*b1))
				++b1;
		} else if (MAC_SOFI_IA_TV(*a) == MAC_SOFI_IA_TV(*b2)) {
			if (MAC_SOFI_IA_IS_LAST(*a++))
				return (1);
			if (!MAC_SOFI_IA_IS_LAST(*b2))
				++b2;
		} else if (MAC_SOFI_IA_TV(*a) < MAC_SOFI_IA_TV(*b1) &&
		    MAC_SOFI_IA_TV(*a) < MAC_SOFI_IA_TV(*b2))
			return (0);
		else {
			step = 0;
			if (MAC_SOFI_IA_TV(*a) > MAC_SOFI_IA_TV(*b1) &&
			    !MAC_SOFI_IA_IS_LAST(*b1)) {
				++b1;
				step = 1;
			}
			if (MAC_SOFI_IA_TV(*a) > MAC_SOFI_IA_TV(*b2) &&
			    !MAC_SOFI_IA_IS_LAST(*b2)) {
				++b2;
				step = 1;
			}
			if (!step)
				return (0);
		}
	} while (!MAC_SOFI_IA_IS_LAST(*b1) || !MAC_SOFI_IA_IS_LAST(*b2));

	return (0);
}

static int
sofi_check_acl(struct mac_sofi_label *subj, struct mac_sofi_label *obj,
    size_t acl)
{
	mac_sofi_ia *b, *e;

	b = &MAC_SOFI_I_ACL(obj, acl, 0);
	e = b + MAC_SOFI_I_SZ(obj, acl);
	if (b == e)
		return (0);
	while (b != e) {
		b = sofi_i_subset(b, subj->integrity);
		if (b == NULL)
			return (0);
	}
	return (EPERM);
}

static void
sofi_update_int(mac_sofi_ia *nint, struct mac_sofi_label *rd,
    struct mac_sofi_label *wr)
{
	mac_sofi_int nint2;

	sofi_int_copy(wr->integrity, nint);
	sofi_int_join(&MAC_SOFI_I_ACL(rd, MAC_SOFI_FTR, 0), nint);
	sofi_int_meet(rd->integrity, nint);
	sofi_int_copy(wr->integrity, nint2);
	sofi_int_meet(&MAC_SOFI_I_ACL(wr, MAC_SOFI_FGW, 0), nint2);
	sofi_int_meet(&MAC_SOFI_I_ACL(rd, MAC_SOFI_FAR, 0), nint2);
	sofi_int_join(nint2, nint);
}

static int
sofi_do_op(struct ucred *cred, struct label *obj_label, accmode_t accmode,
    struct mac_sofi_label **obj_n)
{
	int error;
	struct mac_sofi_label *subj, *obj_o;
	struct mac_sofi_proc_label *psubj;
	mac_sofi_int nint_subj, nint_obj;
	char dbg_mode[4] = "";

	if (accmode & VREAD)
		strcat(dbg_mode, "R");
	if (accmode & VWRITE)
		strcat(dbg_mode, "W");
	if (accmode & VEXEC)
		strcat(dbg_mode, "E");
	SOFI_DEBUG_ENFORCE("%s cred=%p cr_label=%p obj_label=%p mode=%s",
	    obj_n == NULL ? "check only" : "update integrity", cred,
	    cred->cr_label, obj_label, dbg_mode);
	
	subj = SLOT(cred->cr_label);
	obj_o = SLOT(obj_label);
	if (obj_n != NULL)
		*obj_n = NULL;
	if ((accmode & (VREAD | VEXEC)) != 0) {
		error = sofi_check_acl(subj, obj_o, MAC_SOFI_ACL_R);
		if (error != 0)
			return (error);
	}
	if ((accmode & VWRITE) != 0) {
		error = sofi_check_acl(subj, obj_o, MAC_SOFI_ACL_W);
		if (error != 0)
			return (error);
	}
	if ((accmode & (VREAD | VEXEC)) != 0) {
		sofi_update_int(nint_subj, subj, obj_o);
		if (sofi_i_subset(subj->min_int, nint_subj) != NULL)
			return (EPERM);
	}
	if ((accmode & VWRITE) != 0) {
		sofi_update_int(nint_obj, obj_o, subj);
		if (sofi_i_subset(obj_o->min_int, nint_obj) != NULL)
			return (EPERM);
	}
	if (obj_n == NULL)
		return (0);

	if ((accmode & VWRITE) != 0) {
		*obj_n = sofi_create_label_copy(obj_o, M_WAITOK);
		sofi_int_copy(nint_obj, (*obj_n)->integrity);
	}
	if ((accmode & (VREAD | VEXEC)) != 0) {
		psubj = PSLOT(curthread->td_proc->p_label);
		mtx_lock(&psubj->mtx);
		sofi_int_meet(psubj->integrity, nint_subj);
		if (sofi_i_subset(subj->min_int, nint_subj) != NULL) {
			mtx_unlock(&psubj->mtx);
			return (EPERM);
		}
		sofi_int_copy(nint_subj, psubj->integrity);
		psubj->flags |= MAC_SOFI_PLF_UPDATE;
		thread_lock(curthread);
		curthread->td_flags |= TDF_ASTPENDING | TDF_MACPEND;
		thread_unlock(curthread);
		mtx_unlock(&psubj->mtx);
	}
	return (0);
}

/*
 * Process, credentials, and thread handling
 */

static int
sofi_cred_check_relabel(struct ucred *cred, struct label *newlabel)
{
	struct mac_sofi_label *ms_cred, *ms_new, *ms_temp;
	int error = 0;

	ms_cred = SLOT(cred->cr_label);
	ms_new = SLOT(newlabel);

	if (sofi_enforce(cred)) {
		error = sofi_check_acl(ms_cred, ms_cred, MAC_SOFI_ACL_ACL);
		if (error != 0)
			return (error);
		if (sofi_i_subset(ms_new->integrity, ms_cred->integrity))
			return (EPERM);
	}

	ms_temp = sofi_modify_label(ms_cred, ms_new, M_NOWAIT);
	if (ms_temp == NULL)
		return (ENOMEM);
        sofi_set_label_copy(ms_temp, newlabel);

	return (error);
}

static void
sofi_cred_create_root(struct ucred *cred)
{
	SOFI_DEBUG_OP("cred=%p cr_label=%p", cred, cred->cr_label);
	sofi_init_label_root(cred->cr_label, M_WAITOK);
}

static void
sofi_cred_relabel(struct ucred *cred, struct label *newlabel)
{
	sofi_move_label(newlabel, cred->cr_label);
}

static void
sofi_thread_userret(struct thread *td)
{
	struct proc *p = td->td_proc;
	struct mac_sofi_proc_label *subj;
	struct ucred *newcred, *oldcred;

	subj = PSLOT(p->p_label);
	SOFI_DEBUG_OP("%p", td);
	mtx_lock(&subj->mtx);
	if (subj->flags & MAC_SOFI_PLF_UPDATE) {
		mtx_unlock(&subj->mtx);
		newcred = crget();
		PROC_LOCK(p);
		mtx_lock(&subj->mtx);
		if (subj->flags & MAC_SOFI_PLF_UPDATE) {
			/* we won the update race */
			oldcred = p->p_ucred;
			crcopy(newcred, oldcred);
			crhold(newcred);
			sofi_int_copy(subj->integrity,
			    SLOT(newcred->cr_label)->integrity);
			subj->flags &= ~MAC_SOFI_PLF_UPDATE;
			sofi_int_set_root(subj->integrity);
			p->p_ucred = newcred;
			crfree(oldcred);
		}
		mtx_unlock(&subj->mtx);
		PROC_UNLOCK(p);
	} else
		mtx_unlock(&subj->mtx);
}

/*
 * Mount point and vnode handling
 */

static void
sofi_mount_create(struct ucred *cred, struct mount *mp, struct label *mplabel)
{
	sofi_copy_label_op(cred->cr_label, mplabel);
}

static int
sofi_valid(struct mac_sofi_label *ms, int buflen)
{
	size_t sz, i, isz;

	sz = SOFI_LABEL_ALLOC_MAXSZ;
	if (buflen > sz) {
		printf("sofi_valid: size(%d) > SOFI_LABEL_ALLOC_MAXSZ(%zu)\n",
		    buflen, sz);
		return (E2BIG);
	}
	sz = sizeof(struct mac_sofi_label);
	if (buflen < sz) {
		printf("sofi_valid: size(%d) < mac_sofi_label(%zu)\n",
		    buflen, sz);
		return (EINVAL);
	}
	sz = MAC_SOFI_ACLSZ;
	if (ms->n_acl != sz) {
		printf("sofi_valid: n_acl(%hu) != MAC_SOFI_ACLSZ(%zu)\n",
		    ms->n_acl, sz);
		return (EINVAL);
	}
	sz = sizeof(struct mac_sofi_label) + sizeof(mac_sofi_acl_sz[ms->n_acl]);
	if (buflen < sz)
	{
		printf("sofi_valid: size(%d) < mac_sofi_label(%zu) + "
		    "mac_sofi_acl_sz[%hu](%zu) = %zu\n", buflen,
		    sizeof(struct mac_sofi_label), ms->n_acl,
		    sizeof(mac_sofi_acl_sz[ms->n_acl]), sz);
		return (EINVAL);
	}
	sz = SOFI_LABEL_SZ(ms);
	if (buflen != sz) {
		printf("sofi_valid: size(%d) != mac_sofi_label(%zu) + "
		    "mac_sofi_acl_sz[%hu](%zu) + mac_sofi_ia[%"PRIx32"](%zu) = "
		    "%zu\n", buflen, sizeof(struct mac_sofi_label), ms->n_acl,
		    sizeof(mac_sofi_acl_sz[ms->n_acl]), ms->sz[ms->n_acl - 1],
		    sizeof(mac_sofi_ia[ms->sz[ms->n_acl - 1]]), sz);
		return (EINVAL);
	}
	for (i = 1; i < ms->n_acl; ++i)
		if (ms->sz[i] < ms->sz[i - 1]) {
			printf("sofi_valid: sz[%zu](%"PRIx32") < "
			    "sz[%zu](%"PRIx32")\n",
			    i, ms->sz[i], i - 1, ms->sz[i - 1]);
			return (EINVAL);
		}
	for (i = 0; i < ms->n_acl; ++i) {
		isz = MAC_SOFI_I_SZ(ms, i);
		if (isz != 0 &&
		    !MAC_SOFI_IA_IS_LAST(MAC_SOFI_I_ACL(ms, i, isz - 1)))
		{
			printf("sofi_valid: "
			    "function or ACL #%zu unterminated\n", i);
			return (EINVAL);
		}
	}
	return (0);
}

static int
sofi_vnode_associate_extattr(struct mount *mp, struct label *mplabel,
    struct vnode *vp, struct label *vplabel)
{
	struct mac_sofi_label *ms_temp;
        int buflen, error;

	SOFI_DEBUG_OP("mplabel=%p vplabel=%p", mplabel, vplabel);
	ms_temp = sofi_label_alloc(MAC_SOFI_ACLSZ,
	    MAC_SOFI_ACL_MAX * MAC_SOFI_ACLSZ, M_WAITOK);
	buflen = SOFI_LABEL_ALLOC_MAXSZ;
	error = vn_extattr_get(vp, IO_NODELOCKED, MAC_SOFI_EXTATTR_NAMESPACE,
	    MAC_SOFI_EXTATTR_NAME, &buflen, (char *)ms_temp, curthread);
	if (error == ENOATTR || error == EOPNOTSUPP) {
		SOFI_DEBUG(SOFI_DBG_ERROR,
		    "%s(): vn_extattr_get=%d using mplabel=%p\n",
		    __FUNCTION__, error, mplabel);
		sofi_copy_label(mplabel, vplabel, M_WAITOK);
		sofi_label_free(ms_temp);
		return (0);
	} else if (error) {
		SOFI_DEBUG(SOFI_DBG_ERROR, "%s(): vn_extattr_get=%d\n",
		    __FUNCTION__, error);
		sofi_label_free(ms_temp);
		return (error);
	}
	if (sofi_valid(ms_temp, buflen) != 0) {
		printf("sofi_vnode_associate_extattr: invalid\n");
		sofi_label_free(ms_temp);
		return (EPERM);
	}
	sofi_set_label_copy(sofi_create_label_copy(ms_temp, M_WAITOK), vplabel);
	sofi_label_free(ms_temp);
	return (0);
}

static void
sofi_vnode_associate_singlelabel(struct mount *mp, struct label *mplabel,
    struct vnode *vp, struct label *vplabel)
{
	SOFI_DEBUG_OP("mplabel=%p vplabel=%p", mplabel, vplabel);
	sofi_copy_label(mplabel, vplabel, M_NOWAIT);
}

static int
sofi_vnode_check_access(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, accmode_t accmode)
{
	int error;
	
	if (!sofi_enforce(cred))
		return (0);

	error = sofi_do_op(cred, vplabel, accmode, NULL);

	return (error);
}

static int
sofi_vnode_check_open(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, accmode_t accmode)
{
	int error;
	struct mac_sofi_label *ms_new;
	int locked;

	if (!sofi_enforce(cred))
		return (0);

	error = sofi_do_op(cred, vplabel, accmode, &ms_new);
	if (ms_new == NULL || error != 0 || (accmode & VWRITE) == 0)
		sofi_label_free(ms_new);
	else {
		locked = VOP_ISLOCKED(vp);
		if (locked == LK_SHARED)
			VOP_LOCK(vp, LK_UPGRADE);
		sofi_set_label_copy(ms_new, vp->v_label);
		if (locked == LK_SHARED)
			VOP_LOCK(vp, LK_DOWNGRADE);
	}
	return (error);
}

static int
sofi_vnode_check_exec(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct image_params *imgp, struct label *execlabel)
{
	return (sofi_vnode_check_open(cred, vp, vplabel, VEXEC));
}

static int
sofi_vnode_check_read(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vplabel)
{
	return (sofi_vnode_check_open(active_cred, vp, vplabel, VREAD));
}

static int
sofi_vnode_check_relabel(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct label *newlabel)
{
	struct mac_sofi_label *ms_cred, *ms_vp, *ms_new, *ms_temp;
        int error = 0;
	
	ms_cred = SLOT(cred->cr_label);
	ms_vp = SLOT(vplabel);
	ms_new = SLOT(newlabel);

	if (sofi_enforce(cred)) {
		/* label modification must be permitted by ACL */
		error = sofi_check_acl(ms_cred, ms_vp, MAC_SOFI_ACL_ACL);
		if (error != 0)
			return (error);
		/* must not increase integrity too much */
		if ((ms_new->flags & MAC_SOFI_LF_I) &&
		    !sofi_i_subset2(ms_new->integrity, ms_cred->integrity,
		    ms_vp->integrity))
			return (EPERM);
	}

	ms_temp = sofi_modify_label(ms_vp, ms_new, M_WAITOK);
	sofi_set_label_copy(ms_temp, newlabel);
	return (error);
}

static int
sofi_vnode_check_write(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vplabel)
{
	return (sofi_vnode_check_open(active_cred, vp, vplabel, VWRITE));
}

static int
sofi_vnode_create_extattr(struct ucred *cred, struct mount *mp,
    struct label *mplabel, struct vnode *dvp, struct label *dvplabel,
    struct vnode *vp, struct label *vplabel, struct componentname *cnp)
{
	struct mac_sofi_label *ms_temp;
	size_t buflen;
	int error;
	struct sbuf *sb_cred, *sb_dvp, *sb_vp;

	SOFI_DEBUG_OP("cred=%p cr_label=%p mplabel=%p dvplabel=%p vplabel=%p",
	    cred, cred->cr_label, mplabel, dvplabel, vplabel);
	/* integrity from cred, everything other from dvp */
	ms_temp = sofi_create_label_copy(SLOT(dvplabel), M_WAITOK);
	sofi_int_copy(SLOT(cred->cr_label)->integrity, ms_temp->integrity);
	buflen = SOFI_LABEL_SZ(ms_temp);
	error = vn_extattr_set(vp, IO_NODELOCKED, MAC_SOFI_EXTATTR_NAMESPACE,
	    MAC_SOFI_EXTATTR_NAME, buflen, (char *)ms_temp, curthread);
	if (sofi_debug_flags & SOFI_DBG_VNCREATE) {
		sb_cred = sbuf_new_auto();
		sb_dvp = sbuf_new_auto();
		sb_vp = sbuf_new_auto();
		sofi_to_string(sb_cred, SLOT(cred->cr_label));
		sofi_to_string(sb_dvp, SLOT(dvplabel));
		sofi_to_string(sb_vp, ms_temp);
		printf("%s(): cred(%.*s) + dir(%p, %.*s) = "
		    "vnode(%p, %.*s)/%d\n", __FUNCTION__,
		    (int)sb_cred->s_len, sb_cred->s_buf,
		    dvp, (int)sb_dvp->s_len, sb_dvp->s_buf,
		    vp, (int)sb_vp->s_len, sb_vp->s_buf, error);
		sbuf_delete(sb_vp);
		sbuf_delete(sb_dvp);
		sbuf_delete(sb_cred);
	}
	if (error == 0)
		sofi_set_label_copy(ms_temp, vplabel);
	else
		sofi_label_free(ms_temp);
	return (error);
}

static void
sofi_vnode_relabel(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct label *newlabel)
{
	SOFI_DEBUG_OP("vplabel=%p newlabel=%p", vplabel, newlabel);
	sofi_move_label(newlabel, vplabel);
}

static int
sofi_vnode_setlabel_extattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct label *intlabel)
{
	struct mac_sofi_label *source;
	size_t buflen;
	int error;

	SOFI_DEBUG_OP("intlabel=%p", intlabel);
	source = SLOT(intlabel);
	buflen = SOFI_LABEL_SZ(source);
	error = vn_extattr_set(vp, IO_NODELOCKED, MAC_SOFI_EXTATTR_NAMESPACE,
	    MAC_SOFI_EXTATTR_NAME, buflen, (char *)source, curthread);
	return (error);
}

/*
 * Policy module operations.
 */

static void
sofi_init(struct mac_policy_conf *conf)
{
	if (sofi_slot_kenv >= 0) {
		sofi_slot = sofi_slot_kenv;
		log(LOG_DEBUG,
		    MAC_SOFI_MOD_NAME ": reused struct label slot %d\n",
		    sofi_slot);
	} else
		log(LOG_DEBUG, MAC_SOFI_MOD_NAME ": new struct label slot %d\n",
		    sofi_slot);
}

static struct mac_policy_ops sofi_ops =
{
	.mpo_init = sofi_init,
	
	.mpo_cred_check_relabel = sofi_cred_check_relabel, /* NOSLEEP */
	.mpo_cred_copy_label = sofi_copy_label_op, /* NOSLEEP */
	.mpo_cred_create_init = sofi_cred_create_root, /* NOSLEEP */
	.mpo_cred_create_swapper = sofi_cred_create_root, /* NOSLEEP */
	.mpo_cred_destroy_label = sofi_destroy_label_op, /* NOSLEEP */
	.mpo_cred_externalize_label = sofi_externalize_label, /* sleep */
	.mpo_cred_init_label = sofi_init_label_op, /* sleep */
	.mpo_cred_internalize_label = sofi_internalize_label, /* sleep */
	.mpo_cred_relabel = sofi_cred_relabel, /* NOSLEEP */

	.mpo_mount_create = sofi_mount_create, /* sleep */
	.mpo_mount_destroy_label = sofi_destroy_label_op, /* NOSLEEP */
	.mpo_mount_init_label = sofi_init_label_op, /* sleep */

	.mpo_proc_destroy_label = sofi_proc_destroy_label, /* NOSLEEP */
	.mpo_proc_init_label = sofi_proc_init_label, /* sleep */

	.mpo_thread_userret = sofi_thread_userret, /* sleep */

	.mpo_vnode_associate_extattr = sofi_vnode_associate_extattr, /* sleep */
	.mpo_vnode_associate_singlelabel =
	    sofi_vnode_associate_singlelabel, /* NOSLEEP */
	.mpo_vnode_copy_label = sofi_copy_label_op, /* NOSLEEP */
	.mpo_vnode_check_access = sofi_vnode_check_access, /* sleep */
	.mpo_vnode_check_exec = sofi_vnode_check_exec, /* sleep */
	.mpo_vnode_check_open = sofi_vnode_check_open, /* sleep */
	.mpo_vnode_check_read = sofi_vnode_check_read, /* sleep */
	.mpo_vnode_check_relabel = sofi_vnode_check_relabel, /* sleep */
	.mpo_vnode_check_write = sofi_vnode_check_write, /* sleep */
	.mpo_vnode_create_extattr = sofi_vnode_create_extattr, /* sleep */
	.mpo_vnode_destroy_label = sofi_destroy_label_op, /* NOSLEEP */
	.mpo_vnode_externalize_label = sofi_externalize_label, /* sleep */
	.mpo_vnode_init_label = sofi_init_label_op, /* sleep */
	.mpo_vnode_internalize_label = sofi_internalize_label, /* sleep */
	.mpo_vnode_relabel = sofi_vnode_relabel, /* sleep */
	.mpo_vnode_setlabel_extattr = sofi_vnode_setlabel_extattr, /* sleep */
};

/*
 * Module initialization. Reuse of struct label slot numbers is enabled by an
 * ugly hack.
 */

static int
mac_sofi_policy_modevent(module_t mod, int type, void *data)
{
        struct mac_policy_conf *mpc;
	char *env;
	long slot;
	
	mpc = (struct mac_policy_conf *)data;
	env = getenv(MAC_SOFI_KENV_SLOT);
	if (env != NULL) {
		slot = strtol(env, NULL, 10);
		if (slot >= 0 && slot < MAC_MAX_SLOTS) {
			mpc->mpc_field_off = NULL;
			sofi_slot_kenv = slot;
		}
	}
	return (mac_policy_modevent(mod, type, data));
}

#define mac_policy_modevent mac_sofi_policy_modevent

MAC_POLICY_SET(&sofi_ops, mac_sofi, MAC_SOFI_MOD_NAME,
    MPC_LOADTIME_FLAG_UNLOADOK, &sofi_slot);

#undef mac_policy_modevent
