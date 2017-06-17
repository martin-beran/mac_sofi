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
 *
 * $FreeBSD: $
 */

/*
 * Declarations for the SOFI policy module
 *
 * SOFI (Subjects and Objects with Floating Integrity) algorithm:
 *
 * Subject S performs an action (operation) A on object O
 * A can be: AR (read, data flow S<-O), AW (write S->O), ARW (S<->O)
 * A = AR:  S = R (reader), O = W (writer)
 * A = AW:  S = W         , O = R
 * A = ARW: S = RW        , O = RW
 * Data flow is always W->R (writer to reader).
 *
 * Each entity e (S, O) has:
 * 	integrity I(e) - a set of integrity attributes (IAs) {a1, ..., aN} with
 * 	    comparison function I(x) <= I(y) - integrity I(x) is a subset of
 * 	    integrity I(y)
 * 	minimum integrity MinI(e)
 *
 * Each object O has for each type of actions an access control list
 * ACL(O) - a set of integrities; common action types: read, write, change ACL
 *
 * There are functions mapping integrity -> integrity:
 * 	Each reader R has an integrity testing function FTR(i).
 * 	Each writer W has an integrity granting function FGW(i).
 * 	Each reader R has an integrity accepting function FAR(i).
 *
 * 1. Check ACL
 *      if ACL(O) is empty then grant_access
 * 	else if exists(i in ACL(O): i <= I(S)) then grant_access
 *	else { deny_access; end }
 *
 * 2. Compute new reader integrity I(R): I(S) for AR, ARW; I(O) for AW, ARW
 * 	I'(R) = I(R) & FTR(I(W)) |                                        (1)
 * 		FAR(FGW(I(W)) & I(W)) & FGW(I(W)) & I(W)                  (2)
 * 	(1) Reducing reader integrity according to writer
 * 	(2) Granting integrity by writer to reader
 * 	For simplicity, we use constant FTR, FGW, FAR:
 * 	I'(R) = I(R) & (I(W) | FTR) |
 * 		(I(W) & FGW) & FAR)
 *
 * 3. Check minimum integrity (for each reader)
 * 	if MinI(R) <= I'(R) then grant_access else { deny_access; end }
 *
 * 4. Set new integrity I(R) = I'(R)
 *
 * 5. Perform action.
 *
 * There is a special superuser IA. If it is a member of a subject's integrity,
 * any operation is permitted for the subject, regardless of ACLs. If it is a
 * member of an entity's FTR, FGW, or FAR, it behaves as containing all possible
 * IAs.
 *
 * Externalized (string) form of a label:
 * I<int>M<int>T<int>G<int>A<int>C<acl>R<acl>W<acl>
 * where:
 * I<int> = integrity
 * M<int> = minimum integrity
 * T<int> = FTR
 * G<int> = FGW
 * A<int> = FAR
 * C<acl> = MAC_SOFI_ACL_ACL
 * R<acl> = MAC_SOFI_ACL_R
 * W<acl> = MAC_SOFI_ACL_W
 * Each <int> is a plus-separated list of hexadecimal integrity values.
 * Each <acl> is a colon-separated list of <int> values; any <int> or <acl> may
 * be empty.
 * All parts (denoted by a capital letter) are generated if converting a label
 * to string.
 * If a label is to be modified by a string value, any part may be missing,
 * which means that the part will be unchanged. The exceptions are ACLs. If at
 * least one of ACL parts (C, R, or W) is present, any missing ACL part is set
 * to empty. To simplify parsing, parts must appear in the order shown above.
 */

#ifndef _SYS_SECURITY_MAC_SOFI_H
#define	_SYS_SECURITY_MAC_SOFI_H

/*
 * This kernel environment variable can be set to a struct label slot number to
 * be used by the module. It is intended for development, because slots are not
 * recycled and they will be exhausted after a few load/unload cycles.
 */
#define	MAC_SOFI_KENV_SLOT "security.mac.sofi.slot"

#define	MAC_SOFI_MOD_NAME "MAC/SOFI"

/*
 * Integrity attributes (IAs)
 */

typedef uint32_t	mac_sofi_ia;	/* IA type */

/* Partitioning of the IA space */
#define	MAC_SOFI_IA_LAST_MASK	0x80000000
#define	MAC_SOFI_IA_LAST	0x80000000 /* Marks the last IA in a sequence */

#define	MAC_SOFI_IA_TYPE_MASK	0x70000000
#define	MAC_SOFI_IA_TYPE_GLOBAL	0x00000000 /* Global IAs */
#define	MAC_SOFI_IA_TYPE_USER	0x10000000 /* Per-user IAs */
#define	MAC_SOFI_IA_TYPE_GROUP	0x20000000 /* Per-group IAs */
#define	MAC_SOFI_IA_TYPE_LOCAL	0x30000000 /* Locally defined IAs */
/* Types 0x4, 0x5, 0x6 are reserved for future use */
#define	MAC_SOFI_IA_TYPE_SOFI	0x70000000 /* Internal to SOFI implementation */

#define	MAC_SOFI_IA_VAL_MASK	0x0fffffff /* Value of an IA */
#define	MAC_SOFI_IA_UG_ID_MASK	0x0000ffff /* UID/GID in an IA */
#define	MAC_SOFI_IA_UG_VAL_MASK	0x0fff0000 /* Value in a per-user/group IA */

/* Manipulating IAs */
#define	MAC_SOFI_IA_IS_LAST(ia)	(((ia) & MAC_SOFI_IA_LAST_MASK) >> 31)
#define	MAC_SOFI_IA_TV(ia)	((ia) & ~MAC_SOFI_IA_LAST_MASK)
#define	MAC_SOFI_IA_TYPE(ia)	(((ia) & MAC_SOFI_IA_TYPE_MASK) >> 28)
#define	MAC_SOFI_IA_VAL(ia)	((ia) & MAC_SOFI_VAL_MASK)
#define	MAC_SOFI_IA_UG_ID(ia)	((ia) & MAC_SOFI_IA_UG_ID_MASK)
#define	MAC_SOFI_IA_UG_VAL(ia)	(((ia) & MAC_SOFI_IA_UG_VAL_MASK) >> 16)

#define	MAC_SOFI_IA_SET_LAST(ia, last) \
	((ia) & ~MAC_SOFI_IA_LAST_MASK | ((last) != 0) * MAC_SOFI_IA_LAST)

#define	MAC_SOFI_IA_SET(type, val)		((type) << 28 | (val))
#define	MAC_SOFI_IA_SET_UG(type, id, val) \
	((type) << 28 | (id) | (val) << 16)

/* Special IAs */
#define	MAC_SOFI_IA_ROOT	0x00000000 /* Superuser integrity */
#define	MAC_SOFI_IA_NULL	0x7fffffff /* Not an IA (in empty integrity) */

#define	MAC_SOFI_IA_IS_ROOT(ia)	(MAC_SOFI_IA_TV(ia) == MAC_SOFI_IA_ROOT)
#define	MAC_SOFI_IA_IS_NULL(ia)	(MAC_SOFI_IA_TV(ia) == MAC_SOFI_IA_NULL)

/*
 * SOFI MAC label
 * Each contained integrity is a sorted list of IAs, or a single
 * IA MAC_SOFI_IA_ROOT. 
 * Each contained function or ACL with index a is a list of integrities, stored
 * in array mac_sofi_label.sz in MAC_SOFI_I_SZ(label, a) elements starting at
 * index MAC_SOFI_I_B(label, a).
 *
 */

#define	MAC_SOFI_EXTATTR_NAMESPACE	EXTATTR_NAMESPACE_SYSTEM
#define	MAC_SOFI_EXTATTR_NAME		"mac_sofi"
#define	MAC_SOFI_LABEL_NAME		"sofi"

#define	MAC_SOFI_ISZ_MAX	16	/* Max. IAs in integrity/FTR/FGW/FAR */
#define	MAC_SOFI_ACL_MAX	64	/* Max. of IAs in ACL */

/* Label flags */
#define	MAC_SOFI_LF_LOCKED	0x0100	/* The label is locked */
#define	MAC_SOFI_LF_I		0x0001	/* Use integrity from label */
#define	MAC_SOFI_LF_MIN		0x0002	/* Use minimum integrity from label */
#define	MAC_SOFI_LF_FTR		0x0004	/* Use FTR from label */
#define	MAC_SOFI_LF_FGW		0x0008	/* Use FGW from label */
#define	MAC_SOFI_LF_FAR		0x0010	/* Use FAR from label */
#define	MAC_SOFI_LF_ACL		0x0020	/* Use ACLs from label */

/* Indices of functions and ACLs in a label */
#define	MAC_SOFI_FTR		0	/* reader's integrity testing */
#define	MAC_SOFI_FGW		1	/* writer's integrity granting */
#define	MAC_SOFI_FAR		2	/* reader's integrity accepting */
#define	MAC_SOFI_ACL_ACL	3	/* ACL for change ACL op. */
#define	MAC_SOFI_ACL_R		4	/* ACL for read */
#define	MAC_SOFI_ACL_W		5	/* ACL for write */
#define	MAC_SOFI_ACLSZ		MAC_SOFI_ACL_W + 1

typedef mac_sofi_ia	mac_sofi_int[MAC_SOFI_ISZ_MAX];	/* Integrity */

/* This ensures proper alignment of mac_sofi_label.acl */
typedef mac_sofi_ia	mac_sofi_acl_sz;

struct mac_sofi_label {
	unsigned short	flags;		/* OR of MAC_SOFI_LF_* */
	unsigned short	n_acl;	/* Number of contained ACLs (size of sz[]) */
	mac_sofi_int	integrity;	/* Integrity */
	mac_sofi_int	min_int;	/* Minimum integrity */
	mac_sofi_acl_sz	sz[/*n_acl*/];	/* Cumulative sizes of ACLs */
	/* mac_sofi_ia	acl[sz[n_acl - 1]]; aligned to sizeof(mac_sofi_ia) */
};

/* Label indexing - begin, size, and elements of functions and ACLs */
#define	SOFI_LABEL_ALLOC_SZ(n_acl, sz) \
	(sizeof(struct mac_sofi_label) + sizeof(mac_sofi_acl_sz[(n_acl)]) + \
	    sizeof(mac_sofi_ia[(sz)]))
#define	SOFI_LABEL_SZ(label)	\
    SOFI_LABEL_ALLOC_SZ((label)->n_acl, (label)->sz[(label)->n_acl - 1])
#define	SOFI_LABEL_ALLOC_MAXSZ	\
	SOFI_LABEL_ALLOC_SZ(MAC_SOFI_ACLSZ, MAC_SOFI_ACL_MAX * MAC_SOFI_ACLSZ)

#define	MAC_SOFI_I_B(label, a)	((a) <= 0 ? 0 : (label)->sz[(a) - 1])
#define	MAC_SOFI_I_SZ(label, a)	((label)->sz[(a)] - MAC_SOFI_I_B((label), (a)))
#define	MAC_SOFI_I_ACL(label, a, i) \
	((label)->sz[(label)->n_acl + MAC_SOFI_I_B((label), (a)) + (i)])

/* Label flags */
#define	MAC_SOFI_PLF_UPDATE	0x0100	/* A pending update of integrity */

/* per-process label */
struct mac_sofi_proc_label {
	unsigned short	flags;		/* OR of MAC_SOFI_PLF_* */
	mac_sofi_int	integrity;	/* the new integrity */
	struct mtx	mtx;		/* mutex for this structure */
};

/* Elements of an externalized label */
#define	MAC_SOFI_EXT_INTEGRITY	"I"
#define MAC_SOFI_EXT_MIN_INT	"M"
#define MAC_SOFI_EXT_FTR	"T"
#define MAC_SOFI_EXT_FGW	"G"
#define MAC_SOFI_EXT_FAR	"A"
#define MAC_SOFI_EXT_ACL_ACL	"C"
#define MAC_SOFI_EXT_ACL_R	"R"
#define MAC_SOFI_EXT_ACL_W	"W"
#define MAC_SOFI_EXT_SEP_IA	"+"
#define MAC_SOFI_EXT_SEP_ACL	":"

/* Debugging flags */
#define SOFI_DBG_TMP		0x0001	/* temporary debugging messages */
#define SOFI_DBG_ERROR		0x0002	/* errors */
#define SOFI_DBG_OP		0x0004	/* policy ops entry points */
#define SOFI_DBG_VNCREATE	0x0008	/* create vnode extattr label */
#define SOFI_DBG_ENFORCE	0x0010	/* policy enforcement */
#define SOFI_DBG_INT		0x0020	/* sofi_dbg_int() */

#endif /* !_SYS_SECURITY_MAC_SOFI_H */
