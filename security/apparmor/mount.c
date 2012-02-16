/*
 * AppArmor security module
 *
 * This file contains AppArmor mediation of files
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2012 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/namei.h>

#include "include/apparmor.h"
#include "include/audit.h"
#include "include/context.h"
#include "include/domain.h"
#include "include/file.h"
#include "include/match.h"
#include "include/mount.h"
#include "include/path.h"
#include "include/policy.h"


static void audit_mnt_flags(struct audit_buffer *ab, unsigned long flags)
{
	if (flags & MS_RDONLY)
		audit_log_format(ab, "ro");
	else
		audit_log_format(ab, "rw");
	if (flags & MS_NOSUID)
		audit_log_format(ab, ", nosuid");
	if (flags & MS_NODEV)
		audit_log_format(ab, ", nodev");
	if (flags & MS_NOEXEC)
		audit_log_format(ab, ", noexec");
	if (flags & MS_SYNCHRONOUS)
		audit_log_format(ab, ", sync");
	if (flags & MS_REMOUNT)
		audit_log_format(ab, ", remount");
	if (flags & MS_MANDLOCK)
		audit_log_format(ab, ", mand");
	if (flags & MS_DIRSYNC)
		audit_log_format(ab, ", dirsync");
	if (flags & MS_NOATIME)
		audit_log_format(ab, ", noatime");
	if (flags & MS_NODIRATIME)
		audit_log_format(ab, ", nodiratime");
	if (flags & MS_BIND)
		audit_log_format(ab, flags & MS_REC ? ", rbind" : ", bind");
	if (flags & MS_MOVE)
		audit_log_format(ab, ", move");
	if (flags & MS_SILENT)
		audit_log_format(ab, ", silent");
	if (flags & MS_POSIXACL)
		audit_log_format(ab, ", acl");
	if (flags & MS_UNBINDABLE)
		audit_log_format(ab, flags & MS_REC ? ", runbindable" :
				 ", unbindable");
	if (flags & MS_PRIVATE)
		audit_log_format(ab, flags & MS_REC ? ", rprivate" :
				 ", private");
	if (flags & MS_UNBINDABLE)
		audit_log_format(ab, flags & MS_REC ? ", rslave" :
				 ", slave");
	if (flags & MS_UNBINDABLE)
		audit_log_format(ab, flags & MS_REC ? ", rshared" :
				 ", shared");
	if (flags & MS_RELATIME)
		audit_log_format(ab, ", relatime");
	if (flags & MS_I_VERSION)
		audit_log_format(ab, ", iversion");
	if (flags & MS_STRICTATIME)
		audit_log_format(ab, ", strictatime");
	if (flags & MS_NOUSER)
		audit_log_format(ab, ", nouser");
}

/**
 * mount_audit_cb - call back for mount specific audit fields
 * @ab: audit_buffer  (NOT NULL)
 * @va: audit struct to audit values of  (NOT NULL)
 */
static void mount_audit_cb(struct audit_buffer *ab, void *va)
{
	struct common_audit_data *sa = va;

	if (sa->aad.mnt.type) {
		audit_log_format(ab, " fstype=");
		audit_log_untrustedstring(ab, sa->aad.mnt.type);
	}
	if (sa->aad.mnt.src_name) {
		audit_log_format(ab, " src_name=");
		audit_log_untrustedstring(ab, sa->aad.mnt.src_name);
	}
	if (sa->aad.mnt.trans) {
		audit_log_format(ab, " trans=");
		audit_log_untrustedstring(ab, sa->aad.mnt.trans);
	}
	if (sa->aad.mnt.flags || sa->aad.op == OP_MOUNT) {
		audit_log_format(ab, " flags=\"");
		audit_mnt_flags(ab, sa->aad.mnt.flags);
		audit_log_format(ab, "\"");
	}
	if (sa->aad.mnt.data) {
		audit_log_format(ab, " options=");
		audit_log_untrustedstring(ab, sa->aad.mnt.data);
	}
}

/**
 * aa_audit_file - handle the auditing of file operations
 * @profile: the profile being enforced  (NOT NULL)
 * @gfp: allocation flags
 * @op: operation being mediated
 * @name: name of object being mediated (MAYBE NULL)
 * @src_name: src_name of object being mediated (MAYBE_NULL)
 * @type: type of filesystem
 * @trans: name of trans (MAYBE NULL)
 * @flags: filesystem idependent mount flags
 * @data: filesystem mount flags
 * @request: permissions requested
 * @perms: the permissions computed for the request (NOT NULL)
 * @info: extra information message (MAYBE NULL)
 * @error: 0 if operation allowed else failure error code
 *
 * Returns: %0 or error on failure
 */
int aa_audit_mount(struct aa_profile *profile, gfp_t gfp, int op,
		   const char *name, const char *src_name, const char *type,
		   const char *trans, unsigned long flags, void *data,
		   u32 request, struct file_perms *perms, const char *info,
		   int error)
{
	int audit_type = AUDIT_APPARMOR_AUTO;
	struct common_audit_data sa;

	if (likely(!error)) {
		u32 mask = perms->audit;

		if (unlikely(AUDIT_MODE(profile) == AUDIT_ALL))
			mask = 0xffff;

		/* mask off perms that are not being force audited */
		request &= mask;

		if (likely(!request))
			return 0;
		audit_type = AUDIT_APPARMOR_AUDIT;
	} else {
		/* only report permissions that were denied */
		request = request & ~perms->allow;

		if (request & perms->kill)
			audit_type = AUDIT_APPARMOR_KILL;

		/* quiet known rejects, assumes quiet and kill do not overlap */
		if ((request & perms->quiet) &&
		    AUDIT_MODE(profile) != AUDIT_NOQUIET &&
		    AUDIT_MODE(profile) != AUDIT_ALL)
			request &= ~perms->quiet;

		if (!request)
			return COMPLAIN_MODE(profile) ? 0 : error;
	}

	COMMON_AUDIT_DATA_INIT(&sa, NONE);
	sa.aad.op = op,
	sa.aad.name = name;
	sa.aad.info = info;
	sa.aad.error = error;
	sa.aad.mnt.src_name = src_name;
	sa.aad.mnt.type = type;
	sa.aad.mnt.trans = trans;
	sa.aad.mnt.flags = flags;
	sa.aad.mnt.data = data;

	return aa_audit(audit_type, profile, gfp, &sa, mount_audit_cb);
}


/**
 * match_mnt_flags - Do an ordered match on mount flags
 * @dfa: dfa to match against
 * @state: state to start in
 * @flags: mount flags to match against
 *
 * Mount flags are encoded as an ordered match. This is done instead of
 * checking against a simple bitmask, to allow for logical operations
 * on the flags.
 *
 * Returns: next state after flags match
 */
static unsigned int match_mnt_flags(struct aa_dfa *dfa, unsigned int state,
				    unsigned long flags)
{
	unsigned int i;

	for (i = 0; i <= 31 ; ++i) {
		if ((1 << i) & flags)
			state = aa_dfa_next(dfa, state, i + 1);
	}
	return state;
}

/**
 * compute_mnt_perms - compute mount permission associated with @state
 * @dfa: dfa to match against (NOT NULL)
 * @state: state match finished in
 *
 * Returns: mount permissions
 */
static struct file_perms compute_mnt_perms(struct aa_dfa *dfa,
					   unsigned int state)
{
	struct file_perms perms;

	perms.kill = 0;
	perms.allow = dfa_user_allow(dfa, state);
	perms.audit = dfa_user_audit(dfa, state);
	perms.quiet = dfa_user_quiet(dfa, state);
	perms.xindex = dfa_user_xindex(dfa, state);

	return perms;
}

static int path_flags(struct aa_profile *profile, struct path *path)
{
	return profile->path_flags |
		S_ISDIR(path->dentry->d_inode->i_mode) ? PATH_IS_DIR : 0;
}

int aa_remount(struct aa_profile *profile, struct path *path,
	       unsigned long flags, void *data)
{
	struct file_perms perms;
	const char *name, *info = NULL;
	char *buffer = NULL;
	int binarydata, error;

	binarydata = path->dentry->d_sb->s_type->fs_flags & FS_BINARY_MOUNTDATA;

	error = aa_path_name(path, path_flags(profile, path), &buffer, &name,
			     &info);
	if (error)
		goto audit;

	if (profile->policy.dfa) {
		unsigned int state;
		state = aa_dfa_match(profile->policy.dfa,
				     profile->policy.start[AA_CLASS_MOUNT],
				     name);
		state = aa_dfa_null_transition(profile->policy.dfa, state);
		/* skip device */
		state = aa_dfa_null_transition(profile->policy.dfa, state);
		/* skip type */
		state = aa_dfa_null_transition(profile->policy.dfa, state);
		state = match_mnt_flags(profile->policy.dfa, state, flags);
		state = aa_dfa_null_transition(profile->policy.dfa, state);
		if (data && !binarydata)
			state = aa_dfa_match(profile->policy.dfa, state,
					     data);
		perms = compute_mnt_perms(profile->policy.dfa, state);
	}

	if (AA_MAY_MOUNT & ~perms.allow)
		error = -EACCES;

audit:
	error = aa_audit_mount(profile, GFP_KERNEL, OP_MOUNT, name,
			       NULL, NULL, NULL, flags, data, AA_MAY_MOUNT,
			       &perms, info, error);
	kfree(buffer);

	return error;
}

int aa_bind_mount(struct aa_profile *profile, struct path *path,
		  const char *dev_name, unsigned long flags)
{
	struct file_perms perms = { };
	char *buffer = NULL, *old_buffer = NULL;
	const char *name, *old_name, *info = NULL;
	struct path old_path;
	int error;

	if (!dev_name || !*dev_name)
		return -EINVAL;

	flags &= MS_REC | MS_BIND;

	error = aa_path_name(path, path_flags(profile, path), &buffer, &name,
			     &info);
	if (error)
		goto audit;

	error = kern_path(dev_name, LOOKUP_FOLLOW|LOOKUP_AUTOMOUNT, &old_path);
	if (error)
		goto audit;

	error = aa_path_name(&old_path, path_flags(profile, &old_path),
			     &old_buffer, &old_name, &info);
	path_put(&old_path);
	if (error)
		goto audit;

	if (profile->policy.dfa) {
		unsigned int state;
		state = aa_dfa_match(profile->policy.dfa,
				     profile->policy.start[AA_CLASS_MOUNT],
				     name);
		state = aa_dfa_null_transition(profile->policy.dfa, state);
		state = aa_dfa_match(profile->policy.dfa, state, old_name);
		state = aa_dfa_null_transition(profile->policy.dfa, state);
		/* skip type */
		state = aa_dfa_null_transition(profile->policy.dfa, state);
		state = match_mnt_flags(profile->policy.dfa, state, flags);
		perms = compute_mnt_perms(profile->policy.dfa, state);
	}

	if (AA_MAY_MOUNT & ~perms.allow)
		error = -EACCES;

audit:
	error = aa_audit_mount(profile, GFP_KERNEL, OP_MOUNT, name,
			       old_name, NULL, NULL, flags, NULL,
			       AA_MAY_MOUNT, &perms, info, error);

	kfree(buffer);
	kfree(old_buffer);

	return error;
}

int aa_mount_change_type(struct aa_profile *profile, struct path *path,
			 unsigned long flags)
{
	struct file_perms perms = { };
	char *buffer = NULL;
	const char *name, *info = NULL;
	int error;

	flags &= (MS_REC | MS_SILENT | MS_SHARED | MS_PRIVATE | MS_SLAVE |
		  MS_UNBINDABLE);

	error = aa_path_name(path, path_flags(profile, path), &buffer, &name,
			     &info);
	if (error)
		goto audit;

	if (profile->policy.dfa) {
		unsigned int state;
		state = aa_dfa_match(profile->policy.dfa,
				     profile->policy.start[AA_CLASS_MOUNT],
				     name);
		state = aa_dfa_null_transition(profile->policy.dfa, state);
		/* skip device */
		state = aa_dfa_null_transition(profile->policy.dfa, state);
		/* skip type */
		state = aa_dfa_null_transition(profile->policy.dfa, state);
		state = match_mnt_flags(profile->policy.dfa, state, flags);
		perms = compute_mnt_perms(profile->policy.dfa, state);
	}

	if (AA_MAY_MOUNT & ~perms.allow)
		error = -EACCES;

audit:
	error = aa_audit_mount(profile, GFP_KERNEL, OP_MOUNT, name,
			       NULL, NULL, NULL, flags, NULL,
			       AA_MAY_MOUNT, &perms, info, error);
	kfree(buffer);

	return error;
}

int aa_move_mount(struct aa_profile *profile, struct path *path,
		  const char *orig_name)
{
	struct file_perms perms = { };
	char *buffer = NULL, *old_buffer = NULL;
	const char *name, *old_name, *info = NULL;
	struct path old_path;
	int error;

	if (!orig_name || !*orig_name)
		return -EINVAL;

	error = aa_path_name(path, path_flags(profile, path), &buffer, &name,
			     &info);
	if (error)
		goto audit;

	error = kern_path(orig_name, LOOKUP_FOLLOW, &old_path);
	if (error)
		goto audit;

	error = aa_path_name(&old_path, path_flags(profile, &old_path),
			     &old_buffer, &old_name, &info);
	path_put(&old_path);
	if (error)
		goto audit;

	if (profile->policy.dfa) {
		unsigned int state;
		state = aa_dfa_match(profile->policy.dfa,
				     profile->policy.start[AA_CLASS_MOUNT],
				     name);
		state = aa_dfa_null_transition(profile->policy.dfa, state);
		state = aa_dfa_match(profile->policy.dfa, state, old_name);
		state = aa_dfa_null_transition(profile->policy.dfa, state);
		/* skip type */
		state = aa_dfa_null_transition(profile->policy.dfa, state);
		state = match_mnt_flags(profile->policy.dfa, state, MS_MOVE);
		perms = compute_mnt_perms(profile->policy.dfa, state);
	}

	if (AA_MAY_MOUNT & ~perms.allow)
		error = -EACCES;

audit:
	error = aa_audit_mount(profile, GFP_KERNEL, OP_MOUNT, name,
			       old_name, NULL, NULL, MS_MOVE, NULL,
			       AA_MAY_MOUNT, &perms, info, error);

	kfree(buffer);
	kfree(old_buffer);

	return error;
}

int aa_new_mount(struct aa_profile *profile, const char *orig_dev_name,
		 struct path *path, const char *type, unsigned long flags,
		 void *data)
{
	struct file_system_type *fstype = NULL;
	struct file_perms perms = { };
	char *buffer = NULL, *dev_buffer = NULL;
	const char *name, *dev_name, *info = NULL;
	struct path dev_path;
	int binary_data, error;

	fstype = get_fs_type(type);
	if (!fstype) {
		error = -ENODEV;
		goto out;
	}
	binary_data = fstype->fs_flags & FS_BINARY_MOUNTDATA;

	if (fstype->fs_flags & FS_REQUIRES_DEV) {
		if (!dev_name) {
			error = -ENOENT;
			goto out;
		}

		error = kern_path(orig_dev_name, LOOKUP_FOLLOW, &dev_path);
		if (error)
			goto audit;

		error = aa_path_name(&dev_path, path_flags(profile, &dev_path),
				     &dev_buffer, &dev_name, &info);
		path_put(&dev_path);
		if (error)
			goto audit;
	} else
		dev_name = orig_dev_name;

	error = aa_path_name(path, path_flags(profile, path), &buffer, &name,
			     &info);
	if (error)
		goto audit;

	if (profile->policy.dfa) {
		unsigned int state;
		state = aa_dfa_match(profile->policy.dfa,
				     profile->policy.start[AA_CLASS_MOUNT],
				     name);
		state = aa_dfa_null_transition(profile->policy.dfa, state);
		if (dev_name)
			state = aa_dfa_match(profile->policy.dfa, state,
					     dev_name);
		state = aa_dfa_null_transition(profile->policy.dfa, state);
		state = aa_dfa_match(profile->policy.dfa, state, type);
		state = aa_dfa_null_transition(profile->policy.dfa, state);
		state = match_mnt_flags(profile->policy.dfa, state, flags);
		state = aa_dfa_null_transition(profile->policy.dfa, state);
		if (data && !binary_data)
			state = aa_dfa_match(profile->policy.dfa, state,
					     data);
		perms = compute_mnt_perms(profile->policy.dfa, state);
	}

	if (AA_MAY_MOUNT & ~perms.allow)
		error = -EACCES;

audit:
	error = aa_audit_mount(profile, GFP_KERNEL, OP_MOUNT, name,  dev_name,
			       type, NULL, flags, data, AA_MAY_MOUNT,
			       &perms, info, error);
	kfree(buffer);
	kfree(dev_buffer);

out:
	if (fstype)
		put_filesystem(fstype);

	return error;

}

int aa_umount(struct aa_profile *profile, struct vfsmount *mnt, int flags)
{
	struct file_perms perms = { };
	char *buffer = NULL;
	const char *name, *info = NULL;
	int error;

	struct path path = { mnt, mnt->mnt_root };
	error = aa_path_name(&path, path_flags(profile, &path), &buffer, &name,
			     &info);
	if (error)
		goto audit;

	if (profile->policy.dfa) {
		unsigned int state;
		state = aa_dfa_match(profile->policy.dfa,
				     profile->policy.start[AA_CLASS_MOUNT],
				     name);
		perms = compute_mnt_perms(profile->policy.dfa, state);
	}

	if (AA_MAY_UMOUNT & ~perms.allow)
		error = -EACCES;

audit:
	error = aa_audit_mount(profile, GFP_KERNEL, OP_UMOUNT, name, NULL,
			       NULL, NULL, 0, NULL, AA_MAY_UMOUNT,
			       &perms, info, error);
	kfree(buffer);

	return error;
}

int aa_pivotroot(struct aa_profile *profile, struct path *old_path,
		  struct path *new_path)
{
	struct file_perms perms = { };
	struct aa_profile *target = NULL;
	char *old_buffer = NULL, *new_buffer = NULL;
	const char *old_name, *new_name, *info = NULL;
	int error;

	error = aa_path_name(old_path, path_flags(profile, old_path),
			     &old_buffer, &old_name, &info);
	if (error)
		goto audit;

	error = aa_path_name(new_path, path_flags(profile, new_path),
			     &new_buffer, &new_name, &info);
	if (error)
		goto audit;

	if (profile->policy.dfa) {
		unsigned int state;
		state = aa_dfa_match(profile->policy.dfa,
				     profile->policy.start[AA_CLASS_MOUNT],
				     old_name);
		state = aa_dfa_null_transition(profile->policy.dfa, state);
		state = aa_dfa_match(profile->policy.dfa, state, new_name);
		perms = compute_mnt_perms(profile->policy.dfa, state);
	}

	if (AA_MAY_PIVOTROOT & perms.allow) {
		if ((perms.xindex & AA_X_TYPE_MASK) == AA_X_TABLE) {
			target = x_table_lookup(profile, perms.xindex);
			if (!target)
				error = -ENOENT;
			else
				error = aa_replace_current_profile(target);
		}
	} else
		error = -EACCES;

audit:
	error = aa_audit_mount(profile, GFP_KERNEL, OP_PIVOTROOT, new_name,
			       old_name, NULL,
			       target ? target->base.name : NULL, 0, NULL,
			       AA_MAY_PIVOTROOT, &perms, info, error);

	aa_put_profile(target);
	kfree(old_buffer);
	kfree(new_buffer);

	return error;
}
