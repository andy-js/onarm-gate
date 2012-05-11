
#
#	Configuration variables for the runtime environment of the nightly
# build script and other tools for construction and packaging of releases.
# This script is sourced by 'nightly' and 'bldenv' to set up the environment
# for the build. This example is suitable for building an OpenSolaris
# workspace, which will contain the resulting archives. It is based
# off the onnv release. It sets NIGHTLY_OPTIONS to make nightly do:
#	DEBUG build only (-D, -F)
#	do not run protocmp or checkpaths (-N)
#	do not bringover from the parent (-n)
#	creates cpio archives for bfu (-a)
#	runs 'make check' (-C)
#	runs lint in usr/src (-l plus the LINTDIRS variable)
#	sends mail on completion (-m and the MAILTO variable)
#	checks for changes in ELF runpaths (-r)
#	build and use this workspace's tools in /tools (-t)
#
NIGHTLY_OPTIONS="-FNnDt";			export NIGHTLY_OPTIONS

# This is a variable for the rest of the script - GATE doesn't matter to
# nightly itself
GATE=illumos-gate;				export GATE

# CODEMGR_WS - where is your workspace at (or what should nightly name it)
CODEMGR_WS="/home/andy/Projects/illumos-gate";					export CODEMGR_WS

# Location of encumbered binaries.
ON_CLOSED_BINS="$CODEMGR_WS/closed";		export ON_CLOSED_BINS

# This flag controls whether to build the closed source.  If
# undefined, nightly(1) and bldenv(1) will set it according to whether
# the closed source tree is present.  CLOSED_IS_PRESENT="no" means not
# building the closed sources.
# CLOSED_IS_PRESENT="no";		export CLOSED_IS_PRESENT

# Maximum number of dmake jobs.  The recommended number is 2 + (2 *
# NCPUS), where NCPUS is the number of CPUs on your build system.
maxjobs() {
	ncpu=`/usr/sbin/psrinfo -p`
	expr $ncpu \* 2 + 2
}
DMAKE_MAX_JOBS=`maxjobs`;			export DMAKE_MAX_JOBS

# path to onbld tool binaries
ONBLD_BIN="/opt/onbld/bin"

# used by bfu.
FASTFS=$ONBLD_BIN/arm/fastfs;	export FASTFS
BFULD=$ONBLD_BIN/arm/bfuld;	export BFULD
GZIPBIN=/usr/bin/gzip;				export GZIPBIN
ACR=$ONBLD_BIN/acr;				export ACR

# PARENT_WS is used to determine the parent of this workspace. This is
# for the options that deal with the parent workspace (such as where the
# proto area will go).
PARENT_WS="";			export PARENT_WS

# CLONE_WS is the workspace nightly should do a bringover from. Since it's
# going to bringover usr/src, this could take a while, so we use the
# clone instead of the gate (see the gate's README).
CLONE_WS="";			export CLONE_WS

# The bringover, if any, is done as STAFFER.
# Set STAFFER to your own login as gatekeeper or developer
# The point is to use group "staff" and avoid referencing the parent
# workspace as root.
# Some scripts optionally send mail messages to MAILTO.
#
STAFFER=andy;					export STAFFER
MAILTO=$STAFFER;					export MAILTO

# The project (see project(4)) under which to run this build.  If not
# specified, the build is simply run in a new task in the current project.
BUILD_PROJECT=;				export BUILD_PROJECT

# You should not need to change the next four lines
LOCKNAME="`basename $CODEMGR_WS`_nightly.lock"; export LOCKNAME
ATLOG="$CODEMGR_WS/log";			export ATLOG
LOGFILE="$ATLOG/nightly.log";		export LOGFILE
MACH=arm;							export MACH
NATIVE_MACH=i386;			export NATIVE_MACH


# REF_PROTO_LIST - for comparing the list of stuff in your proto area
# with. Generally this should be left alone, since you want to see differences
# from your parent (the gate).
#
REF_PROTO_LIST=$PARENT_WS/usr/src/proto_list_${MACH};	export REF_PROTO_LIST

# where cpio archives of the OS are placed. Usually this should be left
# alone too.
CPIODIR="${CODEMGR_WS}/archives/${MACH}/nightly";		export CPIODIR

#
#	build environment variables, including version info for mcs, motd,
# motd, uname and boot messages. Mostly you shouldn't change this except
# when the release slips (nah) or you move an environment file to a new
# release
#
ROOT="$CODEMGR_WS/proto/root_${MACH}";	export ROOT
SRC="$CODEMGR_WS/usr/src";					export SRC
VERSION="$GATE";							export VERSION

#
# the RELEASE and RELEASE_DATE variables are set in Makefile.master;
# there might be special reasons to override them here, but that
# should not be the case in general
#
# RELEASE="5.11";			export RELEASE
# RELEASE_DATE="October 2007";		export RELEASE_DATE

# proto area in parent for optionally depositing a copy of headers and
# libraries corresponding to the protolibs target
# not applicable given the NIGHTLY_OPTIONS
#
PARENT_ROOT=$PARENT_WS/proto/root_$MACH;	export PARENT_ROOT

#
#       package creation variable. you probably shouldn't change this either.
#
PKGARCHIVE="${CODEMGR_WS}/packages/${MACH}/nightly";	export PKGARCHIVE

# we want make to do as much as it can, just in case there's more than
# one problem.
MAKEFLAGS=k;	export MAKEFLAGS

# Magic variable to prevent the devpro compilers/teamware from sending
# mail back to devpro on every use.
UT_NO_USAGE_TRACKING="1"; export UT_NO_USAGE_TRACKING

# Build tools - don't change these unless you know what you're doing.  These
# variables allows you to get the compilers and onbld files locally or
# through cachefs.  Set BUILD_TOOLS to pull everything from one location.
# Alternately, you can set ONBLD_TOOLS to where you keep the contents of
# SUNWonbld and SPRO_ROOT to where you keep the compilers.  SPRO_VROOT
# exists to make it easier to test new versions of the compiler.
BUILD_TOOLS=/opt;				export BUILD_TOOLS
#ONBLD_TOOLS=/opt/onbld;			export ONBLD_TOOLS
#SPRO_ROOT=/opt/SUNWspro;			export SPRO_ROOT
#SPRO_VROOT=;				export SPRO_VROOT

# This goes along with lint - it is a series of the form "A [y|n]" which
# means "go to directory A and run 'make lint'" Then mail me (y) the
# difference in the lint output. 'y' should only be used if the area you're
# linting is actually lint clean or you'll get lots of mail.
# You shouldn't need to change this though.
#LINTDIRS="$SRC y";	export LINTDIRS

# Set this flag to 'n' to disable the automatic validation of the dmake
# version in use.  The default is to check it.
CHECK_DMAKE=n

# Set this flag to 'n' to disable the use of 'checkpaths'.  The default,
# if the 'N' option is not specified, is to run this test.
#CHECK_PATHS=y

# BRINGOVER_FILES is the list of files nightly passes to bringover.
# If not set the default is "usr", but it can be used for bringing
# over deleted_files or other nifty directories.
#BRINGOVER_FILES="usr deleted_files"

# POST_NIGHTLY can be any command to be run at the end of nightly.  See
# nightly(1) for interactions between environment variables and this command.
#POST_NIGHTLY=

#
# the source product has no SCCS history, and is modified to remove source
# that cannot be shipped. EXPORT_SRC is where the clear files are copied, then
# modified with 'make EXPORT_SRC'.
#
EXPORT_SRC="$CODEMGR_WS/export_src";	export EXPORT_SRC

#
# CRYPT_SRC is similar to EXPORT_SRC, but after 'make CRYPT_SRC' the files in
# xmod/cry_files are saved. They are dropped on the exportable source to create
# the domestic build.
#

CRYPT_SRC="$CODEMGR_WS/crypt_src";		export CRYPT_SRC

#
# OPEN_SRCDIR is where we copy the open tree to so that we can be sure
# we don't have a hidden dependency on closed code.  The name ends in
# "DIR" to avoid confusion with the flags related to open source
# builds.
#

OPEN_SRCDIR="$CODEMGR_WS/open_src";	export OPEN_SRCDIR

#
# Flag to enable creation of per-build-type proto areas.  If "yes",
# more proto areas are created, which speeds up incremental builds but
# increases storage consumption.  Will be forced to "yes" for
# OpenSolaris deliveries.
#
MULTI_PROTO=no;							export MULTI_PROTO

__GNUC="";          export __GNUC
CW_NO_SHADOW=1;         export CW_NO_SHADOW
GNU_ROOT=/opt/arm-eabi/arm-pc-solaris2.11;					export GNU_ROOT
GNU_PREFIX=/opt/arm-eabi;				export GNU_PREFIX
GNU_TOOL_TARGET=arm-pc-solaris2.11;			export GNU_TOOL_TARGET
GNU_TOOL_PREFIX=arm-pc-solaris2.11-;	export GNU_TOOL_PREFIX
DEFAULT_SYSROOT=/opt/arm-eabi/root;		export DEFAULT_SYSROOT
LD_PREFIX=/opt/arm-eabi;			export LD_PREFIX
__LINT=#;           export __LINT
__ARLIB=#;          export __ARLIB
__SOLIB="";         export __SOLIB
USE_WS_TOOLS=;          export USE_WS_TOOLS
USE_UTSTUNE=;           export USE_UTSTUNE


# Target ARM platform.
ARM_PLATFORM=ne1; export ARM_PLATFORM

# Comment out below line if you want to use GNU binutils linker
# to build OpenSolaris.
__GNU_LD=#;			export __GNU_LD

# ARM architecture doesn't support 64-bit build.
BUILD64=#;			export BUILD64

# Use ARM EABI mode.
GNUC_ARM_EABI=;		export GNUC_ARM_EABI

# Install all kernel modules under /usr directory.
# Set '#' if you don't want to.
KMODS_INST_USR=;	export KMODS_INST_USR

# IPv4 only.
USE_INET6=#;		export USE_INET6
