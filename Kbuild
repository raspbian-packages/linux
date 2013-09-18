#
# Kbuild for top-level directory of the kernel
# This file takes care of the following:
# 1) Generate bounds.h
# 2) Generate asm-offsets.h (may need bounds.h)
# 3) Check for missing system calls

#####
# 1) Generate bounds.h

bounds-file := include/generated/bounds.h

always  := $(bounds-file)
targets := $(bounds-file) kernel/bounds.s

quiet_cmd_bounds = GEN     $@
define cmd_bounds
	(set -e; \
	 echo "#ifndef __LINUX_BOUNDS_H__"; \
	 echo "#define __LINUX_BOUNDS_H__"; \
	 echo "/*"; \
	 echo " * DO NOT MODIFY."; \
	 echo " *"; \
	 echo " * This file was generated by Kbuild"; \
	 echo " *"; \
	 echo " */"; \
	 echo ""; \
	 sed -ne $(sed-y) $<; \
	 echo ""; \
	 echo "#endif" ) > $@
endef

# We use internal kbuild rules to avoid the "is up to date" message from make
kernel/bounds.s: kernel/bounds.c FORCE
	$(Q)mkdir -p $(dir $@)
	$(call if_changed_dep,cc_s_c)

$(obj)/$(bounds-file): kernel/bounds.s Kbuild
	$(Q)mkdir -p $(dir $@)
	$(call cmd,bounds)

#####
# 2) Generate asm-offsets.h
#

offsets-file := include/generated/asm-offsets.h

always  += $(offsets-file)
targets += $(offsets-file)
targets += arch/$(SRCARCH)/kernel/asm-offsets.s


# Default sed regexp - multiline due to syntax constraints
define sed-y
	"/^->/{s:->#\(.*\):/* \1 */:; \
	s:^->\([^ ]*\) [\$$#]*\([-0-9]*\) \(.*\):#define \1 \2 /* \3 */:; \
	s:^->\([^ ]*\) [\$$#]*\([^ ]*\) \(.*\):#define \1 \2 /* \3 */:; \
	s:->::; p;}"
endef

quiet_cmd_offsets = GEN     $@
define cmd_offsets
	(set -e; \
	 echo "#ifndef __ASM_OFFSETS_H__"; \
	 echo "#define __ASM_OFFSETS_H__"; \
	 echo "/*"; \
	 echo " * DO NOT MODIFY."; \
	 echo " *"; \
	 echo " * This file was generated by Kbuild"; \
	 echo " *"; \
	 echo " */"; \
	 echo ""; \
	 sed -ne $(sed-y) $<; \
	 echo ""; \
	 echo "#endif" ) > $@
endef

# We use internal kbuild rules to avoid the "is up to date" message from make
arch/$(SRCARCH)/kernel/asm-offsets.s: arch/$(SRCARCH)/kernel/asm-offsets.c \
                                      $(obj)/$(bounds-file) FORCE
	$(Q)mkdir -p $(dir $@)
	$(call if_changed_dep,cc_s_c)

$(obj)/$(offsets-file): arch/$(SRCARCH)/kernel/asm-offsets.s Kbuild
	$(call cmd,offsets)

#####
# 3) Check for missing system calls
#

always += missing-syscalls
targets += missing-syscalls

quiet_cmd_syscalls = CALL    $<
      cmd_syscalls = $(CONFIG_SHELL) $< $(CC) $(c_flags) $(missing_syscalls_flags)

missing-syscalls: scripts/checksyscalls.sh $(offsets-file) FORCE
	$(call cmd,syscalls)

# Keep these two files during make clean
no-clean-files := $(bounds-file) $(offsets-file)
