bin_PROGRAMS += pr-controller/ovn-pr-controller
pr_controller_ovn_pr_controller_SOURCES = \
	pr-controller/ovn-pr-controller.c \
	pr-controller/en-lflow.c \
	pr-controller/en-lflow.h \
	pr-controller/en-runtime-data.c \
	pr-controller/en-runtime-data.h

pr_controller_ovn_pr_controller_LDADD = lib/libovn.la $(OVS_LIBDIR)/libopenvswitch.la
man_MANS += pr-controller/ovn-pr-controller.8
EXTRA_DIST += pr-controller/ovn-pr-controller.8.xml
CLEANFILES += pr-controller/ovn-pr-controller.8
