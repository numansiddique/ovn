bin_PROGRAMS += pr-controller/ovn-pr-controller
pr_controller_ovn_pr_controller_SOURCES = \
	pr-controller/ovn-pr-controller.c

pr_controller_ovn_pr_controller_LDADD = lib/libovn.la $(OVS_LIBDIR)/libopenvswitch.la
man_MANS += pr-controller/ovn-pr-controller.8
EXTRA_DIST += pr-controller/ovn-pr-controller.8.xml
CLEANFILES += pr-controller/ovn-pr-controller.8
