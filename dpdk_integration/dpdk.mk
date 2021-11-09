DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_PIPELINE)       += -lrte_pipeline
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_TABLE)          += -lrte_table
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_PORT)           += -lrte_port

DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_PDUMP)          += -lrte_pdump
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_DISTRIBUTOR)    += -lrte_distributor
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_REORDER)        += -lrte_reorder
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_IP_FRAG)        += -lrte_ip_frag
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_METER)          += -lrte_meter
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_SCHED)          += -lrte_sched
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_LPM)            += -lrte_lpm
# librte_acl needs --whole-archive because of weak functions
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_ACL)            += -Wl,--whole-archive
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_ACL)            += -lrte_acl
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_ACL)            += -Wl,--no-whole-archive
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_JOBSTATS)       += -lrte_jobstats
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_POWER)          += -lrte_power

DPDK_LDLIBS-y += -Wl,--whole-archive

DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_TIMER)          += -lrte_timer
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_HASH)           += -lrte_hash
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_VHOST)          += -lrte_vhost

DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_KVARGS)         += -lrte_kvargs
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_MBUF)           += -lrte_mbuf
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_ETHER)          += -lrte_ethdev
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_CRYPTODEV)      += -lrte_cryptodev
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_MEMPOOL)        += -lrte_mempool
DPDK_LDLIBS-$(CONFIG_RTE_DRIVER_MEMPOOL_RING)   += -lrte_mempool_ring
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_RING)           += -lrte_ring
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_EAL)            += -lrte_eal
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_CMDLINE)        += -lrte_cmdline
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_CFGFILE)        += -lrte_cfgfile
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_NET)            += -lrte_net

DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_PMD_BOND)       += -lrte_pmd_bond
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_PMD_XENVIRT)    += -lrte_pmd_xenvirt -lxenstore

DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_PCI)            += -lrte_pci
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_PCI_BUS)        += -lrte_bus_pci
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_VDEV_BUS)       += -lrte_bus_vdev

ifeq ($(CONFIG_RTE_BUILD_SHARED_LIB),n)
# plugins (link only if static libraries)
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_PMD_AF_PACKET)  += -lrte_pmd_af_packet
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_BNX2X_PMD)      += -lrte_pmd_bnx2x -lz
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_BNXT_PMD)       += -lrte_pmd_bnxt
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_CXGBE_PMD)      += -lrte_pmd_cxgbe
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_E1000_PMD)      += -lrte_pmd_e1000
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_ENA_PMD)        += -lrte_pmd_ena
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_ENIC_PMD)       += -lrte_pmd_enic
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_FM10K_PMD)      += -lrte_pmd_fm10k
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_I40E_PMD)       += -lrte_pmd_i40e
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_IXGBE_PMD)      += -lrte_pmd_ixgbe
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_MLX4_PMD)       += -lrte_pmd_mlx4 -libverbs
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_MLX5_PMD)       += -lrte_pmd_mlx5 -libverbs
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_MPIPE_PMD)      += -lrte_pmd_mpipe -lgxio
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_NFP_PMD)        += -lrte_pmd_nfp -lm
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_PMD_NULL)       += -lrte_pmd_null
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_PMD_PCAP)       += -lrte_pmd_pcap -lpcap
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_QEDE_PMD)       += -lrte_pmd_qede -lz
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_PMD_RING)       += -lrte_pmd_ring
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_PMD_SZEDATA2)   += -lrte_pmd_szedata2 -lsze2
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_THUNDERX_NICVF_PMD) += -lrte_pmd_thunderx_nicvf -lm
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_VIRTIO_PMD)     += -lrte_pmd_virtio
ifeq ($(CONFIG_RTE_LIBRTE_VHOST),y)
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_PMD_VHOST)      += -lrte_pmd_vhost
endif # $(CONFIG_RTE_LIBRTE_VHOST)
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_VMXNET3_PMD)    += -lrte_pmd_vmxnet3_uio

ifeq ($(CONFIG_RTE_LIBRTE_CRYPTODEV),y)
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_PMD_AESNI_MB)   += -lrte_pmd_aesni_mb
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_PMD_AESNI_MB)   += -L$(AESNI_MULTI_BUFFER_LIB_PATH) -lIPSec_MB
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_PMD_AESNI_GCM)  += -lrte_pmd_aesni_gcm -lcrypto
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_PMD_AESNI_GCM)  += -L$(AESNI_MULTI_BUFFER_LIB_PATH) -lIPSec_MB
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_PMD_NULL_CRYPTO) += -lrte_pmd_null_crypto
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_PMD_QAT)        += -lrte_pmd_qat -lrte_compressdev -lcrypto
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_PMD_SNOW3G)     += -lrte_pmd_snow3g
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_PMD_SNOW3G)     += -L$(LIBSSO_SNOW3G_PATH)/build -lsso_snow3g
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_PMD_KASUMI)     += -lrte_pmd_kasumi
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_PMD_KASUMI)     += -L$(LIBSSO_KASUMI_PATH)/build -lsso_kasumi
endif # CONFIG_RTE_LIBRTE_CRYPTODEV

endif # !CONFIG_RTE_BUILD_SHARED_LIBS

DPDK_LDLIBS-y += -Wl,--no-whole-archive

ifeq ($(CONFIG_RTE_BUILD_SHARED_LIB),n)
# The static libraries do not know their dependencies.
# So linking with static library requires explicit dependencies.
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_EAL)            += -lrt
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_SCHED)          += -lm
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_SCHED)          += -lrt
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_METER)          += -lm
ifeq ($(CONFIG_RTE_EXEC_ENV_LINUXAPP)$(CONFIG_RTE_EAL_NUMA_AWARE_HUGEPAGES),yy)
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_EAL)          += -lnuma
endif
ifeq ($(CONFIG_RTE_LIBRTE_VHOST_USER),n)
DPDK_LDLIBS-$(CONFIG_RTE_LIBRTE_VHOST)          += -lfuse
endif
DPDK_LDLIBS-$(CONFIG_RTE_PORT_PCAP)             += -lpcap
endif # !CONFIG_RTE_BUILD_SHARED_LIBS
