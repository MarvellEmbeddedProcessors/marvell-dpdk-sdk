.. SPDX-License-Identifier: BSD-3-Clause
   Copyright(c) 2023 Marvell.

Marvell octeon_ep_bb_vf Poll Mode Driver
========================================

octeon_ep_bb_vf BBDEV poll mode driver (PMD) offloads 4G/5G Phy processing functions
(LDPC/TURBO Encode/Decode) to OCTEON CNXK based accelerator using SDP interface to
transfer data between host and CNXK using Gen5x4 PCI interface.

More information about OCTEON CNXK SoCs may be obtained from `<https://www.marvell.com>`_.

Features
--------

octeon_ep_bb_vf BBDEV PMD currently supports the following features:

- CN10XX SoC
- Support for LDPC_DEC/LDPC_ENC/TURBO_ENC/TURBO_DEC operations
- Up to 31 VFs
- Up to 8 queue pairs per VF each supporting one operation.
    (If no of VFs is 31 then max no of queues per each VF should be 4 since maximum 128 queues can only be mapped across all VFs 31*4=124<128)
- PCIe Gen-5x4 Interface

Installation
------------

octeon_ep_bb_vf BBDEV PMD is cross-compiled for host platform during DPDK build.

.. note::

   octeon_ep_bb_vf BBDEV PMD uses services from the kernel mode OCTEON EP
   PF driver in linux. This driver is included in the OCTEON TX SDK.

Initialization
--------------

List PF devices available on cn10k platform:

.. code-block:: console

    lspci -nnD | grep ef01

``ef01`` is octeon_ep_bb_vf PF device id.  Output should be:

.. code-block:: console

    0000:0a:00.0 Processing accelerators: Cavium, Inc. Device ef01
    0000:0a:00.1 Processing accelerators: Cavium, Inc. Device ef01

Set ``sriov_numvfs`` on the PF device, to create a VF:

.. code-block:: console

    echo 1 > /sys/bus/pci/devices/0000:0a:00.0/sriov_numvfs

The devices can be listed on the host console with:

.. code-block:: console

    lspci -nnD | grep ef0[1\|2]

which should output:

.. code-block:: console

    0000:0a:00.0 Processing accelerators [1200]: Cavium, Inc. Device [177d:ef01]
    0000:0a:00.1 Processing accelerators [1200]: Cavium, Inc. Device [177d:ef01]
    0000:0a:00.2 Processing accelerators [1200]: Cavium, Inc. Device [177d:ef02]

Bind octeon_ep_bb_vf VF device to the vfio_pci driver:

.. code-block:: console

    cd <dpdk directory>
    ./usertools/dpdk-devbind.py -u 0000:0a:00.2
    ./usertools/dpdk-devbind.py -b vfio-pci 0000:0a:00.2

Test Application
----------------

BBDEV provides a test application, ``test-bbdev.py`` and range of test data for testing
the functionality of octeon_ep_bb_vf FEC encode and decode, depending on the device
capabilities. The test application is located under app->test-bbdev folder and has the
following options:

.. code-block:: console

  "-p", "--testapp-path": specifies path to the bbdev test app.
  "-e", "--eal-params"	: EAL arguments which are passed to the test app.
  "-t", "--timeout"	: Timeout in seconds (default=300).
  "-c", "--test-cases"	: Defines test cases to run. Run all if not specified.
  "-v", "--test-vector"	: Test vector path (default=dpdk_path+/app/test-bbdev/test_vectors/bbdev_null.data).
  "-n", "--num-ops"	: Number of operations to process on device (default=32).
  "-b", "--burst-size"	: Operations enqueue/dequeue burst size (default=32).
  "-s", "--snr"		: SNR in dB used when generating LLRs for bler tests.
  "-s", "--iter_max"	: Number of iterations for LDPC decoder.
  "-l", "--num-lcores"	: Number of lcores to run (default=16).
  "-i", "--init-device" : Initialise PF device with default values.


To execute the test application tool using simple decode or encode data,
type one of the following:

.. code-block:: console

  cd dpdk/app/test-bbdev
  ./test-bbdev.py -e="-l 0-1 0000:0a:00.2" -c validation -b 32 -v ldpc_dec_default.data
  ./test-bbdev.py -e="-l 0-1 0000:0a:00.2" -c validation -b 32 -v ldpc_enc_default.data

Test Vectors
~~~~~~~~~~~~

In addition to the simple LDPC decoder and LDPC encoder tests, bbdev also provides
a range of additional tests under the test_vectors folder, which may be useful. The results
of these tests will depend on octeon_ep_bb_vf FEC capabilities which may cause some
testcases to be skipped, but no failure should be reported.

.. code-block:: console

  cd dpdk/app/test-bbdev
  ./test-bbdev.py -e="-l 0-1 0000:0a:00.2" -c validation -b 32 -n 128 -v test_vectors/<supported_vector.data>
  cd dpdk
  ./build/app/dpdk-test-bbdev -l 0-1  0000:0a:00.2 -- -l 1 -v app/test-bbdev/test_vectors/<supported_vector.data>
