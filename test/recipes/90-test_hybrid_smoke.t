#! /usr/bin/env perl
# Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use OpenSSL::Test::Utils;
use OpenSSL::Test qw/:DEFAULT srctop_dir/;

BEGIN {
    setup("test_hybrid_smoke");
}

plan skip_all => "No TLS/SSL protocols are supported by this OpenSSL build"
    if alldisabled(grep { $_ ne "ssl3" } available_protocols("tls"));

plan tests => 1;

# Cross-algorithm hybrid smoke. PQC operations require oqsprovider; point the
# module loader at the install location unless the environment already supplies
# one. The fixtures live under test/certs/hybrid_e2e/smoke and are produced by
# gen_smoke_certs.sh. The test skips its cases gracefully if oqsprovider cannot
# be loaded.
$ENV{OPENSSL_MODULES} //= "/usr/local/lib/ossl-modules";

ok(run(test(["hybrid_smoke_test",
             srctop_dir("test", "certs", "hybrid_e2e", "smoke")])),
   "running hybrid_smoke_test");
