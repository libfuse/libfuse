From 060fbdd03d03b0b9835b861a72f9aeb25347277d Mon Sep 17 00:00:00 2001
From: Martin Liska <mliska@suse.cz>
Date: Tue, 25 Jan 2022 14:29:05 +0100
Subject: [PATCH] Add new option --ignore-unused-rpmlintrc.

The option skips reporting of unused-rpmlintrc-filter errors.

Fixes: #794.
---
 rpmlint/cli.py    | 2 ++
 rpmlint/lint.py   | 3 ++-
 test/test_lint.py | 3 ++-
 3 files changed, 6 insertions(+), 2 deletions(-)

diff --git a/rpmlint/cli.py b/rpmlint/cli.py
index 81d5b92b..8a7bc09e 100644
--- a/rpmlint/cli.py
+++ b/rpmlint/cli.py
@@ -82,6 +82,8 @@ def process_lint_args(argv):
     parser.add_argument('-i', '--installed', nargs='+', default='', help='installed packages to be validated by rpmlint')
     parser.add_argument('-t', '--time-report', action='store_true', help='print time report for run checks')
     parser.add_argument('-T', '--profile', action='store_true', help='print cProfile report')
+    parser.add_argument('--ignore-unused-rpmlintrc', action='store_true',
+                        help='Do not report "unused-rpmlintrc-filter" errors')
     lint_modes_parser = parser.add_mutually_exclusive_group()
     lint_modes_parser.add_argument('-s', '--strict', action='store_true', help='treat all messages as errors')
     lint_modes_parser.add_argument('-P', '--permissive', action='store_true', help='treat individual errors as non-fatal')
diff --git a/rpmlint/lint.py b/rpmlint/lint.py
index a98d2c04..1d5e0050 100644
--- a/rpmlint/lint.py
+++ b/rpmlint/lint.py
@@ -277,7 +277,8 @@
 
         # validate used filters in rpmlintrc
         if is_last:
-            self.output.validate_filters(pkg)
+            if not self.options['ignore_unused_rpmlintrc']:
+                self.output.validate_filters(pkg)
 
         if spec_checks:
             self.specfiles_checked += 1
