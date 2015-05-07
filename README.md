===============================================================================
M1522.000800 System Programmig                                      Spring 2015
===============================================================================
                               Malloc Lab
===============================================================================

based on the CS:APP Malloc Lab (c) by R.Bryant and D.O'Hallaron.


Directions to Students
----------------------

In this lab you write a dynamic storage allocator for C programs.

The goal is to implement an allocator that is correct, efficient, and fast.


0. Files:
---------

mm.{c,h}          Your solution malloc package. mm.c is the file that you
                  will be handing in, and is the only file you should modify.
mdriver.c         The malloc driver that tests your mm.c file.
*-bal.rep         Tracefiles to test your implementation.
Makefile          Builds the driver

Other support files for the driver:

config.h          Configures the malloc lab driver
fsecs.{c,h}       Wrapper function for the different timer packages
clock.{c,h}       Routines for accessing the Pentium and Alpha cycle counters
fcyc.{c,h}        Timer functions based on cycle counters
ftimer.{c,h}      Timer functions based on interval timers and gettimeofday()
memlib.{c,h}      Models the heap and sbrk function


1. Building and running the driver
----------------------------------

To build the driver, type "make" to the shell.

To run the driver on a tiny test trace:

  unix> mdriver -V -f short1-bal.rep

The -V option prints out helpful tracing and summary information.

To get a list of the driver flags:

  unix> mdriver -h
