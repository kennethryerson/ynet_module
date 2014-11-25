#!/usr/bin/python

import time
import re
import sys

if __name__=="__main__":
    if len(sys.argv) != 2:
        print("usage: update_version.py VERSION")
    
    name = "Kenneth Ryerson"
    email = "kryerson@vermeer.com"
    
    version = sys.argv[1]
    
    datetime = time.strftime("%a, %d %b %Y %X")
    timezone = time.strftime("-%H%M",time.gmtime(time.timezone))
    
    #update dkms/dkms.conf
    dkms_conf_file = open("dkms/dkms.conf","r")
    dkms_conf_lines = dkms_conf_file.readlines()
    dkms_conf_file.close()
    
    dkms_conf_file = open("dkms/dkms.conf","w")
    for line in dkms_conf_lines:
        dkms_conf_file.write(re.sub("PACKAGE_VERSION=[0-9\.]+","PACKAGE_VERSION={0}".format(version),line))
    dkms_conf_file.close()
    
    print("Version info written to dkms/dkms.conf")
    
    #update dkms/ynet.c
    ynet_c_file = open("dkms/ynet.c","r")
    ynet_c_lines = ynet_c_file.readlines()
    ynet_c_file.close()
    
    ynet_c_file = open("dkms/ynet.c","w")
    for line in ynet_c_lines:
        ynet_c_file.write(re.sub("#define YNET_VERSION\t\"[0-9\.]+\"","#define YNET_VERSION\t\"{0}\"".format(version),line))
    ynet_c_file.close()
    
    print("Version info written to dkms/ynet.c")
    
    #update dkms/ynet.h
    ynet_h_file = open("dkms/ynet.h","r")
    ynet_h_lines = ynet_h_file.readlines()
    ynet_h_file.close()
    
    ynet_h_file = open("dkms/ynet.h","w")
    for line in ynet_h_lines:
        ynet_h_file.write(re.sub("Version:\t@(#)ynet.h\t[0-9\.]+","Version:\t@(#)ynet.h\t{0}".format(version),line))
    ynet_h_file.close()
    
    print("Version info written to dkms/ynet.h")
    
    #update debian/postinst
    postinst_file = open("debian/postinst","r")
    postinst_lines = postinst_file.readlines()
    postinst_file.close()
    
    postinst_file = open("debian/postinst","w")
    for line in postinst_lines:
        postinst_file.write(re.sub("MODVER=[0-9\.]+","MODVER={0}".format(version),line))
    postinst_file.close()
    
    print("Version info written to debian/postinst")
    
    #update debian/prerm
    prerm_file = open("debian/prerm","r")
    prerm_lines = prerm_file.readlines()
    prerm_file.close()
    
    prerm_file = open("debian/prerm","w")
    for line in prerm_lines:
        prerm_file.write(re.sub("MODVER=[0-9\.]+","MODVER={0}".format(version),line))
    prerm_file.close()
    
    print("Version info written to debian/prerm")
    
    #update debian/changelog
    debian_version_file = open("debian/changelog","r")
    debian_version_lines = debian_version_file.readlines()
    debian_version_file.close()
    
    debian_version_file = open("debian/changelog","w")
    debian_version_file.write("ynet ({0}) UNRELEASED; urgency=medium\n".format(version))
    debian_version_file.write("\n")
    debian_version_file.write("  * <Enter change here>\n")
    debian_version_file.write("\n")
    debian_version_file.write(" -- {0} <{1}>  {2} {3}\n".format(name,email,datetime,timezone))
    debian_version_file.write("\n")
    
    debian_version_file.writelines(debian_version_lines)
    debian_version_file.close()
    
    print("Version info written to debian/changelog")

    #update Makefile
    makefile_file = open("Makefile","r")
    makefile_lines = makefile_file.readlines()
    makefile_file.close()
    
    makefile_file = open("Makefile","w")
    for line in makefile_lines:
        makefile_file.write(re.sub("MODVER = [0-9\.]+","MODVER = {0}".format(version),line))
    makefile_file.close()
    
    print("Version info written to Makefile")
    
