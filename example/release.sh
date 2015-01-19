#!/bin/sh
# $Id: release.sh,v 1.2 2005/08/28 15:36:00 lha Exp $
#

package=soft-pkcs11
ftp=/afs/su.se/home/l/h/lha/Public/soft-pkcs11
checkversion=YES
name=`basename $0`
root=vr.l.nxs.se:/cvsroot

if [ X"$#" = X0 ]; then
    echo "$name [-tag branch] version"
    exit 1
fi

while true ; do
    case "$1" in
	-tag)
	    shift
	    if [ X"$#" = X0 ] ; then 
		echo "missing tagname"; exit 1; 
	    fi
	    tag_name="$1"
	    ;;
	-h*)
            echo $name [-tag branch] version
	    echo $name -tag tupp-0-35-branch 0.35.3pre1
	    echo $name -tag HEAD 0.36pre1
	    echo $name 0.36
	    exit 1
	    ;;
	-*)
	    echo "$name: unknown option $1"
	    exit 1
	    ;;
	*)
	    break
	    ;;
    esac
    shift
done

if [ X$# != X1 ]; then
    echo "$name: missing version"
    exit 1
fi

version="$1"

if expr "$version" : ${package} > /dev/null ; then
    echo "version number should not contain \"${package}\""
    exit 1
fi


if [ X"${tag_name}" = "X" ]; then
    tag_name=${package}-`echo "${version}" | sed 's,\.,-,g'`
fi

echo preparing "${package}-${version}" from tag ${tag_name}

exportfile=${package}-export-log.$$

echo exporting tree...
cvs -d $root \
	export -d "${package}-${version}" -r "${tag_name}" ${package} > $exportfile
res=$?
if [ X"$res" != X0 ]; then
    echo "cvs export failed, check $exportfile"
    exit 1
fi
rm $exportfile

ac="notfound"
[ -f "${package}-${version}/configure.in" ] && ac="configure.in"
[ -f "${package}-${version}/configure.ac" ] && ac="configure.ac"
if [ "$ac" = notfound ] ; then
    echo "could not find configure, confused"
    exit 1
fi

if [ X"$checkversion" = XYES ]; then
    echo checking version
    chkver=`grep -e '^VERSION=' "${package}-${version}/$ac" | sed 's,[^=]*=,,'`
    if [ "X$chkver" = X ]; then 
	chkver=`grep -e '^AC_INIT(' "${package}-${version}/$ac" | sed 's/[^,]*,[ 	]*//;s/[ 	]*,.*//'`
    fi

    if [ "X${chkver}" != "X${version}" ]; then
        echo "version mismatch ${chkver} != ${version}"
        exit 1
    fi
fi

echo "autofooing"
res=0
done=0
if [ -d "${package}-${version}" ] ; then
	cd "${package}-${version}"
	if [ -f HACKING ]; then
	    sh HACKING
	    res=$?
	    done=1
	fi
	if [ -f regen.sh ]; then
	    sh regen.sh
	    res=$?
	    done=1
	fi
	if [ "X$done" = X0 ] ; then
	    autoreconf -f -i
	fi
	cd ..
fi
if [ X"$res" != X0 ]; then
    echo "autofooing failed"
    exit 1
fi

echo "removing autom4te cache"
amc="${package}-${version}/autom4te*.cache"
if [ -d ${amc} ] ; then
	rm -r ${amc}
fi

if [ -f "${package}-${version}/doc/${package}.texi" ] ; then
	echo "generate info documenation"
	(cd "${package}-${version}/doc" && makeinfo "${package}.texi")
fi

echo "rolling tar-ball"
tar cf - "${package}-${version}" | gzip -9 > "${package}-${version}.tar.gz"
res=$?
if [ X"$res" != X0 ]; then
    echo "creation of tar-ball failed"
    exit 1
fi

if [ -d $HOME/.gnupg ] ; then
	gpg -b -a ${package}-${version}.tar.gz
fi

echo Done!
echo Dont forget to copy the "${package}-${version}.tar.gz" file to the ftp-site.
test X"$ftp" != X && echo "cp ${package}-${version}.tar.gz* $ftp"
exit 0
