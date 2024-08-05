#!/bin/bash

tmpfile=`mktemp backtrace.XXX`

PROGRAM_PATH=''
TRACE_TYPE=glibc

print_help()
{
    echo "Usage: "
    echo "   " `basename $0`" [-s] [-p <path/to/filename>] -t <\"full trace\">"
    echo "Options: "
    echo "    -t   '<trace>'  - The entire trace should be put into quotes"
    echo "                      for this option"
    echo "    -p   path/to/filename  - optional path to the binary, typically"
    echo "                            autodetected"
    echo
    exit 1
}

if [ -z "$1" -o "$1" = "-h" -o "$1" = "--help" ]; then
    rm -f $tmpfile
    print_help
fi

while getopts "hf:t:p:" opt; do
    case $opt in
    h)
        print_help
        ;;
    f)
        PROGRAM_PATH="$OPTARG"
        ;;
    t)
        TRACE="$OPTARG"
        ;;
    p)
        PROGRAM_PATH="$OPTARG"
        ;;
    *)
        print_help
        ;;
        esac
done


# use addr2line
parse_glibc_trace()
{
    local trace="$1"
    local filename="$2"
    local tmpname=""
    local symbol=""

    IFS=$'\n'
    for line in ${trace}; do

        #echo "Line: '$line"

        # remove C2 A0 (non breaking space, as inserted by windows)
        line=$(echo $line | sed 's/\xC2\xA0/ /g')

        line=`echo $line | egrep "\[" | egrep "\]"`
        [ -n "$line" ] || continue

        # cut off additional syslog part - beginning of line to ':'
        line=$(echo $line line | sed -e 's/.*://')

        # parse lines like
        # /usr/lib/libfuse3.so.3(+0x1c0ef) [0x7fca6061c0ef]

        filename=$(echo $line | awk '{print $1}' | sed -e 's/(.*$//')
        if [ -z "${filename}" ]; then
            echo "Failed to get filename path for line: \"$line\""
            return
        fi

        if [[ $filename != /* ]]; then
            if [ -n "${PROGRAM_PATH}" ]; then
                filename="${PROGRAM_PATH}"
            else
                tmpname="$(which $filename)"
                if [ $? -ne 0 ]; then
                    echo "Failed to get path for '$filename'"
                    continue
                fi
                filename="${tmpname}"
            fi
        fi

        # for plain glibc backtrace_symbols the symbol is also in column1,
        # within the brackets ()
        symbol=$(echo $line | awk '{print $1}' | sed -e 's/^.*(//' | sed -e 's/).*//')
        if [ -z "${symbol}" ]; then
            echo "Failed to get symbol for line: \"$line\""
            continue
        fi

        addr2line -a -p -s -C -f -i -e ${filename} ${symbol}
    done
}

if [ -z "$TRACE" ]; then
    echo "Missing backtrace option!"
    echo
    print_help
fi


# For now only glibc backtrace_symbols traces are supported
if [ $TRACE_TYPE = "glibc" ]; then
    parse_glibc_trace "$TRACE" "${PROGRAM_PATH}"
else
    echo "Unknown tracetype: '${TRACE_TYPE}'"
fi

rm -f $tmpfile
