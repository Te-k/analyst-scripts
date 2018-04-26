#! /bin/bash
if [ $# -eq 0 ]
then
    echo "No file given"
    exit 0
fi

if [ ! -f $1 ]
then
    echo "Bad file"
    exit 1
fi

file=$1
name=${file%.*}

cat << __EOF | gnuplot
set xdata time
set key box
set xlabel 'Time'
set ylabel 'Response Time' font 'Arial,12'
set autoscale
set timefmt "%Y-%m-%d %H:%M:%S"
set term png
set offsets 0, 0, 1, 0
set output 'plot1.png'
plot '$file' using 1:4 title '$name'  with linespoints
__EOF

