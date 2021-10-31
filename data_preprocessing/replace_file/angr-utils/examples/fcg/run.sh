gnome-terminal -t "plot1" -x bash -c "source virtualenvwrapper.sh;workon angr;py fcfg_time.py;exec bash"
gnome-terminal -t "plot2" -x bash -c "source virtualenvwrapper.sh;workon angr;py fcfg_time0.py;exec bash"
gnome-terminal -t "plot3" -x bash -c "source virtualenvwrapper.sh;workon angr;py fcfg_time1.py;exec bash"
