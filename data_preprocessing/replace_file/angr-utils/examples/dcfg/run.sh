gnome-terminal -t "plot1" -x bash -c "source virtualenvwrapper.sh;workon angr;py dcfg_samples_plot.py;exec bash"
gnome-terminal -t "plot2" -x bash -c "source virtualenvwrapper.sh;workon angr;py dcfg_samples_plot0.py;exec bash"
gnome-terminal -t "plot3" -x bash -c "source virtualenvwrapper.sh;workon angr;py dcfg_samples_plot1.py;exec bash"
