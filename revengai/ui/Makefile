all: auto_analysis.py function_simularity.py

auto_analysis.py: %.py: %.ui
	pyuic5 auto_analysis_panel.ui -o auto_analysis_panel.py

function_simularity.py: %.py: %.ui
	pyuic5 function_simularity_panel.ui -o function_simularity_panel.py

clean:
	rm auto_analysis_panel.py function_simularity_panel.py
