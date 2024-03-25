all: auto_analysis.py rename_symbols.py

auto_analysis.py: %.py: %.ui
	pyuic5 auto_analysis_panel.ui -o auto_analysis_panel.py

rename_symbols.py: %.py: %.ui
	pyuic5 rename_symbols_panel.ui -o rename_symbols_panel.py

clean:
	rm auto_analysis_panel.py rename_symbols_panel.py
