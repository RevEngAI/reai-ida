all: auto_analysis.py function_similarity.py auto_sync.py

auto_analysis.py: %.py: %.ui
	pyuic5 auto_analysis_panel.ui -o auto_analysis_panel.py

function_similarity.py: %.py: %.ui
	pyuic5 function_similarity_panel.ui -o function_similarity_panel.py

auto_sync.py: %.py: %.ui
	pyuic5 auto_sync_panel.ui -o auto_sync_panel.py

clean:
	rm auto_analysis_panel.py function_similarity_panel.py auto_sync_panel.py
