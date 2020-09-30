all:
	pipenv run python make_tables.py
	pipenv run python overview_table.py

	pipenv run python make_tex.py
	pdflatex --output-directory test-dir main.tex
