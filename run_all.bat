@echo off
REM Retrains everything and starts the dashboard
python -m venv venv
call venv\Scripts\activate
pip install -r requirements.txt
python 1_prepare_data.py
python 2_train_models.py
python 3_test_examples.py
python 4_make_report.py
python app.py
