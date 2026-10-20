# SentinelShield — convenience targets (works with GNU make on Windows/macOS/Linux)
#
# No make installed? The same steps are plain commands:
#   pip install -r requirements.txt
#   python app.py
#   python simulator.py
#   python report.py

PY ?= python

.PHONY: install run sim report demo stop clean

install:
	$(PY) -m pip install -r requirements.txt

run:
	$(PY) app.py

sim:
	$(PY) simulator.py

report:
	$(PY) report.py

demo: clean
	$(PY) app.py & \
	sleep 5 && \
	$(PY) simulator.py && \
	$(PY) report.py && \
	echo "[+] demo complete — open http://127.0.0.1:5000/"

stop:
	@$(PY) -c "import pathlib,os,signal; p=pathlib.Path('app.pid'); pid=int(p.read_text().strip()) if p.exists() else None; os.kill(pid, signal.SIGTERM) if pid else print('no app.pid — server not running'); p.unlink(missing_ok=True)"

clean:
	@$(PY) -c "import pathlib,shutil; [pathlib.Path(f).unlink(missing_ok=True) for f in ('logs.db','simulator_run.json','report.md','report.pdf','app_out.log','app_err.log','app.pid')]; [shutil.rmtree(d, ignore_errors=True) for d in ('__pycache__','waf/__pycache__')]; print('cleaned')"
