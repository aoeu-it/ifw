setup-dev: 
		pip install --user virtualenv 
		virtualenv .
		#source bin/activate
		#pip install -r requirements-dev.txt

setup:
		pip install --user virtualenv 
		virtualenv .
		#source bin/activate
		#pip install -r requirements.txt

lint:
		pylint source/infra.py
		pylint source/to_iptables.py
		flake8 source/infra.py
		flake8 source/to_iptables.py

unittest:
		cd source; python tests.py
