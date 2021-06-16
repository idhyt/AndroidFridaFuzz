.PHONY:

clean:
	find . -name '__pycache__' | xargs rm -rf
	find . -name '*.pyc' | xargs rm -rf
	find . -name '*.pyo' | xargs rm -rf
	rm -rf ./data/com.*

env:
	pip install -r requirements.txt
	npm install --registry=https://registry.npm.taobao.org frida-compile

build:
	python fuzz.py --compile ./tests/config.json

run:
	python fuzz.py --fuzz ./tests/config.json
