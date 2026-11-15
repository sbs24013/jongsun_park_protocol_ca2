
# Project automation commands
.PHONY: install run attack test clean

# Install required libraries
install:
	pip install -r requirements.txt

# Run normal and flawed protocols
run:
	python -m src.protocol
	python -m src.flawed

# Execute Nonce Reuse attack
attack:
	python -m attack.attack

# Execute Nonce Reuse attack with production mode (corrected protocol)
attack-correct:
	python -m attack.attack --mode correct
	
# Run all security tests
test:
	python -m pytest tests/ -v

# Remove temporary files
clean:
	rm -rf __pycache__
	rm -rf src/__pycache__
	rm -rf attack/__pycache__
	rm -rf tests/__pycache__
	rm -rf .pytest_cache
