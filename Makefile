
# Project automation commands
.PHONY: install run attack test clean

# Install required libraries
install:
	pip install -r requirements.txt

# Run normal and flawed protocols
run:
	python src/protocol.py
	python src/flawed.py

# Execute Nonce Reuse attack
attack:
	python attack/attack.py

# Execute Nonce Reuse attack with production mode (corrected protocol)
attack-correct:
  python attack/attack.py --mode correct
	
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
