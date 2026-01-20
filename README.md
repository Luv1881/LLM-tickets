This folder contains a dataset of security tickets and the tools used to manage, validate, and fix them. Everything here is designed to help an AI (the **LLM Ticket **) learn how to handle security alerts.

## Files and What They Do

### 1. `security_tickets.jsonl`
**The Dataset**  
This is the main file. It contains 500 examples of security alerts (like leaked passwords or API keys). Each line is one "ticket" that includes:
- Details about the leak (where it happened, how serious it is).
- A **Label** (e.g., "Confirmed", "False Positive").
- An **Ideal Comment** (the perfect explanation a security expert would write).

### 2. `generate_tickets.py`
**The Creator**  
A script used to generate "synthetic" (fake but realistic) security tickets. It creates various scenarios so we have plenty of data to test the AI.

### 3. `validate_tickets.py`
**The Checker**  
This script acts like a teacher. It reads all the tickets in `security_tickets.jsonl` and checks if the labels match our official **Decision Logic** (the rules for how to triage a ticket). It tells us the accuracy percentage and highlights any mistakes.

### 4. `fix_tickets.py`
**The Repairman**  
If the checker finds mistakes, this script fixes them! It goes through the dataset, applies the correct logic to every ticket, and updates the labels and comments so they are 100% accurate.

### 5. `validation_mismatches.json`
**The Error Report**  
When you run the checker (`validate_tickets.py`), it saves a list of every single mistake it found into this file. It’s useful for seeing exactly what went wrong before running the fix.

