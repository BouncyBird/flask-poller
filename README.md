# Flask Poller
A simple flask application where you can create polls, or questions and share them with others to get an answer/opinion. Inspired by websites such as [Poll Maker](https://www.poll-maker.com/) and [Fast-Poll](https://fast-poll.com/)
# Quick Start
- Clone this repo: `git clone https://github.com/BouncyBird/flask-poller.git` or with the GitHub CLI: `gh repo clone BouncyBird/flask-poller`
- Open that folder in a editor(VScode)
- Optionally create a virtual environment
- Install the required packages from the requirements.txt file: `pip install -r requirements.txt`
- Initialize the database with these commands:
  - `flask db init`
  - `flask db migrate`
  - `flask db upgrade`
- Run the app: `python app.py`
