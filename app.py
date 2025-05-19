# Import the Flask class from the flask module
from flask import Flask

# Create an instance of the Flask class. 
# __name__ is a special Python variable that gets the name of the current module.
# Flask uses this to know where to look for resources like templates and static files.
app = Flask(__name__)

# Define a route for the root URL ('/').
# The @app.route('/') decorator tells Flask what URL should trigger our function.
@app.route('/')
def hello_world():
    """
    This function will be executed when a user accesses the root URL.
    It returns a simple string that will be displayed in the browser.
    """
    return 'Hello, World!'

# This block ensures that the Flask development server runs only when the script is executed directly
# (not when it's imported as a module into another script).
if __name__ == '__main__':
    # app.run() starts the Flask development server.
    # debug=True enables debugging mode, which provides helpful error messages
    # and automatically reloads the server when code changes are made.
    # For production, debug should be set to False.
    app.run(debug=True)
