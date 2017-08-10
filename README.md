# KryptChat
A secure, multi-party, on-line chat application. 

KryptChat is a multi-party chat application built with the Tornado framework. Besides the 256 Bit AES encryption used to transport messages, it implements ephemeral Diffy Hellman and replay detection to ensure complete security. Messages are signed and authenticated via RSA(PKCS1 PSS).

# Usage

Before starting the chat client, you should edit the config.py configuration file and set the IP address of the server. If you are running the server on the same computer where your client will be running, then set the loacalhost address '127.0.0.1' as the server IP. Otherwise, if your server is running on another machine on the local network, then set the IP address of that machine as the server IP in the config.py file.

Once configuration is done, the chat client can be started by passing main.py to the Python interpreter:
python main.py <json file containing user credentials>

The program takes 1 argument: a JSON file, which contains user credentials. These credentials are then used by the program during the login process. 3 example JSON files have been provided: user_bill.json, user_elon.json and user_steve.json. The user credentials provided in these files are not mandatory, but the server already recognizes them as legitimate users. You are free to create Your own users in separate JSON files as long as the contents of that file follow the same format as the supplied JSON files:
{
    "user_name" : "<Enter user name here>",
    "password"  : "<Enter password here>"
}
The user credentials are required to ease testing: it enables You to run multiple instances of the client on the same machine with different user credentials.

When started, the chat client automatically tries to log in. Any subsequent action such as creating a conversation or sending chat messages require a prior successful login, otherwise an error message is printed. The program notifies You of the outcome of the login attempt.

After login, You need to enter the menu to either create a conversation or to join an existing one. Depending on Your operating system, different keyboard shortcuts can be used. For Mac OS and Linux, that shortcut is CTRL+z, for Windows, it is CTRL+BREAK (if you don't have a Break key, then it is CTRL+Fn+B). At start up, the program attempts to register a handler function for the shortcuts. If registration fails for all the shortcuts, You are notified and the program exits.

Every time You enter the menu, the conversations in which the current user is a participant are printed to the console. The conversations are given an ID by the server, that is how You can refer to them as well. After the list of current conversations, You are given two choices: to create a new conversation or to enter an existing conversation or to quit the program. You always need to retrurn to this main menu (with CTRL-Break or CTRL-z) to make another choice. For example, if You have created a conversation through the menu, You have to return to the menu and select "Enter an existing conversation" in order to join that conversation.

When creating a new conversation, the program queries the server for users whom You can invite into the conversation. To specify the list of participants, You must enter their user names separated with ';' characters. If only 1 user is invited, the separator should be omitted. Example: if, as Bill, You want to invite both Elon and Steve, enter:
Elon;Steve
However, if You want to chat with Elon only, enter:
Elon
If an unknown user name is entered, the program will print a notification and will not create the conversation.

When entering an existing conversation, You will be prompted to specify which conversation You wish to enter. To specify the conversation, You must enter its ID on the console. The ID of all the conversations in which Your current user participates in printed when you enter the menu. After entering, the program starts printing the previous messages and paralelly waits for Your input to send. Because these two things happen paralelly, there can be situations when arriving messages seem to interrupt your typing. That interruption, however, appears only on the console and does not affect the text You are currently typing.

