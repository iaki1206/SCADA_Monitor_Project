To run the application, users just need to double-click the SCADA_Monitor.exe file. Everything (Flask server, event simulation, web interface) will start automatically.

SCADA_Monitor\dist\SCADA_Monitor.exe

Note: Make sure to test the executable before distributing it. Some antivirus software might flag newly created executables, so you might need to add an exception.




After running the executable or the Python script, the web interface will automatically open in your default web browser at http://localhost:5000 . However, if it doesn't open automatically, you can manually open your web browser and navigate to:


http://localhost:5000


You should see:

1. A statistics panel showing Total Events, High Severity events, and Unique Sources
2. A real-time Event Timeline graph
3. A Live Events table showing the most recent security events
The interface will update automatically as new events are generated. High severity events will be highlighted in red in the Live Events table.

If you're not seeing the web interface, make sure:

1. The application is running (you should see console output indicating the server started)
2. There are no other applications using port 5000
3. Your firewall isn't blocking the connection
