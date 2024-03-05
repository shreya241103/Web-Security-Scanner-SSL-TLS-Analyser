import socket

# Set up the client socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('192.168.64.7', 8009))

# Send strings to the server and receive the capitalized strings back
while True:
    # Get a string input from the user
    message = input("Enter URL for Web Scanning-> ")

    # Send the string to the server
    client_socket.send(message.encode())
    print("\n-----REQUEST SENT TO SERVER-----\n")

    
    data = client_socket.recv(1024).decode()

    print(data)
    message = input("Enter URL for Web Scanning-> ")
