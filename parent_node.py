import socket
import json

CHILD_IP = "127.0.0.1"   # change later if using 2 laptops
PORT = 9999

def main():
    target = input("Enter IP: ")
    start = int(input("Start port: "))
    end = int(input("End port: "))

    command = {
        "target": target,
        "start": start,
        "end": end
    }

    s = socket.socket()
    s.connect((CHILD_IP, PORT))

    s.sendall(json.dumps(command).encode())

    data = s.recv(65536)
    results = json.loads(data.decode())

    print("\nRESULTS:")
    for r in results:
        print(r)

    s.close()

if __name__ == "__main__":
    main()