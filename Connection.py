from scapy.all import IP, TCP

class Connection:
    def __init__(self, source_ip, source_port, destination_ip, destination_port):
        self.source_ip = source_ip
        self.source_port = source_port
        self.destination_ip = destination_ip
        self.destination_port = destination_port

    @classmethod
    def from_packet(cls, packet):
        source_ip = "unknown"
        destination_ip = "unknown"
        source_port = 0
        destination_port = 0

        if IP in packet:
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst

            if TCP in packet:
                source_port = packet[TCP].sport
                destination_port = packet[TCP].dport

        return cls(source_ip, source_port, destination_ip, destination_port)

    def __eq__(self, other):
        if not isinstance(other, Connection):
            return False

        return (
            (self.source_ip == other.source_ip)
            and (self.source_port == other.source_port)
            and (self.destination_ip == other.destination_ip)
            and (self.destination_port == other.destination_port)
        ) or (
            (self.source_ip == other.destination_ip)
            and (self.source_port == other.destination_port)
            and (self.destination_ip == other.source_ip)
            and (self.destination_port == other.source_port)
        )

    def __hash__(self):
        return hash(
            (hash(self.source_ip) ^ hash(self.source_port))
            ^ (hash(self.destination_ip) ^ hash(self.destination_port))
        )

    def get_filename(self, path):
        return f"{path}{self.source_ip}.{self.source_port}-{self.destination_ip}.{self.destination_port}.data"

    def __str__(self):
        return f"{self.source_ip}:{self.source_port} -> {self.destination_ip}:{self.destination_port}"
