import random
import simpy


class SatelliteLink(object):
    def __init__(self, env):
        self.env = env

    def transmit(self, packet, source, dest):
        delay = random.uniform(0.5, 2.0)
        yield self.env.timeout(delay)
        dest.receive(packet, source)


class GroundStation(object):
    def __init__(self, env, name, link):
        self.env = env
        self.name = name
        self.link = link

    def send_packets(self, dest, interval):
        pkt_id = 0
        while True:
            yield self.env.timeout(random.expovariate(1.0 / interval))
            pkt_id += 1
            packet = f"Pkt-{pkt_id}"
            print(f"[{self.env.now:5.2f}s] {self.name} SENT {packet} -> {dest.name}")
            self.env.process(self.link.transmit(packet, self, dest))

    def receive(self, packet, source):
        print(
            f"[{self.env.now:5.2f}s] {self.name} RECEIVED {packet} (from {source.name})"
        )


env = simpy.Environment()
link = SatelliteLink(env)
gsA = GroundStation(env, "GS_A", link)
gsB = GroundStation(env, "GS_B", link)
env.process(gsA.send_packets(dest=gsB, interval=2.0))
env.process(gsB.send_packets(dest=gsA, interval=3.0))
env.run(until=15)
