import random
import simpy


class Packet:
    def __init__(self, id, src, creation_time):
        self.id = id
        self.src = src
        self.creation_time = creation_time


class SatellitePath(object):
    def __init__(self, env, name, delay, spike_prob, spike_delay):
        self.env = env
        self.name = name
        self.delay = delay
        self.spike_prob = spike_prob
        self.spike_delay = spike_delay

    def traverse(self, pkt, dest):
        yield self.env.timeout(self.delay)
        jitter = random.uniform(0.5, 2.0)
        yield self.env.timeout(jitter)
        if random.random() < self.spike_prob:
            print(
                f" DELAY EVENT: Packet {pkt.id} delayed by {self.spike_delay}s on {self.name}"
            )
            yield self.env.timeout(self.spike_delay)
        dest.receive(pkt, self.name)


class SatNetRouter(object):
    def __init__(self, env, paths):
        self.env = env
        self.paths = paths

    def forward(self, pkt, dest):
        best_path = min(self.paths, key=lambda x: x.delay)
        print(
            f"[SatNet Internal] Routing pkt {pkt.id} via {best_path.name} (Delay: {best_path.delay}s)"
        )
        self.env.process(best_path.traverse(pkt, dest))


class GroundStation(object):
    def __init__(self, env, name, router=None):
        self.env = env
        self.name = name
        self.router = router

    def send(self, dest, count):
        for i in range(count):
            pkt = Packet(i, self.name, self.env.now)
            print(f"[{self.env.now:5.2f}s] {self.name} SENT pkt {pkt.id}")
            self.router.forward(pkt, dest)
            yield self.env.timeout(1.0)

    def receive(self, pkt, path_used):
        latency = self.env.now - pkt.creation_time
        print(
            f"[{self.env.now:5.2f}s] {self.name} RECEIVED pkt {pkt.id} (via {path_used}, latency: {latency:.2f}s)"
        )


env = simpy.Environment()
fast_path = SatellitePath(env, "path_leo_fast", 0.1, spike_prob=0.3, spike_delay=2.0)
slow_path = SatellitePath(env, "path_geo_slow", 0.8, spike_prob=0.0, spike_delay=0.0)
satnet = SatNetRouter(env, paths=[fast_path, slow_path])
sender = GroundStation(env, "client", satnet)
receiver = GroundStation(env, "server")
env.process(sender.send(dest=receiver, count=10))
env.run(until=20)
