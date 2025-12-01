import random
import simpy


def packet_generator(env, node, interval, dest):
    while True:
        yield env.timeout(random.expovariate(1.0 / interval))
        packet = f"Packet at {env.now}"
        print(f"{node} sent {packet} to {dest}")
        env.process(packet_handler(env, dest, packet))


def packet_handler(env, node, packet):
    delay = random.uniform(0.5, 2.0)
    yield env.timeout(delay)
    print(f"{node} received {packet} at {env.now}")


env = simpy.Environment()
env.process(packet_generator(env, "Node A", 2, "Node B"))
env.process(packet_generator(env, "Node C", 5, "Node D"))
env.run(until=20)
