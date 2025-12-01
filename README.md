# satnet-simulator
simulator for my FYP
## plan
basic simulator, with endpoints able to send packets to each other and a network introducing delay per packet (or per flow). 
- packets are actually forwarded on the lowest-delay path
- packets are deliberately delayed
- packets are randomly assigned to one across N paths (each with a different delay)
- etc.
