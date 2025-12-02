# satnet-simulator
basic simulator for my FYP, with endpoints able to send packets to each other and a network introducing delay per packet. there are many cases to examine:
- packets are forwarded on the lowest-delay path
- packets are deliberately delayed
- packets are randomly assigned to one across N paths (each with a different delay)
- etc.
## current implementation
`count` packets are sent, each with their own uniformly random delay (0.5s-2.0s). ground station A sends forwards packet to router. router finds the best path by choosing smallest delay path. the packet then traverses that path, and reaches destination. network adds fixed delay to random packets, random packet chose less than `spike_prob`.
## venv
to activate the venv
```
source venv/bin/activate
```
to deactivate, run `deactivate`
## requirements
run the command below when new imports are used
```
pip freeze > requirements.txt
```
to instsall, run 
```
pip install -r requirements.txt
```
