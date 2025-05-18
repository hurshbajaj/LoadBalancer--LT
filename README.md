# Load Balancer >> LT | Less Trash |
Written in Rust, uses < Weighted Round Robin > to evenly distribute requests.
<hr>

**Complete with**

 - Health Checks
 - Fastest Server First
 - Timeouts
	 - Strict
	 - Lenient  
- Weighted Round Robin
- Safe Request Handling with Arc /  Async Mutex
- Custom Reverse Proxy
- Inactive Servers due to Timeout Window revaluation
- Failovers
<hr>

*1.0* 
Next step: Adding metrics  (Many being kept track of already, simply need to be provided a TUI )

Current logs undescriptive & improper, solely meant for debugging.
