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
- DDoS / Dos Proofing
- DDoS threshold via | Sliding Window | & | dynamic |
- Dos threshold | manual | & | static |
- Redis Cache
- HMAC
<hr>

*3* 
