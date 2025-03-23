---
title: 'Apache Camel failover load balancer with dynamic endpoints'
description: 'This blog post showcases how to create an Apache Camel route, which load balances a dynamic number of endpoints with failover in Round Robin mode.'
pubDate: 'Jan 18 2025'
---

## Table of Contents

## Introduction

This post showcases how to create an [Apache Camel](https://camel.apache.org) route, which [load balances](https://en.wikipedia.org/wiki/Load_balancing_(computing)) a dynamic number of endpoints. The load balancer will use the [Round Robin algorithm](https://en.wikipedia.org/wiki/Round-robin_scheduling), and it will be paired with [failover](https://en.wikipedia.org/wiki/Failover) in order to achieve high availability.


## Failover

As stated already, the endpoints need to be dynamic, i.e. configurable. The [Apache Camel Failover](https://camel.apache.org/components/4.4.x/eips/failover-eip.html) documentation thoroughly explains how to create a failover load balancer, but with static endpoints that are defined directly inside the code.

In order to have dynamic endpoints, the route definition that is demonstrated in the documentation needs to be modified a bit.

***Note:** The following is a small demonstration. In the next section a complete example is shown.*

**Original:**

```java
from("direct:start")
	.loadBalance().failover(10, false, true)
		.to("http:service1")
		.to("http:service2")
		.to("http:service3")
	.end();
```

**Modified:**

```java
LoadBalanceDefinition route = from("direct:start")
	.loadBalance()
	// Failover at most 10 times in round-robin mode
	.failover(10, false, true);

// The endpoints should ideally be configured in the `application.properties` or `application.yaml`
// String[] endpoints = { "http:service1", "http:service2", "http:service3" };
for (String endpoint : endpoints) {
	route = route.to(endpoint.trim() + "?bridgeEndpoint=true");
}

route.end();
```

## Code

### application.properties

```txt
example.endpoints="http://example-one.com/foo","http://example-two.com/bar"
```

### Class

```java
@Component
public class ExampleRoute extends RouteBuilder {

	@Value("${example.endpoints}")
	private String[] exampleEndpoints;

	@Override
	public void configure() {
		final String exampleRouteId = "example-route";
		final String exampleRoute = "direct:" + exampleRouteId;

		rest("/example")
			.get()
			.to(exampleRoute);

		LoadBalanceDefinition route = from(exampleRoute)
			.routeId(exampleRouteId)
			.loadBalance()
			// Continuously try to failover in round-robin mode
			.failover(-1, false, true);

		for (String endpoint : exampleEndpoints) {
			route = route.to(endpoint.trim() + "?bridgeEndpoint=true");
		}

		route.end();
	}
}
```

## Conclusion

Turns out this was fairly easy, but I wish I had this kind of resource when working with Apache Camel. Wasted more time than I'd like to admit. One skill issue at a time...
