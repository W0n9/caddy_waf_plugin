# About this repo

This is a WAF plugin for [Caddy Server](https://github.com/caddyserver/caddy) using [Chaitin SafeLine](https://www.chaitin.cn/zh/safeline) as backend engine.

# How to use

```
(waf) {
	route {
		waf_chaitin {
			snserver_addr 10.2.137.27:8000
			mode monitor //Deprecated
			strategy request //Deprecated
		}
	}
}

:8080 {
	import waf
	respond / "hello world"
}
```

# TODO
- [x] Detection and Interception  
- [ ]  Pass the `remote_addr` to the Engine  
- [ ]  Multi backend engine instances support, include Load Balance and High Availability
