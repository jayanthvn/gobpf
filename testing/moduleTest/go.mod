module github.com/jayanthvn/gobpf/testing/map-pin-info

go 1.16

require (
	github.com/aquasecurity/libbpfgo v0.2.4-libbpf-0.6.1
	github.com/benesch/cgosymbolizer v0.0.0-20190515212042-bec6fe6e597b // indirect
	github.com/ianlancetaylor/cgosymbolizer v0.0.0-20220405231054-a1ae3e4bba26 // indirect
	github.com/jayanthvn/gobpf v0.0.9
	golang.org/x/sys v0.0.0-20220624220833-87e55d714810 // indirect
)

replace github.com/jayanthvn/gobpf => ../../
