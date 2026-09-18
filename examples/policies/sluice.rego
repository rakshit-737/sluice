# Example sink policy for sluice's OPA backend.
#
# sluice sends one input document per tool call:
#   {"tool": "...", "caps": [...], "source": "...",
#    "args": {"<arg>": {"integrity": "...", "confidentiality": "...", "sources": [...]}}}
# and reads data.sluice.decision = {"allow": bool, "verdict"?: str, "reasons": [...]}.
package sluice

import rego.v1

outbound_caps := {"net.out", "comms", "shell"}

outbound if {
	some cap in input.caps
	cap in outbound_caps
}

# Nothing derived from untrusted content may drive a shell.
reasons contains {"arg": arg, "msg": "untrusted data reaches a shell argument"} if {
	"shell" in input.caps
	some arg, a in input.args
	a.integrity == "untrusted"
}

# Secret data never leaves through an outbound tool, whatever the YAML policy says.
reasons contains {"arg": arg, "msg": sprintf("secret data may not leave via %s", [input.tool])} if {
	outbound
	some arg, a in input.args
	a.confidentiality == "secret"
}

# Web content may not choose where outbound data goes.
reasons contains {"arg": arg, "msg": "destination derived from web content"} if {
	outbound
	some arg in {"to", "url", "recipient"}
	"tool.web_fetch" in input.args[arg].sources
}

default decision := {"allow": true, "reasons": []}

decision := {"allow": false, "verdict": "block", "reasons": reasons} if {
	count(reasons) > 0
}
