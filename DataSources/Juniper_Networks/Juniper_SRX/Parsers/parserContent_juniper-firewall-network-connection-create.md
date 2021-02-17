#### Parser Content
```Java
{
Name = juniper-firewall-network-connection-create
    Vendor = Juniper Networks
    Product = Juniper SRX
    Lms = Splunk
    DataType = "network-connection"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ """RT_FLOW - RT_FLOW_SESSION_CREATE""", """encrypted=""" ]
    Fields = [
	"""encrypted="({additional_info}[^"]*)""",
	"""destination-address="({dest_ip}[^"]*)""",
	"""destination-port="({dest_port}[^"]*)""",
	"""\s({event_name}RT_FLOW - [^\s]*)\s\[""",
	"""\s({host}[^\s]*)\sRT_FLOW""",
	"""packet-incoming-interface="({src_interface}[^"]*)""",
	"""source-address="({src_ip}[^"]*)""",
	"""source-port="({src_port}[^"]*)""",
	"""({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)(?:z|Z)?""",
	"""username="(?!N\/A)({user}[^"]+)"""",
	"""protocol-id="({protocol}[^"]*)""",
	"""destination-zone-name="({dest_network_zone}[^"]*)""",
	"""reason="({miscellaneous}[^"]*)""",
	"""\sapplication="({network_app}[^"]*)""",
	"""policy-name="({policy}[^"]*)""",
	"""source-zone-name="({src_network_zone}[^"]*)""",
	"""nested-application="({subtype}[^"]*)""",
	"""service-name="({service}[^"]*)"""
    ]
}
```