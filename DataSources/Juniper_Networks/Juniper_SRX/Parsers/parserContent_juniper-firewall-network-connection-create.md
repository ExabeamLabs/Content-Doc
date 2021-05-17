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
	"""encrypted="({additional_info}[^"]{0,2000})""",
	"""destination-address="({dest_ip}[^"]{0,2000})""",
	"""destination-port="({dest_port}[^"]{0,2000})""",
	"""\s({event_name}RT_FLOW - [^\s]{0,2000})\s\[""",
	"""\s({host}[^\s]{0,2000})\sRT_FLOW""",
	"""packet-incoming-interface="({src_interface}[^"]{0,2000})""",
	"""source-address="({src_ip}[^"]{0,2000})""",
	"""source-port="({src_port}[^"]{0,2000})""",
	"""({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)(?:z|Z)?""",
	"""username="(?!N\/A)({user}[^"]{1,2000})"""",
	"""protocol-id="({protocol}[^"]{0,2000})""",
	"""destination-zone-name="({dest_network_zone}[^"]{0,2000})""",
	"""reason="({miscellaneous}[^"]{0,2000})""",
	"""\sapplication="({network_app}[^"]{0,2000})""",
	"""policy-name="({policy}[^"]{0,2000})""",
	"""source-zone-name="({src_network_zone}[^"]{0,2000})""",
	"""nested-application="({subtype}[^"]{0,2000})""",
	"""service-name="({service}[^"]{0,2000})"""
    ]
}
```