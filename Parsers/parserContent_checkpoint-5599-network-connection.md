#### Parser Content
```Java
{
Name = checkpoint-5599-network-connection
  Vendor = Check Point Software
  Product = Check Point NGFW
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """; product:"""",  """ CheckPoint 5599 """ ]
  Fields = [
	"""({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ) ({host}[\w.\-]+) CheckPoint""",
	"""product:"({product_name}[^"]+)"""",
	"""received_bytes:"({bytes_in}[^"]+)"""",
	"""sent_bytes:"({bytes_out}[^"]+)"""",
	"""origin:"({origin_ip}[^"]+)"""",
	"""originsicname:"({origin_sic_name}[^"]+)"""",
	"""loguid:"({log_uid}[^"]+)"""",
	"""ifdir:"({direction}[^"]+)""",
	"""policy_name=({policy}.+?)[\\\]]""",
	"""proto:"({protocol}[^"]+)"""",
	"""src:"({src_ip}[^"]+)"""",
	"""s_port:"({src_port}[^"]+)"""",
	"""message_info:"({additional_info}[^"]+)"""",
	"""dst:"({dest_ip}[^"]+)"""",
	"""ifname:"({src_interface}[^"]+)"""
  ]
}
```