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
	"""({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ) ({host}[\w.\-]{1,2000}) CheckPoint""",
	"""product:"({product_name}[^"]{1,2000})"""",
	"""received_bytes:"({bytes_in}[^"]{1,2000})"""",
	"""sent_bytes:"({bytes_out}[^"]{1,2000})"""",
	"""origin:"({origin_ip}[^"]{1,2000})"""",
	"""originsicname:"({origin_sic_name}[^"]{1,2000})"""",
	"""loguid:"({log_uid}[^"]{1,2000})"""",
	"""ifdir:"({direction}[^"]{1,2000})""",
	"""policy_name=({policy}.+?)[\\\]]""",
	"""proto:"({protocol}[^"]{1,2000})"""",
	"""src:"({src_ip}[^"]{1,2000})"""",
	"""s_port:"({src_port}[^"]{1,2000})"""",
	"""message_info:"({additional_info}[^"]{1,2000})"""",
	"""dst:"({dest_ip}[^"]{1,2000})"""",
	"""ifname:"({src_interface}[^"]{1,2000})"""
  ]


}
```