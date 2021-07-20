#### Parser Content
```Java
{
Name = cisco-dhcp
  Vendor = Cisco
  Product = Cisco DHCP
  Lms = Direct
  DataType = "dhcp"
  TimeFormat = "MM/dd/yyyy HH:mm:ss"
  Conditions = [ """ hn="""", """ ip="""", """ hn16="""" ]
  Fields = [
		"""({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d)""",
		"""exabeam_host=({host}\S+)""",
		"""\shn="({dest_host}[^"]{1,2000}?)""""
		"""\sip="({dest_ip}[a-fA-F0-9.:]{1,2000})"""
  	]
    DupFields = [ "dest_host->user" ]
}
```