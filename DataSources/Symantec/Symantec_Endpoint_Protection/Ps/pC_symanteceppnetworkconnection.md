#### Parser Content
```Java
{
Name = symantec-epp-network-connection
  Vendor = Symantec
  Product = Symantec Endpoint Protection
  Lms = Direct
  DataType = "network-connection-failed"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ SymantecServer: """, """IP de l’hôte local""", """Action""", """ Bloqués""" ]
  Fields = [
    """SymantecServer: ({host}({src_host}[\w\-\.]{1,2000})),""",
    """IP de l’hôte local :\s({src_ip}[a-fA-F\d:\.]{1,2000})""",
    """Port local :\s({src_port}\d{1,5}),""",
    """Adresse IP de l’hôte distant :\s({dest_ip}[a-fA-F\d:\.]{1,2000})""",
    """Nom de l’hôte distant :\s(|({dest_host}[\w\-\.]{1,20000}))""",
    """Port distant :\s({dest_port}\d{1,5}),""",
    """Port distant :[^,]{1,2000

}
```