#### Parser Content
```Java
{
Name = aventail-vpn-start-1
  Vendor = Dell
  Product = Aventail
  Lms = Splunk
  DataType = "vpn-start"
  TimeFormat = "dd/MMM/yyyy:HH:mm:ss.SSSSSS Z"
  Conditions = [ """ Src='""", """ User='""", """' Dest='""", """EquipmentId='""", """PlatformPrefix='""" ]
  Fields = [
    """logserver:\s*\[({time}\d+\/\w+\/\d\d\d\d:\d\d:\d\d:\d\d\.\d+ [\+\-]\d+)""",
    """\w+\s+\d+\s+\d\d:\d\d:\d\d ({host}[\w\-.]+) logserver:""",
    """User='\(({user}[^\s\)]+)""",
    """Src='\[?({src_ip}[A-Fa-f:\d.]+)\]?:({src_port}\d+)'""",
    """Dest='({dest_ip}[A-Fa-f:\d.]+):({dest_port}\d+)'""",
  ]
  DupFields = ["user->account"]
}
```