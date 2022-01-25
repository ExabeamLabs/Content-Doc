#### Parser Content
```Java
{
Name = aventail-vpn-start-1
  Vendor = Dell
  Product = SonicWALL Aventail
  Lms = Splunk
  DataType = "vpn-start"
  TimeFormat = "dd/MMM/yyyy:HH:mm:ss.SSSSSS Z"
  Conditions = [ """ Src='""", """ User='""", """' Dest='""", """EquipmentId='""", """PlatformPrefix='""" ]
  Fields = [
    """logserver:\s{0,100}\[({time}\d{1,100}\/\w+\/\d\d\d\d:\d\d:\d\d:\d\d\.\d{1,100} [\+\-]\d{1,100})""",
    """\w+\s{1,100}\d{1,100}\s{1,100}\d\d:\d\d:\d\d ({host}[\w\-.]{1,2000}) logserver:""",
    """User='\(({user}[^\s\)]{1,2000})""",
    """Src='\[?({src_ip}[A-Fa-f:\d.]{1,2000})\]?:({src_port}\d{1,100})'""",
    """Dest='({dest_ip}[A-Fa-f:\d.]{1,2000}):({dest_port}\d{1,100})'""",
  ]
  DupFields = ["user->account"]
}
```