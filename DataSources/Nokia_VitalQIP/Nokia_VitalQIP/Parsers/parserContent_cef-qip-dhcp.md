#### Parser Content
```Java
{
Name = cef-qip-dhcp
    Vendor = Nokia VitalQIP
  Product = Nokia VitalQIP
    Lms = ArcSight
    DataType = "dhcp"
    TimeFormat = "epoch"
    Conditions = [ """CEF:""", """|QIP|DHCP|""" ]
    Fields = [
      """\srt=({time}\d{1,100})""",
      """\sshost=({dest_host}.+?)\s{1,100}([\w\.]{1,2000}=|$)""",
      """\ssrc=({dest_ip}[a-fA-F\d.:]{1,2000})""",
      """\sdvc=({host}.+?)\s{1,100}([\w\.]{1,2000}=|$)""",
      """\ssntdom=({domain}.+?)\s{1,100}([\w\.]{1,2000}=|$)"""
    ]
    DupFields = [ "dest_host->user" ]
  }
```