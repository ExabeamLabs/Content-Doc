#### Parser Content
```Java
{
Name = cef-qip-dhcp
    Vendor = Nokia VitalQIP
    Lms = ArcSight
    DataType = "dhcp"
    TimeFormat = "epoch"
    Conditions = [ """CEF:""", """|QIP|DHCP|""" ]
    Fields = [
      """\srt=({time}\d+)""",
      """\sshost=({dest_host}.+?)\s+([\w\.]+=|$)""",
      """\ssrc=({dest_ip}[a-fA-F\d.:]+)""",
      """\sdvc=({host}.+?)\s+([\w\.]+=|$)""",
      """\ssntdom=({domain}.+?)\s+([\w\.]+=|$)"""
    ]
    DupFields = [ "dest_host->user" ]
  }
```