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
      """\sshost=({dest_host}.+?)\s{1,100}([\w\.]+=|$)""",
      """\ssrc=({dest_ip}[a-fA-F\d.:]+)""",
      """\sdvc=({host}.+?)\s{1,100}([\w\.]+=|$)""",
      """\ssntdom=({domain}.+?)\s{1,100}([\w\.]+=|$)"""
    ]
    DupFields = [ "dest_host->user" ]
  }
```