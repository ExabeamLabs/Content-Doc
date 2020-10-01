#### Parser Content
```Java
{
Name = cef-bcn-bdds-dhcp
    Vendor = BCN
  Product = BCN
    Lms = ArcSight
    DataType = "dhcp"
    TimeFormat = "epoch"
    Conditions = [ """CEF:""", """|BCN|BDDS_DHCP|""", """|DHCP_Message|DHCP message|""", """shost=""", """src=""" ]
    Fields = [
      """\srt=({time}\d+)""",
      """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sdvchost=({host}[\w.\-]+)""",
      """\scat=(?:|({category}.+?))\s\w+=""",
      """\sshost=({dest_host}[^\s]+)""",
      """\ssrc=({dest_ip}[^\s]+)"""
    ]
    DupFields = [ "dest_host->user" ]
  }
```