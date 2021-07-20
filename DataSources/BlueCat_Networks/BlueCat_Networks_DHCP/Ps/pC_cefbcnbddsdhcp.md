#### Parser Content
```Java
{
Name = cef-bcn-bdds-dhcp
    Vendor = BlueCat Networks
    Product = BlueCat Networks DHCP
    Lms = ArcSight
    DataType = "dhcp"
    TimeFormat = "epoch"
    Conditions = [ """CEF:""", """|BCN|BDDS_DHCP|""", """|DHCP_Message|DHCP message|""", """shost=""", """src=""" ]
    Fields = [
      """\srt=({time}\d{1,100})""",
      """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sdvchost=({host}[\w.\-]{1,2000})""",
      """\scat=(?:|({category}.+?))\s\w+=""",
      """\sshost=({dest_host}[^\s]{1,2000})""",
      """\ssrc=({dest_ip}[^\s]{1,2000})"""
    ]
    DupFields = [ "dest_host->user" ]
  }
```