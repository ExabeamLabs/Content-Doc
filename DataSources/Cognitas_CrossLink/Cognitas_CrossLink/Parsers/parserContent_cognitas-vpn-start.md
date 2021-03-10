#### Parser Content
```Java
{
Name = cognitas-vpn-start
    Vendor = Cognitas CrossLink
    Lms = Direct
    DataType = "vpn-start"
    TimeFormat = "epoch"
    Conditions = [ """CEF:""","""|Cognitas|CrossLink|""","""|Authentication Succeeded|"""]
    Fields = [ """\srt=({time}\d+)""",
      """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\ssuser=({user}.+?)\s+\w+=""",
      """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sdvchost=({host}[^\s]+)"""
    ]
  }
```