#### Parser Content
```Java
{
Name = cognitas-vpn-start
    Vendor = Cognitas CrossLink
  Product = Cognitas CrossLink
    Lms = Direct
    DataType = "vpn-start"
    TimeFormat = "epoch"
    Conditions = [ """CEF:""","""|Cognitas|CrossLink|""","""|Authentication Succeeded|"""]
    Fields = [ """\srt=({time}\d{1,100})""",
      """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\ssuser=({user}.+?)\s{1,100}\w+=""",
      """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sdvchost=({host}[^\s]{1,2000})"""
    ]
  }
```