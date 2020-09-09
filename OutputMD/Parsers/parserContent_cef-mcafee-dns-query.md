#### Parser Content
```Java
{
Name = cef-mcafee-dns-query
    Vendor = Infoblox
    Product = Infoblox
    Lms = ArcSight
    DataType = "dns-query"
    IsHVF = true
    TimeFormat = "epoch"
    Conditions = [ """CEF:""", """|McAfee|ESM|""", """|Infoblox_NIOS DNS Query|""", """Query\=""" ]
    Fields = [
      """({host}\S+) CEF:""",
      """CEF:([^\|]*\|){5}({event_name}[^\|]+)""",
      """\Wrt=({time}\d+)""",
      """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
      """\Wspt=({src_port}\d+)""",
      """\Wdst=({dest_ip}[a-fA-F\d.:]+)""",
      """\Wproto=({protocol}\S+)""",
      """\WQuery\\=({query}.+?)\?\s*([\w\\]+=|$)""",
      """\WType_Name\\=({query_type}.+?)\s*([\w\\]+=|$)""",
      """\WnitroRequest_Type=(-|({query_flags}.+?))\s*([\w\\]+=|$)""",
    ]
  }

${UnixParserTemplates.unix-activity-json}{
  Name = unix-account-switch-json
  DataType = "unix-account-switch"
  Conditions = [ """"ident":"sudo""", """pam_unix(sudo:session): session""" ]
  Fields = ${UnixParserTemplates.unix-activity-json.Fields}[
    """session (opened|closed) for user ({account}[^\s"]+)""",
    """\(uid=({user_id}\d+)\)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```