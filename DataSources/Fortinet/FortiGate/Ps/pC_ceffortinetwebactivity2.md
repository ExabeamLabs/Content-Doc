#### Parser Content
```Java
{
Name = cef-fortinet-web-activity-2
  Vendor = Fortinet
  Product = FortiGate
  Lms = Direct
  DataType = "web-activity"
  TimeFormat = "epoch_sec"
  Conditions = [ """|Fortinet|Fortigate|""", """|utm:webfilter """, """FTNTFGTlevel=""", """FTNTFGTsubtype=webfilter""" ]
  Fields = [
    """FTNTFGTeventtime=({time}\d{1,19})""",
    """\s\d\d:\d\d:\d\d\s({host}[\w\-\.]{1,2000})""",
    """\|Fortinet\|Fortigate\|([^|]{1,2000}\|){2}({event_name}[^|]{1,2000})\|""",
    """\ssrc=({src_ip}[a-fA-F\d\.]{1,2000})""",
    """\sspt=({src_port}\d{1,5})""",     
    """\sdhost=({web_domain}[^\s]{1,2000}?)\s\w+=""", 
    """\sdst=({dest_ip}[a-fA-F\d\.]{1,2000})""",
    """\sdpt=({dest_port}\d{1,5})""",
    """\sact=({action}[^=]{1,2000}?)\s\w+=""",
    """\sproto=({protocol}[^\s]{1,2000})"""
    """\srequest=({full_url}(\w{1,5}:\/\/)?[^\s\/\?]{1,2000}({uri_path}\/[^\s\?]{0,2000})?(\?({uri_query}[^\s]{0,2000})))\s\w+=""",
    """\sout=({bytes_out}\d{1,20})""",
    """\sin=({bytes_in}\d{1,20})""",
    """deviceDirection=({direction}\d)""",
    """\smsg=({additional_info}[^=]{1,2000}?)\s\w+="""
  ]


}
```