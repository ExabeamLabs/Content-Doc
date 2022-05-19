#### Parser Content
```Java
{
Name = sourcefire-network-alert-4
  Vendor = Cisco
  Product = Cisco Firepower
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """Protocol:""", """ApplicationProtocol: NetBIOS-ssn (SMB)""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ) ({host}[\w.\-]{1,2000})""",
    """\sSrcIP:\s{0,100}({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\sDstIP:\s{0,100}({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\sSrcPort:\s{0,100}({src_port}\d{1,100})""",
    """\sDstPort:\s{0,100}({dest_port}\d{1,100})""",
    """\sProtocol:\s{0,100}({protocol}[^,]{1,2000}?)(,|\s{0,100}$)""",
    """\sUser:\s{0,100}(Unknown|({user}[^,]{1,2000}?))(,|\s{0,100}$)""",
    """\sFileAction:\s{0,100}({alert_type}[^,]{1,2000}?)(,|\s{0,100}$)""",
    """\sFilePolicy:\s{0,100}({alert_name}[^,]{1,2000}?)(,|\s{0,100}$)""",
    """\sFileName:\s{0,100}({file_path}({file_parent}[^,]{0,2000}?[\\\/]{1,2000})?({file_name}[^,\\\/]{0,2000}?(\.({file_ext}\w+))?))(,|\s{0,100}$)""",
    """\sFileSize:\s{0,100}({file_size}\d{1,100})""",
    """\sFileType:\s{0,100}({file_type}[^,]{1,2000}?)(,|\s{0,100}$)""",
  ]


}
```