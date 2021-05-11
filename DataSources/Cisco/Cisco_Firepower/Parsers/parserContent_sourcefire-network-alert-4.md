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
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ) ({host}[\w.\-]+)""",
    """\sSrcIP:\s{0,100}({src_ip}[a-fA-F\d.:]+)""",
    """\sDstIP:\s{0,100}({dest_ip}[a-fA-F\d.:]+)""",
    """\sSrcPort:\s{0,100}({src_port}\d{1,100})""",
    """\sDstPort:\s{0,100}({dest_port}\d{1,100})""",
    """\sProtocol:\s{0,100}({protocol}[^,]+?)(,|\s{0,100}$)""",
    """\sUser:\s{0,100}(Unknown|({user}[^,]+?))(,|\s{0,100}$)""",
    """\sFileAction:\s{0,100}({alert_type}[^,]+?)(,|\s{0,100}$)""",
    """\sFilePolicy:\s{0,100}({alert_name}[^,]+?)(,|\s{0,100}$)""",
    """\sFileName:\s{0,100}({file_path}({file_parent}[^,]*?[\\\/]+)?({file_name}[^,\\\/]*?(\.({file_ext}\w+))?))(,|\s{0,100}$)""",
    """\sFileSize:\s{0,100}({file_size}\d{1,100})""",
    """\sFileType:\s{0,100}({file_type}[^,]+?)(,|\s{0,100}$)""",
  ]
}
```