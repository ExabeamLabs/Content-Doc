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
    """\sSrcIP:\s*({src_ip}[a-fA-F\d.:]+)""",
    """\sDstIP:\s*({dest_ip}[a-fA-F\d.:]+)""",
    """\sSrcPort:\s*({src_port}\d+)""",
    """\sDstPort:\s*({dest_port}\d+)""",
    """\sProtocol:\s*({protocol}[^,]+?)(,|\s*$)""",
    """\sUser:\s*(Unknown|({user}[^,]+?))(,|\s*$)""",
    """\sFileAction:\s*({alert_type}[^,]+?)(,|\s*$)""",
    """\sFilePolicy:\s*({alert_name}[^,]+?)(,|\s*$)""",
    """\sFileName:\s*({file_path}({file_parent}[^,]*?[\\\/]+)?({file_name}[^,\\\/]*?(\.({file_ext}\w+))?))(,|\s*$)""",
    """\sFileSize:\s*({file_size}\d+)""",
    """\sFileType:\s*({file_type}[^,]+?)(,|\s*$)""",
  ]
}
```