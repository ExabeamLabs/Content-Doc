#### Parser Content
```Java
{
Name = s-lanscopecat-usb-activity
  Vendor = LanScope
  Product = LanScope Cat
  Lms = Splunk
  DataType = "usb-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """LanScopeCat - Operation""", """WindowTitle=""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}(\+|\-)\d\d:\d\d)\s{1,100}({host}\S+)\s{1,100}LanScopeCat\s{1,100}\-""",
    """\sEvent="({activity}[^"]+)""",
    """\sAgent="({dest_host}[^"]+)""",
    """\sLogonUser="({user}[^"]+)""",
    """\sApplication="({process_name}[^"]+)""",
    """\sFileSize="({bytes}[^"]+)""",
    """\sDevice="({device_id}[^"]+)""",
    """\sIPAddress="({src_ip}[a-fA-F\d.:]+)""",
    """\sWindowTitle="({file_path}(({file_parent}[^"]+?)[\\\/]+)?({file_name}[^"\\\/]+))"""",
  ]
}
```