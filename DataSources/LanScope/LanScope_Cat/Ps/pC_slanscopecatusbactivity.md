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
    """\sEvent="({activity}[^"]{1,2000})""",
    """\sAgent="({dest_host}[^"]{1,2000})""",
    """\sLogonUser="({user}[^"]{1,2000})""",
    """\sApplication="({process_name}[^"]{1,2000})""",
    """\sFileSize="({bytes}[^"]{1,2000})""",
    """\sDevice="({device_id}[^"]{1,2000})""",
    """\sIPAddress="({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\sWindowTitle="({file_path}(({file_parent}[^"]{1,2000}?)[\\\/]{1,2000})?({file_name}[^"\\\/]{1,2000}))"""",
  ]
}
```