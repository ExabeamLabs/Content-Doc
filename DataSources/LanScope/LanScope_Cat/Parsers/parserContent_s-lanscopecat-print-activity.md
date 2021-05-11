#### Parser Content
```Java
{
Name = s-lanscopecat-print-activity
  Vendor = LanScope
  Product = LanScope Cat
  Lms = Splunk
  DataType = "print-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """LanScopeCat - Print""", """Printer=""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}(\+|\-)\d\d:\d\d)\s{1,100}({host}\S+)\s{1,100}LanScopeCat\s{1,100}\-""",
    """\sEvent="({activity}[^"]+)""",
    """\sAgent="({dest_host}[^"]+)""",
    """\sLogonUser="({user}[^"]+)""",
    """\sPrinter="({printer_name}[^"]+)""",
    """\sDocument="({object}[^"]+)""",
    """\sNumOfPrintedPages="({num_pages}\d{1,100})""",
    """\sPrinterIPAddress="({dest_ip}[^"]+)""",
    """\sPrintFrom="({src_host}[^"]+)""",
    """\sIPAddress="({src_ip}[a-fA-F\d.:]+)""",
    """\sAlertType="({alert_type}[^"]+)""",
  ]
}
```