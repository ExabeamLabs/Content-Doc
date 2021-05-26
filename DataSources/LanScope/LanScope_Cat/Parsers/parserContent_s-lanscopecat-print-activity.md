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
    """\sEvent="({activity}[^"]{1,2000})""",
    """\sAgent="({dest_host}[^"]{1,2000})""",
    """\sLogonUser="({user}[^"]{1,2000})""",
    """\sPrinter="({printer_name}[^"]{1,2000})""",
    """\sDocument="({object}[^"]{1,2000})""",
    """\sNumOfPrintedPages="({num_pages}\d{1,100})""",
    """\sPrinterIPAddress="({dest_ip}[^"]{1,2000})""",
    """\sPrintFrom="({src_host}[^"]{1,2000})""",
    """\sIPAddress="({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\sAlertType="({alert_type}[^"]{1,2000})""",
  ]
}
```