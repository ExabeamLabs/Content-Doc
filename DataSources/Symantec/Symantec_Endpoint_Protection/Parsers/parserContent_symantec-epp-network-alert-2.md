#### Parser Content
```Java
{
Name = symantec-epp-network-alert-2
  Vendor = Symantec
  Product = Symantec Endpoint Protection
  Lms = Direct
  DataType = "network-connection-failed"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """CIDS Signature ID""", """traffic from IP address""", """block""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\w+\s{1,100}\d{1,2}\s\d{1,2}:\d{1,2}:\d{1,2}\s({host}[\w\.-]{1,2000})\s""",
    """Local:\s{0,100}({dest_ip}[a-fA-F:\.\d]{1,2000}),Local:\s{0,100}(?:0+|({dest_host}[^,]{1,2000})),([^,]{0,2000}
```