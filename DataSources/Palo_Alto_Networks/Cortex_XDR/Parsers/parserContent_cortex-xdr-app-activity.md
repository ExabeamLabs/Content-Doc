#### Parser Content
```Java
{
Name = cortex-xdr-app-activity
  Vendor = Palo Alto Networks
  Product = Cortex XDR
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """|Palo Alto Networks|Cortex XDR|""", """|Management Audit Logs|""", """SUCCESS""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """\Wsuser=(?:N\/A|({user_firstname}[^",\s]+)\s+({user_lastname}[^",\s]+))""",
    """cs1=({user_email}[^@\s]+@[^\s]+)""",
    """cs2=({activity}.+?)\s+cs3Label""",
    """cs3=({outcome}[^\s]+)\s+""",
  ]
}
```