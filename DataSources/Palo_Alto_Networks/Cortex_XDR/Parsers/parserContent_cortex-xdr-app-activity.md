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
    """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
    """\Wsuser=(?:N\/A|({user_firstname}[^",\s]+)\s{1,100}({user_lastname}[^",\s]+))""",
    """cs1=({user_email}[^@\s]+@[^\s]+)""",
    """cs2=({activity}.+?)\s{1,100}cs3Label""",
    """cs3=({outcome}[^\s]+)\s{1,100}""",
  ]
}
```