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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """\Wsuser=(?:N\/A|({user_firstname}[^",\s]{1,2000})\s{1,100}({user_lastname}[^",\s]{1,2000}))""",
    """cs1=({user_email}[^@\s]{1,2000}@[^\s]{1,2000})""",
    """cs2=({activity}.+?)\s{1,100}cs3Label""",
    """cs3=({outcome}[^\s]{1,2000})\s{1,100}""",
  ]
}
```