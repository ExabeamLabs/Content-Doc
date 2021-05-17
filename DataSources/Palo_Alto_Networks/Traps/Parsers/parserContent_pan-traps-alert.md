#### Parser Content
```Java
{
Name = pan-traps-alert
  Vendor = Palo Alto Networks
  Product = Traps
  Lms = Direct
  DataType = "alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """,Traps Agent,""", """Prevention Key:""" ]
  Fields = [
    """\d{1,100}\s{1,100}\d{4}\-\d{1,100}\-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z(\-|\+)\d{1,100}:\d{1,100}\s{1,100}({host}(\d{1,3}\.){3}\d{1,3})""",
    """({time}\w+ \d{1,100} \d\d\d\d \d\d:\d\d:\d\d),Traps Agent,""",
    """,Traps Agent,([^,]{0,2000}
```