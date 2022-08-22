#### Parser Content
```Java
{
Name = infoblox-dns-query-1
  Vendor = Infoblox
  Product = BloxOne
  Lms = Splunk
  DataType = "dns-query"
  TimeFormat = "epoch"
  Conditions = [ """,Query,""" ]
  Fields = [
    """({time}\d{10}),[^,]{0,2000}.Query,""",
    """,Query,(|({protocol}[^,]{1,2000})),""",
    """,Query,([^,]{0,2000

}
```