#### Parser Content
```Java
{
Name = infoblox-dns-response
  Vendor = Infoblox
  Product = BloxOne
  Lms = Splunk
  DataType = "dns-response"
  TimeFormat = "epoch"
  Conditions = [ """,Response,""" ]
  Fields = [
    """({time}\d{10}),[^,]{0,2000

}
```