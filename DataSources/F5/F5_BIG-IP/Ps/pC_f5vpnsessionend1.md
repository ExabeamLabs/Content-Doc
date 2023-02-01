#### Parser Content
```Java
{
Name = f5-vpn-session-end-1
  Vendor = F5
  Product = F5 BIG-IP
  Lms = Direct
  DataType = "vpn-end"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """ PPP tunnel """, """ closed.""", """Session_ID="""" ]
  Fields = [
    """({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}(\+|-)\d{2}:\d{2})\s({host}[\w.-]{1,2000})""",
    """session_id="({session_id}[^\s="]{1,2000})""""
  ]


}
```