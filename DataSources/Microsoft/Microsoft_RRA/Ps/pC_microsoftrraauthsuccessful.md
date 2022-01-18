#### Parser Content
```Java
{
Name = microsoft-rra-auth-successful
  Vendor = Microsoft
  Product = Microsoft RRA
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """RoutingDomainID-""", """CoID= {""", """has connected and has been successfully authenticated""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """CoID=\{({session_id}[^\{\}]{1,2000}?)\}""",
    """:\s{0,100}The user (({domain}[^\\\/]{1,2000}?)[\\\/]{1,2000})?({user}[^\\\/]{1,2000}?) has connected""",
  ]


}
```