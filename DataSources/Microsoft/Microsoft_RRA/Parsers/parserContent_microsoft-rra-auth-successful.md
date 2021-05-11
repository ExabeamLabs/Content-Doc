#### Parser Content
```Java
{
Name = microsoft-rra-auth-successful
  Vendor = Microsoft
  Product = Microsoft RRA
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """RoutingDomainID-""", """CoID={""", """has connected and has been successfully authenticated""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """CoID=\{({session_id}[^\{\}]+?)\}""",
    """:\s{0,100}The user (({domain}[^\\\/]+?)[\\\/]+)?({user}[^\\\/]+?) has connected""",
  ]
}
```