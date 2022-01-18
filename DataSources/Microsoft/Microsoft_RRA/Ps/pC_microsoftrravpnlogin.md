#### Parser Content
```Java
{
Name = microsoft-rra-vpn-login
  Vendor = Microsoft
  Product = Microsoft RRA
  Lms = Direct
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """RoutingDomainID-""", """CoID= {""", """has been assigned address""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """CoID=\{({session_id}[^\{\}]{1,2000}?)\}""",
    """:\s{0,100}The user (({domain}[^\\\/]{1,2000}?)[\\\/]{1,2000})?({user}[^\\\/]{1,2000}?) connected on port""",
    """has been assigned address ({src_translated_ip}[a-fA-F\d.:]{1,2000})""",
  ]


}
```