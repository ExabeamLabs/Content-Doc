#### Parser Content
```Java
{
Name = microsoft-rra-vpn-logout
  Vendor = Microsoft
  Product = Microsoft RRA
  Lms = Direct
  DataType = "vpn-end"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """RoutingDomainID-""", """CoID= {""", """The user with ip address""", """has disconnected""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """CoID=\{({session_id}[^\{\}]{1,2000}?)\}""",
    """The user with ip address ({src_translated_ip}[a-fA-F\d.:]{1,2000})""",
  ]


}
```