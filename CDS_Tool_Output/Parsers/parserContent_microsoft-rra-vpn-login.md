#### Parser Content
```Java
{
Name = microsoft-rra-vpn-login
  Vendor = Microsoft
  Product = Microsoft RRA
  Lms = Direct
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """RoutingDomainID-""", """CoID={""", """has been assigned address""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """CoID=\{({session_id}[^\{\}]+?)\}""",
    """:\s*The user (({domain}[^\\\/]+?)[\\\/]+)?({user}[^\\\/]+?) connected on port""",
    """has been assigned address ({src_translated_ip}[a-fA-F\d.:]+)""",
  ]
}
```