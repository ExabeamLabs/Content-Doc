#### Parser Content
```Java
{
Name = microsoft-rra-vpn-logout-1
  Vendor = Microsoft
  Product = Routing and Remote Access Service 
  Lms = Direct
  DataType = "vpn-end"
  TimeFormat = "MM/dd/yyyy' at 'H:mm a"
  Conditions = [ """RoutingDomainID-""", """CoID={""", """ and disconnected on """, """The reason for disconnecting was""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """CoID=\{({session_id}[^\{\}]{1,2000}?)\}""",
    """:\s{0,100}The user (({domain}[^\\\/]{1,2000})[\\\/]{1,2000})?({user}[^\\\/]{1,2000}?)\s{1,100}connected on port""",
    """\sand disconnected on ({time}\d{1,100}/\d{1,100}/\d\d\d\d at \d{1,100}:\d{1,100} (am|AM|pm|PM))""",
    """The user was active for ({session_min}\d{1,100}) minutes ({session_sec}\d{1,100}) seconds""",
    """({bytes_out}\d{1,100}) bytes were sent and ({bytes_in}\d{1,100}) bytes were received""",
    """\sThe reason for disconnecting was ({reason}[^\.]{1,2000})""",
  ]
}
}
```