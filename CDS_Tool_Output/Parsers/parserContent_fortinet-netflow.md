#### Parser Content
```Java
{
Name = fortinet-netflow
  Vendor = Fortinet
  Product = Fortinet Enterprise Firewall
  Lms = Splunk
  DataType = "netflow-connection"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """first_switched""" , """traffic_locality""" ]
  Fields = [
     """exabeam_host=([^=]+@\s*)?({host}\S+)""",
     """\Wip_protocol"*:"*\s*({protocol}[^",]*?)\s*("|,)""",
     """\Whost"*:"*\s*({host}[\w\-.]*)""",
     """\Wsrc_addr"*:"*\s*({src_ip}[A-Fa-f:\d.]*)""",
     """\Wsrc_port"*:\s*(([A-Fa-f:\d.]+?):)?({src_port}\d+)?\s*("|,|$)""",
     """\Wdst_addr"*:"*\s*({dest_ip}[A-Fa-f:\d.]*)""",
     """\Wdst_port"*:\s*(([A-Fa-f:\d.]+?):)?({dest_port}\d+)?\s*("|,|$)""",
     """\Wdirection"*:"*\s*({direction}[^",]*?)\s*("|,)""",
     """("|:)({time}\d\d\d\d-\d\d-\d\d(T|\s+)\d\d:\d\d:\d\d)""",
     """\Wbytes"*:\s*({bytes}\d+)""",
     """\Wservice_name"*:"*\s*({service}[^("\s]*)""",
     """\Wflow_end_reason"*:\s*({end_reason}\d+)""",
     """\Wfirst_switched"*:"*\s*({time_start}[^",]*?)\s*("|,)""",
     """\Wlast_switched"*:"*\s*({time_end}[^",]*?)\s*("|,)""",
     """\Wpackets"*:\s*({packets}\d+)""",
     """\Wtraffic_locality"*:"*\s*(|({locality}[^",]*?))\s*("|,|$)""",
  ]
}

  {
    Name = fortiauthenticator-auth-successful
    Vendor = Fortinet
    Product = FortiAuthenticator
    Lms = Splunk
    DataType = "authentication-successful"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = [ """subcategory="Authentication"""", """action="Login"""" ]
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
      """exabeam_host=({host}[^\s]+)""",
      """exabeam_host=({dest_host}[^\s]+)""",
      """nas="({dest_host}[^"]+)"""",
      """user="({user}[^"]+)"""",
      """status="({outcome}[^"]+)"""",
      """action="({event_name}[^"]+)"""",
      """status="Success" ({additional_info}.+?)\s*$""",
      """status="Failed" ({failure_reason}.+?)( to .*?)?\s*$""",
    ]
  }

{
  Name = fortinet-auth-successful
  Vendor = Fortinet
  Product = Fortinet VPN
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd 'time='HH:mm:ss"
  Conditions = [ """action="FSSO-logon""", """ logdesc=""" ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """date=({time}\d\d\d\d-\d\d-\d\d time=\d\d:\d\d:\d\d)""",
    """devname="*({host}[^"]+?)"*(\s+\w+=|\s*$)""",
    """\ssrcip="?({src_ip}[a-fA-F\d.:]+)""",
    """\sdstip="?({dest_ip}[a-fA-F\d.:]+)""",
    """\suser="*({user}[^"]+?)"*(\s+\w+=|\s*$)""",
    """\slogdesc="({event_name}[^"]+)""",
    """\sserver="({dest_host}[^"]+)""",
  ]
}
```