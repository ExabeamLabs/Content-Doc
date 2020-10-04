#### Parser Content
```Java
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