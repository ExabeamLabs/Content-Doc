#### Parser Content
```Java
{
Name = cyberark-app-login
  Vendor = CyberArk Vault
  Product = CyberArk Vault
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "epoch"
  Conditions = [  """|Cyber-Ark|Vault|""", """Action=Logon""" ]
  Fields = [
    """exabeam_host=({host}[\w\-.]+)""",
    """(\d\d:\d\d:\d\d|\d\d\d\d-\d\d-\d\d\w\d\d:\d\d:\d\d\w) ({host}[\w\-.]+) (LEEF|CEF)""",
    """(LEEF|CEF):([^\|]*?\|){4}({event_code}\d+)""",
    """exabeam_endTime=({time}\d+)""",
    """usrName=(({domain}[^\\=]+)(\\)+)?({user}.+?)\s+(\w+=|$)""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\EventMessage=(\s+|({event_subtype}.+?))\s+(\w+=|$)""",
    """\sSafe=(\s+|({safe_value}.*?))\s+(\w+=|$)""",
    """\sGatewayStation=({gateway_station}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sReason=(\s+|({reason}[^=]*?))\s+(\w+=|$)""",
    """({app}Cyber-Ark)"""
  ]
  DupFields=[ "host->dest_host" ]
}
```