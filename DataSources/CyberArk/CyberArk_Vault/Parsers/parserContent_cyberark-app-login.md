#### Parser Content
```Java
{
Name = cyberark-app-login
  Vendor = CyberArk
  Product = CyberArk Vault
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "epoch"
  Conditions = [  """|Cyber-Ark|Vault|""", """Action=Logon""" ]
  Fields = [
    """exabeam_host=({host}[\w\-.]+)""",
    """(\d\d:\d\d:\d\d|\d\d\d\d-\d\d-\d\d\w\d\d:\d\d:\d\d\w) ({host}[\w\-.]+) (LEEF|CEF)""",
    """(LEEF|CEF):([^\|]*?\|){4}({event_code}\d{1,100})""",
    """exabeam_endTime=({time}\d{1,100})""",
    """usrName=(({domain}[^\\=]+)(\\)+)?({user}.+?)\s{1,100}(\w+=|$)""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\EventMessage=(\s{1,100}|({event_subtype}.+?))\s{1,100}(\w+=|$)""",
    """\sSafe=(\s{1,100}|({safe_value}.*?))\s{1,100}(\w+=|$)""",
    """\sGatewayStation=({gateway_station}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sReason=(\s{1,100}|({reason}[^=]*?))\s{1,100}(\w+=|$)""",
    """({app}Cyber-Ark)"""
  ]
  DupFields=[ "host->dest_host" ]
}
```