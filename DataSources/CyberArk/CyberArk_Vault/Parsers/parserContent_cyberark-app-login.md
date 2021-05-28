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
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """(\d\d:\d\d:\d\d|\d\d\d\d-\d\d-\d\d\w\d\d:\d\d:\d\d\w) ({host}[\w\-.]{1,2000}) (LEEF|CEF)""",
    """(LEEF|CEF):([^\|]{0,2000}?\|){4}({event_code}\d{1,100})""",
    """exabeam_endTime=({time}\d{1,100})""",
    """usrName=(({domain}[^\\=]{1,2000})(\\)+)?({user}.+?)\s{1,100}(\w+=|$)""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sEventMessage=(\s{1,100}|({event_subtype}[^=]{1,2000}?))\s{1,100}(\w+=|$)""",
    """\sSafe=(\s{1,100}|({safe_value}.*?))\s{1,100}(\w+=|$)""",
    """\sGatewayStation=({gateway_station}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sReason=(\s{1,100}|({reason}[^=]{0,2000}?))\s{1,100}(\w+=|$)""",
    """({app}Cyber-Ark)"""
  ]
  DupFields=[ "host->dest_host" ]
}
```