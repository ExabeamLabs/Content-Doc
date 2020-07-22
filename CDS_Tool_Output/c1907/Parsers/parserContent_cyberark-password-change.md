#### Parser Content
```Java
{
Name = cyberark-password-change
  Vendor = CyberArk Vault
  Product = CyberArk Vault
  Lms = Direct
  DataType = "account-switch"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [  """|Cyber-Ark|Vault|""", """Action=CPM Change Password""", """Safe""" ]
  Fields = [
    """exabeam_host=({host}[\w\-.]+)""",
    """exabeam_endTime=({time}\d+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ) ({host}[\w\-.]+) (LEEF|CEF)""",
    """(LEEF|CEF):([^\|]*?\|){4}({event_code}\d+)""",
    """usrName=(({domain}[^\\\/=]+)(\\\/)+)?({user}.+?)\s+\w+=""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sFile=({account}.+?)\s+\w+=""",
    """\sFile=[^=]+\-({account}\w{1,11})\s+\w+=""",
    """\sSafe=({safe_value}.+?)\s+\w+=""",
    """\sGatewayStation=({gateway_station}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sReason=({reason}[^=]+?)\s+\w+=""",
    """\sExtraDetails=address=((\d{1,3}\.){3}\d{1,3}|({src_host}[^;]+));username=({account}[^;]+)"""
  ]
  DupFields=[ "host->dest_host" ]
}
```