#### Parser Content
```Java
{
Name = cyberark-password-change
  Vendor = CyberArk
  Product = CyberArk Vault
  Lms = Direct
  DataType = "account-switch"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [  """|Cyber-Ark|Vault|""", """Action=CPM Change Password""", """Safe""" ]
  Fields = [
    """exabeam_host=({host}[\w\-.]+)""",
    """exabeam_endTime=({time}\d{1,100})""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ) ({host}[\w\-.]+) (LEEF|CEF)""",
    """(LEEF|CEF):([^\|]*?\|){4}({event_code}\d{1,100})""",
    """usrName=(({domain}[^\\\/=]+)(\\\/)+)?({user}.+?)\s{1,100}\w+=""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sFile=({account}.+?)\s{1,100}\w+=""",
    """\sFile=[^=]+\-({account}\w{1,11})\s{1,100}\w+=""",
    """\sSafe=({safe_value}.+?)\s{1,100}\w+=""",
    """\sGatewayStation=({gateway_station}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sReason=({reason}[^=]+?)\s{1,100}\w+=""",
    """\sExtraDetails=address=((\d{1,3}\.){3}\d{1,3}|({src_host}[^;]+));username=({account}[^;]+)"""
  ]
  DupFields=[ "host->dest_host" ]
}
```