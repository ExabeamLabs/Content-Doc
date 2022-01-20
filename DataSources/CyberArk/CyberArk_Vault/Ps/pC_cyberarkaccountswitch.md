#### Parser Content
```Java
{
Name = cyberark-account-switch
  Vendor = CyberArk
  Product = CyberArk Vault
  Lms = Direct
  DataType = "account-switch"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [  """|Cyber-Ark|Vault|""", """Action=Retrieve password""", """Safe""" ]
  Fields = [
    """exabeam_endTime=({time}\d{1,100})""",
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """(\d\d:\d\d:\d\d|\d\d\d\d-\d\d-\d\d\w\d\d:\d\d:\d\d\w) ({host}[\w\-.]{1,2000}) (LEEF|CEF)""",
    """(LEEF|CEF):([^\|]{0,2000}?\|){4}({event_code}\d{1,100})""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
    """usrName =(({domain}[^\\=]{1,2000})(\\)+)?(({user_email}[^@]{1,2000}@[^.]{1,2000}\.[^=]{1,2000}?)|({user}[^=]{1,2000}?))\s{1,100}\w+=""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sFile=[^=]{1,2000}\-({account}[^\s-]{1,2000})\s{1,100}\w+=""",
    """\sFile=(({domain}[^\\]{1,2000})\\)?({account}[^=]{1,2000}?)\s{1,100}\w+=""",
    """\sSafe=({safe_value}[^=]{1,2000}?)\s{1,100}\w+=""",
    """\sGatewayStation=({gateway_station}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sReason=({reason}[^=]{1,2000}?)\s{1,100}\w+=""",
    """\sAction=({action}[^=]{1,2000}?)\s{1,100}\w{1,100}="""
  ]
  DupFields=[ "host->dest_host" ]


}
```