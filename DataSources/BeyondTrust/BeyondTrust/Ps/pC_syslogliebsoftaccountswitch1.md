#### Parser Content
```Java
{
Name = syslog-liebsoft-account-switch-1
    Vendor = BeyondTrust
    Product = BeyondTrust
    Lms = Syslog
    DataType = "account-switch"
    TimeFormat = "yyyy-dd-MM'T'HH:mm:ss"
    Conditions = [ """sEventID="EVENT_ID_PASSWORD_CHECKED_OUT"""","""<Event"""]
    Fields = [
    """dtPostTime="({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})""",
    """sLoginName="(({domain}[^"\\]{1,2000})\\+)?({user}[^"]{1,2000})""",
    """sIpAddress="({src_ip}[^"]{1,2000})""",
    """sOriginatingSystem="({host}[^"]{1,2000})""",
    """sOriginatingSystem="({dest_host}[^"]{1,2000})""",
    """dwAppSpecificEventID="({event_code}[^"]{1,2000})""",
    """sMessage="checked-out password for\s{0,100}\([^\)]{0,2000}\)'(({account_domain}[^\\\s']{1,2000})\\+)?({account}[^\\\s']{1,2000})""",
    """sEventID="({event_name}[^"]{1,2000})"""
    ]
  }
```