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
    """sLoginName="(({domain}[^"\\]+)\\+)?({user}[^"]+)""",
    """sIpAddress="({src_ip}[^"]+)""",
    """sOriginatingSystem="({host}[^"]+)""",
    """sOriginatingSystem="({dest_host}[^"]+)""",
    """dwAppSpecificEventID="({event_code}[^"]+)""",
    """sMessage="checked-out password for\s{0,100}\([^\)]*\)'(({account_domain}[^\\\s']+)\\+)?({account}[^\\\s']+)""",
    """sEventID="({event_name}[^"]+)"""
    ]
  }
```