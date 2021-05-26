#### Parser Content
```Java
{
Name = syslog-liebsoft-account-switch
    Vendor = BeyondTrust
    Product = BeyondTrust Privileged Identity
    Lms = Syslog
    DataType = "account-switch"
    TimeFormat = "yyyy-dd-MM'T'HH:mm:ss"
    Conditions = [ """sEventID="EVENT_ID_PASSWORD_RETRIEVED"""","""<Event"""]
    Fields = [
    """dtPostTime="({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})""",
    """sLoginName="(({domain}[^"]{1,2000})\\)?({user}[^"]{1,2000})""",
    """sAccountName"\s{1,100}value="({account}[^"]{1,2000})""",
    """sIpAddress="({src_ip}[^"]{1,2000})""",
    """sOriginatingSystem="({host}[^"]{1,2000})""",
    """sOriginatingSystem="({dest_host}[^"]{1,2000})""",
    """dwAppSpecificEventID="({event_code}[^"]{1,2000})""",
    """sNamespace"\s{1,100}value="({account_domain}[^"]{1,2000})"""
    ]
  }
```