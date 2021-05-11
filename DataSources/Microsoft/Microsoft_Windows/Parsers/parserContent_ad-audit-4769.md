#### Parser Content
```Java
{
Name = ad-audit-4769
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4769"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """ADAuditPlus""", """EVENT_NUMBER = 4769""", """A Kerberos service ticket was requested""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}[\+\-]\d\d:\d\d)\s{1,100}({host}[\w\-.]+)\s{1,100}ADAuditPlus""",
    """({event_name}A Kerberos service ticket was requested)""",
    """({event_code}4769)""",
    """USERNAME\s{0,100}=\s{0,100}(null|-|({user}[^@\s]+))(@({domain}[^@\s]+))?\s""",
    """DOMAIN\s{0,100}=\s{0,100}(null|-|({domain}[^\s\]]+))""",
    """CLIENT_IP_ADDRESS\s{0,100}=\s{0,100}({src_ip}[A-Fa-f:\d.]+)""",
    """CLIENT_HOST_NAME\s{0,100}=\s{0,100}({src_host}[\w\-.]+)""",
    """LOGON_SERVICE\s{0,100}=\s{0,100}(null|-|({service_name}[^\s\]]+))""",
    """ERROR_CODE\s{0,100}=\s{0,100}(null|-|({result_code}[^\s\]]+))""",
    """TICKET_OPTIONS\s{0,100}=\s{0,100}(null|-|({ticket_options}[^\s\]]+))""",
    """TICKET_ENCRYPTION_TYPE\s{0,100}=\s{0,100}(null|-|({ticket_encryption_type}[^\s\]]+))""",
  ]
  DupFields = [ "host->dest_host" ]
}
```