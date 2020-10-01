#### Parser Content
```Java
{
Name = ad-audit-4769
  Vendor = ManageEngine
  Product = AD Audit
  Lms = Direct
  DataType = "windows-4769"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """ADAuditPlus""", """EVENT_NUMBER = 4769""", """A Kerberos service ticket was requested""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+[\+\-]\d\d:\d\d)\s+({host}[\w\-.]+)\s+ADAuditPlus""",
    """({event_name}A Kerberos service ticket was requested)""",
    """({event_code}4769)""",
    """USERNAME\s*=\s*(null|-|({user}[^@\s]+))(@({domain}[^@\s]+))?\s""",
    """DOMAIN\s*=\s*(null|-|({domain}[^\s\]]+))""",
    """CLIENT_IP_ADDRESS\s*=\s*({src_ip}[A-Fa-f:\d.]+)""",
    """CLIENT_HOST_NAME\s*=\s*({src_host}[\w\-.]+)""",
    """LOGON_SERVICE\s*=\s*(null|-|({service_name}[^\s\]]+))""",
    """ERROR_CODE\s*=\s*(null|-|({result_code}[^\s\]]+))""",
    """TICKET_OPTIONS\s*=\s*(null|-|({ticket_options}[^\s\]]+))""",
    """TICKET_ENCRYPTION_TYPE\s*=\s*(null|-|({ticket_encryption_type}[^\s\]]+))""",
  ]
  DupFields = [ "host->dest_host" ]
}
```