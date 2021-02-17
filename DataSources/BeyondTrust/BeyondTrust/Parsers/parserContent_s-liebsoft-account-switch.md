#### Parser Content
```Java
{
Name = s-liebsoft-account-switch
    Vendor = BeyondTrust
    Product = BeyondTrust
    Lms = Splunk
    DataType = "account-switch"
    TimeFormat = "yyyy-dd-MM'T'HH:mm:ss"
    Conditions = [ """sEventID="EVENT_ID_PASSWORD_ACCESS_GRANTED"""","""<Event"""]
    Fields = [
        """\d+:\d+:\d+\s+({host}[^\s]+)\s+<Event""",
        """dtPostTime="({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})""",
        """sEventID="({event_code}[^"]+)""",
        """sIpAddress="({src_ip}[a-fA-F\d.:]+)""",
        """sLoginName="(({domain}[^"\\]+)\\+)?({user}[^"]+)""",
        """key="sNamespace"\s+value="({safe_value}[^"]+)""",
        """key="sSystemName"\s+value="({dest_service}[^"]+)""",
        """key="sAccountName"\s+value="({account}[^"]+)""",
        """sOriginatingSystem="({dest_host}[^"]+)"""
    ]
  }
```